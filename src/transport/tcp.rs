//! Synthetic raw-socket TCP transport (IP protocol 6).
//!
//! The TCP stack is implemented manually: we craft PSH|ACK segments with a
//! forged source carrying the wire frame (optionally behind a 5-byte fake TLS
//! Application-Data record so it reads as HTTPS). Because we provide our own
//! reliability/ordering above the transport, we do not run a full stateful TCP
//! — we keep a monotonic sequence number and a plausible window.
//!
//! The host kernel must be prevented from answering with RST to these segments
//! (no real socket owns the port); the setup step installs an
//! `OUTPUT -p tcp --tcp-flags RST RST -j DROP` rule for the data port.
//!
//! A full stateful fake handshake (SYN/SYN-ACK/ACK + realistic ACK tracking)
//! is a clean extension point: implement [`TcpTransport::handshake`] and feed
//! observed sequence numbers into [`TcpTransport::ack`].

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, Ordering};

use async_trait::async_trait;

use crate::config::TransportKind;
use crate::error::Result;
use crate::spoof::checksum;

use super::raw_core::RawCore;
use super::{Transport, TransportParams};

/// Minimum TCP header length (no options).
const TCP_MIN_HEADER: usize = 20;
/// Fake TLS Application-Data record header length.
const FAKE_TLS_HEADER: usize = 5;
const TCP_PSH_ACK: u8 = 0x18;

/// Synthetic TCP transport.
pub struct TcpTransport {
    core: RawCore,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    fake_tls: bool,
    seq: AtomicU32,
    ack: AtomicU32,
}

impl TcpTransport {
    /// Bind the raw socket for protocol 6.
    pub fn new(p: &TransportParams) -> Result<TcpTransport> {
        let mut seed = [0u8; 4];
        let _ = getrandom::getrandom(&mut seed);
        Ok(TcpTransport {
            core: RawCore::new(6, p)?,
            src: p.forged_src,
            dst: p.peer_real,
            src_port: p.data_port,
            dst_port: p.data_port,
            fake_tls: p.fake_tls,
            seq: AtomicU32::new(u32::from_be_bytes(seed)),
            ack: AtomicU32::new(0),
        })
    }

    /// Feed an observed peer sequence number so our ACK tracks it (used by a
    /// future stateful handshake; harmless no-op otherwise).
    pub fn ack(&self, observed_seq_end: u32) {
        self.ack.store(observed_seq_end, Ordering::Relaxed);
    }

    fn build_segment(&self, payload: &[u8]) -> Vec<u8> {
        let seq = self.seq.fetch_add(payload.len() as u32, Ordering::Relaxed);
        let ack = self.ack.load(Ordering::Relaxed);

        let mut seg = Vec::with_capacity(TCP_MIN_HEADER + payload.len());
        seg.extend_from_slice(&self.src_port.to_be_bytes());
        seg.extend_from_slice(&self.dst_port.to_be_bytes());
        seg.extend_from_slice(&seq.to_be_bytes());
        seg.extend_from_slice(&ack.to_be_bytes());
        seg.push(5 << 4); // data offset = 5 words (20 bytes), reserved 0
        seg.push(TCP_PSH_ACK);
        seg.extend_from_slice(&0xFFFFu16.to_be_bytes()); // window
        seg.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
        seg.extend_from_slice(&0u16.to_be_bytes()); // urgent pointer
        seg.extend_from_slice(payload);

        let csum = l4_checksum(self.src, self.dst, 6, &seg);
        seg[16..18].copy_from_slice(&csum.to_be_bytes());
        seg
    }
}

#[async_trait]
impl Transport for TcpTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Tcp
    }

    async fn send_frame(&self, frame: &[u8]) -> Result<()> {
        // Optional fake TLS Application-Data record around the frame.
        let payload = if self.fake_tls {
            let mut v = Vec::with_capacity(FAKE_TLS_HEADER + frame.len());
            v.push(0x17); // content type: application_data
            v.extend_from_slice(&[0x03, 0x03]); // version TLS 1.2 (as on the wire for 1.3)
            v.extend_from_slice(&(frame.len() as u16).to_be_bytes());
            v.extend_from_slice(frame);
            v
        } else {
            frame.to_vec()
        };
        let seg = self.build_segment(&payload);
        self.core.send_l4(&seg).await
    }

    async fn recv_frame(&self, buf: &mut [u8]) -> Result<usize> {
        let mut tmp = vec![0u8; buf.len() + TCP_MIN_HEADER + FAKE_TLS_HEADER + 64];
        loop {
            let (n, _src) = self.core.recv_l4(&mut tmp).await?;
            if n < TCP_MIN_HEADER {
                continue;
            }
            // Data offset is the high nibble of byte 12, in 32-bit words.
            let data_off = ((tmp[12] >> 4) as usize) * 4;
            if data_off < TCP_MIN_HEADER || data_off > n {
                continue; // malformed / options we don't expect — skip
            }
            let mut payload = &tmp[data_off..n];
            if payload.is_empty() {
                continue; // pure ACK / control segment — skip
            }
            if self.fake_tls {
                if payload.len() < FAKE_TLS_HEADER {
                    continue;
                }
                payload = &payload[FAKE_TLS_HEADER..];
            }
            let m = payload.len().min(buf.len());
            buf[..m].copy_from_slice(&payload[..m]);
            return Ok(m);
        }
    }
}

/// TCP/UDP-style L4 checksum over the pseudo-header + segment.
fn l4_checksum(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, seg: &[u8]) -> u16 {
    let s = src.octets();
    let d = dst.octets();
    let mut sum: u32 = 0;
    sum += u16::from_be_bytes([s[0], s[1]]) as u32;
    sum += u16::from_be_bytes([s[2], s[3]]) as u32;
    sum += u16::from_be_bytes([d[0], d[1]]) as u32;
    sum += u16::from_be_bytes([d[2], d[3]]) as u32;
    sum += proto as u32;
    sum += seg.len() as u32;
    sum += checksum::sum16(seg);
    checksum::finalize(sum)
}
