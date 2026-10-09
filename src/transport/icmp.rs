//! `icmp` transport (IP protocol 1, ICMP Echo).
//!
//! The wire frame is carried as the payload of an ICMP Echo message, so the
//! traffic blends with ordinary ping. The client sends Echo *Request* (type 8)
//! and the server sends Echo *Reply* (type 0), so a captured flow looks like a
//! genuine ping request/reply exchange. The identifier can be fixed or
//! randomized per session.
//!
//! The host kernel must be told not to answer echo requests itself
//! (`net.ipv4.icmp_echo_ignore_all=1`, applied by the setup step), otherwise
//! it would race our userspace replies.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicU16, Ordering};

use async_trait::async_trait;

use crate::config::TransportKind;
use crate::error::Result;
use crate::spoof::checksum;

use super::raw_core::RawCore;
use super::{Transport, TransportParams};

/// ICMP Echo header length (type, code, checksum, id, seq).
const ICMP_HEADER: usize = 8;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;

/// ICMP Echo transport.
pub struct IcmpTransport {
    core: RawCore,
    id: u16,
    send_type: u8,
    seq: AtomicU16,
}

impl IcmpTransport {
    /// Bind the raw socket for protocol 1.
    pub fn new(p: &TransportParams) -> Result<IcmpTransport> {
        let send_type = if p.is_server {
            ICMP_ECHO_REPLY
        } else {
            ICMP_ECHO_REQUEST
        };
        Ok(IcmpTransport {
            core: RawCore::new(1, p)?,
            id: p.icmp_id,
            send_type,
            seq: AtomicU16::new(0),
        })
    }

    /// Build an ICMP Echo message around `frame`.
    fn build(&self, frame: &[u8]) -> Vec<u8> {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let mut msg = Vec::with_capacity(ICMP_HEADER + frame.len());
        msg.push(self.send_type);
        msg.push(0); // code
        msg.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
        msg.extend_from_slice(&self.id.to_be_bytes());
        msg.extend_from_slice(&seq.to_be_bytes());
        msg.extend_from_slice(frame);
        let csum = checksum::checksum(&msg);
        msg[2..4].copy_from_slice(&csum.to_be_bytes());
        msg
    }
}

#[async_trait]
impl Transport for IcmpTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Icmp
    }

    async fn send_frame(&self, frame: &[u8]) -> Result<()> {
        let msg = self.build(frame);
        self.core.send_l4(&msg).await
    }

    async fn send_batch(&self, frames: &[&[u8]]) -> Result<()> {
        let msgs: Vec<Vec<u8>> = frames.iter().map(|f| self.build(f)).collect();
        let refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
        self.core.send_l4_batch(&refs).await
    }

    async fn recv_frame(&self, buf: &mut [u8]) -> Result<usize> {
        let (m, _src) = self.recv_inner(buf).await?;
        Ok(m)
    }

    async fn recv_frame_from(&self, buf: &mut [u8]) -> Result<(usize, Option<Ipv4Addr>)> {
        let (m, src) = self.recv_inner(buf).await?;
        Ok((m, Some(src)))
    }

    fn set_peer(&self, dst: SocketAddrV4) {
        self.core.set_dst(*dst.ip());
    }

    fn supports_hop(&self) -> bool {
        true
    }
}

impl IcmpTransport {
    /// Receive one ICMP Echo datagram and strip the 8-byte header.
    async fn recv_inner(&self, buf: &mut [u8]) -> Result<(usize, Ipv4Addr)> {
        let mut tmp = vec![0u8; buf.len() + ICMP_HEADER];
        loop {
            let (n, src) = self.core.recv_l4(&mut tmp).await?;
            if n < ICMP_HEADER {
                continue; // not a full ICMP echo — skip
            }
            let ty = tmp[0];
            // Accept either echo type; the crypto layer authenticates content.
            if ty != ICMP_ECHO_REQUEST && ty != ICMP_ECHO_REPLY {
                continue;
            }
            let payload = &tmp[ICMP_HEADER..n];
            let m = payload.len().min(buf.len());
            buf[..m].copy_from_slice(&payload[..m]);
            return Ok((m, src));
        }
    }
}
