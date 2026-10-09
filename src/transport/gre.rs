//! `gre` transport (IP protocol 47, GRE / RFC 2784).
//!
//! A minimal GRE header (4 bytes: flags/version = 0, protocol type) precedes
//! the wire frame, so the traffic looks like a real GRE VPN. We advertise the
//! inner protocol as transparent Ethernet bridging (0x6558), a common value
//! for GRE tunnels, which keeps the framing plausible to a DPI engine.

use std::net::{Ipv4Addr, SocketAddrV4};

use async_trait::async_trait;

use crate::config::TransportKind;
use crate::error::{Error, Result};

use super::raw_core::RawCore;
use super::{Transport, TransportParams};

/// GRE header length (no checksum/key/sequence options).
const GRE_HEADER: usize = 4;
/// Inner protocol type advertised in the GRE header (transparent Ethernet bridging).
const GRE_PROTO_TEB: u16 = 0x6558;

/// GRE transport.
pub struct GreTransport {
    core: RawCore,
}

impl GreTransport {
    /// Bind the raw socket for protocol 47.
    pub fn new(p: &TransportParams) -> Result<GreTransport> {
        Ok(GreTransport {
            core: RawCore::new(47, p)?,
        })
    }

    /// Wrap one frame in the minimal GRE header.
    fn wrap(frame: &[u8]) -> Vec<u8> {
        let mut l4 = Vec::with_capacity(GRE_HEADER + frame.len());
        l4.extend_from_slice(&0u16.to_be_bytes()); // flags + version = 0
        l4.extend_from_slice(&GRE_PROTO_TEB.to_be_bytes());
        l4.extend_from_slice(frame);
        l4
    }
}

#[async_trait]
impl Transport for GreTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Gre
    }

    async fn send_frame(&self, frame: &[u8]) -> Result<()> {
        self.core.send_l4(&Self::wrap(frame)).await
    }

    async fn send_batch(&self, frames: &[&[u8]]) -> Result<()> {
        let msgs: Vec<Vec<u8>> = frames.iter().map(|f| Self::wrap(f)).collect();
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

impl GreTransport {
    /// Receive one GRE datagram and strip the 4-byte header.
    async fn recv_inner(&self, buf: &mut [u8]) -> Result<(usize, Ipv4Addr)> {
        let mut tmp = vec![0u8; buf.len() + GRE_HEADER];
        let (n, src) = self.core.recv_l4(&mut tmp).await?;
        if n < GRE_HEADER {
            return Err(Error::decode("gre: frame shorter than GRE header"));
        }
        let payload = &tmp[GRE_HEADER..n];
        let m = payload.len().min(buf.len());
        buf[..m].copy_from_slice(&payload[..m]);
        Ok((m, src))
    }
}
