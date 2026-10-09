//! `ipip` transport (IP protocol 4, IP-in-IP / RFC 2003).
//!
//! The wire frame is carried as the IP payload of an outer IPv4 packet with
//! protocol 4. To an observer it looks like an IP-in-IP tunnel (a common,
//! legitimate encapsulation). We do not require the payload to be a real inner
//! IPv4 packet — the first bytes are our authenticated frame header.

use std::net::{Ipv4Addr, SocketAddrV4};

use async_trait::async_trait;

use crate::config::TransportKind;
use crate::error::Result;

use super::raw_core::RawCore;
use super::{Transport, TransportParams};

/// IP-in-IP transport.
pub struct IpipTransport {
    core: RawCore,
}

impl IpipTransport {
    /// Bind the raw socket for protocol 4.
    pub fn new(p: &TransportParams) -> Result<IpipTransport> {
        Ok(IpipTransport {
            core: RawCore::new(4, p)?,
        })
    }
}

#[async_trait]
impl Transport for IpipTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Ipip
    }

    async fn send_frame(&self, frame: &[u8]) -> Result<()> {
        self.core.send_l4(frame).await
    }

    async fn send_batch(&self, frames: &[&[u8]]) -> Result<()> {
        self.core.send_l4_batch(frames).await
    }

    async fn recv_frame(&self, buf: &mut [u8]) -> Result<usize> {
        let (n, _src) = self.core.recv_l4(buf).await?;
        Ok(n)
    }

    async fn recv_frame_from(&self, buf: &mut [u8]) -> Result<(usize, Option<Ipv4Addr>)> {
        let (n, src) = self.core.recv_l4(buf).await?;
        Ok((n, Some(src)))
    }

    fn set_peer(&self, dst: SocketAddrV4) {
        self.core.set_dst(*dst.ip());
    }

    fn supports_hop(&self) -> bool {
        true
    }
}
