//! `proto58` transport (IP protocol 58).
//!
//! IP protocol 58 is ICMPv6; carried here on IPv4 it has no L4 header, so the
//! wire frame is the IP payload directly. On the wire it resembles IPv6
//! neighbor-discovery / ICMPv6 encapsulation, which many middleboxes pass
//! without deep inspection.

use async_trait::async_trait;

use crate::config::TransportKind;
use crate::error::Result;

use super::raw_core::RawCore;
use super::{Transport, TransportParams};

/// Protocol-58 transport.
pub struct Proto58Transport {
    core: RawCore,
}

impl Proto58Transport {
    /// Bind the raw socket for protocol 58.
    pub fn new(p: &TransportParams) -> Result<Proto58Transport> {
        Ok(Proto58Transport {
            core: RawCore::new(58, p)?,
        })
    }
}

#[async_trait]
impl Transport for Proto58Transport {
    fn kind(&self) -> TransportKind {
        TransportKind::Proto58
    }

    async fn send_frame(&self, frame: &[u8]) -> Result<()> {
        self.core.send_l4(frame).await
    }

    async fn recv_frame(&self, buf: &mut [u8]) -> Result<usize> {
        let (n, _src) = self.core.recv_l4(buf).await?;
        Ok(n)
    }
}
