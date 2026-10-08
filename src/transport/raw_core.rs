//! Shared core for the raw-crafted transports (`icmp`, `proto58`, `ipip`,
//! `gre`). Each such transport differs only in its IP protocol number and a
//! thin L4 wrapper around the wire frame; everything else — building the
//! forged IPv4 header, sending on the raw socket, receiving + parsing +
//! source/protocol filtering — is identical and lives here.

use std::net::Ipv4Addr;

use crate::error::Result;
use crate::spoof::ipv4::{self, Ipv4Build};
use crate::spoof::{IpIdCounter, RawIpSocket};

use super::TransportParams;

/// A reusable raw-IPv4 send/receive core bound to one protocol.
pub struct RawCore {
    raw: RawIpSocket,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    expect_src: Ipv4Addr,
    accept_any: bool,
    ttl_pool: Vec<u8>,
    dscp_pool: Vec<u8>,
    protocol: u8,
    ip_id: IpIdCounter,
}

impl RawCore {
    /// Create a raw core for `protocol` using the transport parameters.
    pub fn new(protocol: u8, p: &TransportParams) -> Result<RawCore> {
        let raw = RawIpSocket::new(protocol, &p.interface, p.sndbuf, p.rcvbuf)?;
        Ok(RawCore {
            raw,
            src: p.forged_src,
            dst: p.peer_real,
            expect_src: p.peer_spoofed,
            accept_any: p.accept_any_src,
            ttl_pool: p.ttl_pool.clone(),
            dscp_pool: p.dscp_pool.clone(),
            protocol,
            ip_id: IpIdCounter::new(),
        })
    }

    /// Build the IPv4 packet around an already-formed L4 payload and send it,
    /// applying per-packet TTL jitter and DSCP marking.
    pub async fn send_l4(&self, l4: &[u8]) -> Result<()> {
        let pkt = ipv4::build(&Ipv4Build {
            src: self.src,
            dst: self.dst,
            protocol: self.protocol,
            ttl: super::pick(&self.ttl_pool, 64),
            tos: super::pick(&self.dscp_pool, 0),
            id: self.ip_id.next(),
            payload: l4,
        });
        self.raw.send_to(&pkt, self.dst).await?;
        Ok(())
    }

    /// Receive one inbound packet of our protocol, validate the IPv4 header,
    /// filter by expected source, and copy the L4 payload into `out`,
    /// returning `(payload_len, observed_source)`. Non-matching packets are
    /// skipped. (A buffer-pool optimization replaces the per-call scratch
    /// allocation in the performance milestone.)
    pub async fn recv_l4(&self, out: &mut [u8]) -> Result<(usize, Ipv4Addr)> {
        let mut scratch = vec![0u8; 65_535];
        loop {
            let n = self.raw.recv(&mut scratch).await?;
            let view = match ipv4::parse(&scratch[..n]) {
                Ok(v) => v,
                Err(_) => continue, // malformed IP — skip
            };
            if view.protocol != self.protocol {
                continue;
            }
            if !self.accept_any && view.src != self.expect_src {
                continue; // not our peer's expected (forged) source — skip
            }
            let payload = view.payload;
            let m = payload.len().min(out.len());
            out[..m].copy_from_slice(&payload[..m]);
            return Ok((m, view.src));
        }
    }
}
