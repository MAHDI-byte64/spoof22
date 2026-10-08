//! Pluggable transports.
//!
//! A [`Transport`] moves opaque wire frames (see [`crate::wire`]) between the
//! two endpoints. Each concrete transport decides how a frame is encapsulated
//! on the wire (UDP datagram, ICMP echo, raw proto-58, TCP segment, QUIC
//! stream, IP-in-IP, GRE) and how the forged source / real destination are
//! applied. The session layer treats every transport uniformly through this
//! trait, enabling racing, failover and hopping.
//!
//! Milestone 1 ships the UDP transport; the remaining six arrive in
//! milestone 2 (and are wired into [`build`] there).

pub mod udp;

use std::sync::Arc;

use async_trait::async_trait;

use crate::config::{Config, Role, TransportKind};
use crate::error::{Error, Result};

/// Common parameters every raw transport needs, derived from config + role.
#[derive(Debug, Clone)]
pub struct TransportParams {
    /// Physical NIC to bind the raw socket to.
    pub interface: String,
    /// Forged source address for outgoing packets (== real_ip in no-spoof).
    pub forged_src: std::net::Ipv4Addr,
    /// The peer's real destination address.
    pub peer_real: std::net::Ipv4Addr,
    /// Our real address (for binding receive sockets).
    pub real_ip: std::net::Ipv4Addr,
    /// L4 port (udp/tcp/quic).
    pub data_port: u16,
    /// ICMP identifier (icmp transport).
    pub icmp_id: u16,
    /// Default TTL (obfuscation may override per-packet later).
    pub ttl: u8,
    /// Default TOS/DSCP byte.
    pub tos: u8,
    /// Socket send buffer size.
    pub sndbuf: usize,
    /// Socket receive buffer size.
    pub rcvbuf: usize,
}

impl TransportParams {
    /// Derive transport parameters from a validated config.
    pub fn from_config(cfg: &Config, _role: Role) -> TransportParams {
        TransportParams {
            interface: cfg.transport.interface.clone(),
            forged_src: cfg.spoof.spoofed_ip,
            peer_real: cfg.spoof.peer_real_ip,
            real_ip: cfg.spoof.real_ip,
            data_port: cfg.transport.data_port,
            icmp_id: cfg.transport.icmp_id,
            ttl: *cfg.obfs.ttl_jitter.first().unwrap_or(&64),
            tos: *cfg.obfs.random_dscp.first().unwrap_or(&0),
            sndbuf: 4 * 1024 * 1024,
            rcvbuf: 4 * 1024 * 1024,
        }
    }
}

/// A transport moves opaque frames between the two endpoints.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Which transport kind this is.
    fn kind(&self) -> TransportKind;

    /// Send one wire frame to the peer.
    async fn send_frame(&self, frame: &[u8]) -> Result<()>;

    /// Receive one wire frame from the peer into `buf`, returning its length.
    async fn recv_frame(&self, buf: &mut [u8]) -> Result<usize>;
}

/// Build a transport of `kind` from the given parameters.
pub async fn build(kind: TransportKind, params: &TransportParams) -> Result<Arc<dyn Transport>> {
    match kind {
        TransportKind::Udp => Ok(Arc::new(udp::UdpTransport::bind(params).await?)),
        // The remaining transports are implemented in milestone 2.
        other => Err(Error::transport(
            other.as_str(),
            "transport not available in this build milestone (milestone 2 adds it)",
        )),
    }
}
