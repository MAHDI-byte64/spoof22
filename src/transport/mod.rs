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

pub mod gre;
pub mod icmp;
pub mod ipip;
pub mod proto58;
pub mod quic;
pub mod raw_core;
pub mod tcp;
pub mod udp;

use std::sync::Arc;

use async_trait::async_trait;

use crate::config::{Config, Role, TransportKind};
use crate::error::Result;

/// Common parameters every raw transport needs, derived from config + role.
#[derive(Debug, Clone)]
pub struct TransportParams {
    /// Physical NIC to bind the raw socket to.
    pub interface: String,
    /// Forged source address for outgoing packets (== real_ip in no-spoof).
    pub forged_src: std::net::Ipv4Addr,
    /// The peer's real destination address.
    pub peer_real: std::net::Ipv4Addr,
    /// The peer's forged source as we expect to *see* it on inbound packets
    /// (used only to filter noise; authentication is cryptographic). Equals
    /// `peer_real` in no-spoof mode.
    pub peer_spoofed: std::net::Ipv4Addr,
    /// Our real address (for binding receive sockets / dst filtering).
    pub real_ip: std::net::Ipv4Addr,
    /// Accept any inbound source (probe mode `--check-allow-any`).
    pub accept_any_src: bool,
    /// L4 port (udp/tcp/quic).
    pub data_port: u16,
    /// ICMP identifier (icmp transport).
    pub icmp_id: u16,
    /// True on the server side (used by ICMP to send Echo *Reply* so the flow
    /// looks like a genuine ping request/reply exchange).
    pub is_server: bool,
    /// Prepend a 5-byte fake TLS Application-Data record on the TCP transport.
    pub fake_tls: bool,
    /// TTL values chosen at random per packet (TTL jitter).
    pub ttl_pool: Vec<u8>,
    /// DSCP/TOS bytes chosen at random per packet.
    pub dscp_pool: Vec<u8>,
    /// Socket send buffer size.
    pub sndbuf: usize,
    /// Socket receive buffer size.
    pub rcvbuf: usize,
}

impl TransportParams {
    /// Derive transport parameters from a validated config.
    pub fn from_config(cfg: &Config, role: Role) -> TransportParams {
        TransportParams {
            interface: cfg.transport.interface.clone(),
            forged_src: cfg.spoof.spoofed_ip,
            peer_real: cfg.spoof.peer_real_ip,
            peer_spoofed: cfg.spoof.peer_spoofed_ip,
            real_ip: cfg.spoof.real_ip,
            accept_any_src: false,
            data_port: cfg.transport.data_port,
            icmp_id: cfg.transport.icmp_id,
            is_server: matches!(role, Role::Server),
            fake_tls: cfg.obfs.fake_tls_header,
            ttl_pool: if cfg.obfs.ttl_jitter.is_empty() {
                vec![64]
            } else {
                cfg.obfs.ttl_jitter.clone()
            },
            dscp_pool: if cfg.obfs.random_dscp.is_empty() {
                vec![0]
            } else {
                cfg.obfs.random_dscp.clone()
            },
            sndbuf: 4 * 1024 * 1024,
            rcvbuf: 4 * 1024 * 1024,
        }
    }
}

/// Pick a random element from a non-empty pool (falls back to `default`).
pub fn pick(pool: &[u8], default: u8) -> u8 {
    use rand::Rng;
    if pool.is_empty() {
        default
    } else {
        pool[rand::thread_rng().gen_range(0..pool.len())]
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

/// Build a transport of `kind` for this side.
///
/// The raw transports derive their parameters from the config; QUIC needs the
/// full config (cert paths, SNI, windows) and establishes its connection here.
pub async fn build(kind: TransportKind, cfg: &Config, role: Role) -> Result<Arc<dyn Transport>> {
    let params = TransportParams::from_config(cfg, role);
    match kind {
        TransportKind::Udp => Ok(Arc::new(udp::UdpTransport::bind(&params).await?)),
        TransportKind::Icmp => Ok(Arc::new(icmp::IcmpTransport::new(&params)?)),
        TransportKind::Proto58 => Ok(Arc::new(proto58::Proto58Transport::new(&params)?)),
        TransportKind::Ipip => Ok(Arc::new(ipip::IpipTransport::new(&params)?)),
        TransportKind::Gre => Ok(Arc::new(gre::GreTransport::new(&params)?)),
        TransportKind::Tcp => Ok(Arc::new(tcp::TcpTransport::new(&params)?)),
        TransportKind::Quic => Ok(Arc::new(quic::QuicTransport::establish(cfg, role).await?)),
    }
}
