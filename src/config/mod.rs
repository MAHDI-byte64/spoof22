//! Configuration: a single TOML schema shared by client and server.
//!
//! Every field the engine understands lives here. The schema is intentionally
//! grouped into sub-tables (`[spoof]`, `[crypto]`, `[tun]`, `[transport]`,
//! `[obfs]`, `[mux]`, `[fec]`, `[perf]`, `[reliability]`, `[observability]`)
//! so the generated `config/*.toml` files read cleanly. All fields have
//! defaults via `#[serde(default)]`, so a minimal file still loads and the
//! validator (see [`validate`]) reports precise errors.
//!
//! Persian field documentation lives in `config/client.toml`,
//! `config/server.toml` and `docs/CONFIG_REFERENCE.fa.md`. The TOML *key*
//! names stay English per the spec.

pub mod validate;

use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Which side of the tunnel this process is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Client,
    Server,
}

/// One of the seven pluggable wire transports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    /// IP proto 17. Plain UDP datagrams.
    Udp,
    /// IP proto 1. ICMP Echo, blends with ping.
    Icmp,
    /// IP proto 58. No L4 header — IPv6-ND camouflage.
    Proto58,
    /// IP proto 6. Looks like HTTP/HTTPS, optional fake-TLS record framing.
    Tcp,
    /// UDP + real QUIC/TLS 1.3 (kernel UDP, real path validation).
    Quic,
    /// IP proto 4. IP-in-IP (RFC 2003).
    Ipip,
    /// IP proto 47. GRE (RFC 2784), looks like a real GRE VPN.
    Gre,
}

impl TransportKind {
    /// Static label for logs / error messages.
    pub fn as_str(self) -> &'static str {
        match self {
            TransportKind::Udp => "udp",
            TransportKind::Icmp => "icmp",
            TransportKind::Proto58 => "proto58",
            TransportKind::Tcp => "tcp",
            TransportKind::Quic => "quic",
            TransportKind::Ipip => "ipip",
            TransportKind::Gre => "gre",
        }
    }

    /// Transports crafted on raw IPv4 sockets, where a forged source address
    /// is possible. QUIC uses the kernel UDP stack + TLS tied to the 4-tuple,
    /// so it can NOT be spoofed and is deliberately excluded.
    pub fn supports_spoofing(self) -> bool {
        matches!(
            self,
            TransportKind::Udp
                | TransportKind::Icmp
                | TransportKind::Proto58
                | TransportKind::Ipip
                | TransportKind::Gre
                | TransportKind::Tcp // synthetic raw-socket TCP (stack implemented manually)
        )
    }

    /// Mux/FEC only apply to the raw datagram-style transports, never tcp/quic
    /// (which carry their own reliable/stream semantics).
    pub fn supports_mux_fec(self) -> bool {
        matches!(
            self,
            TransportKind::Udp | TransportKind::Icmp | TransportKind::Proto58 | TransportKind::Ipip
        )
    }

    /// The IPv4 protocol number this transport rides on the wire.
    pub fn ip_protocol(self) -> u8 {
        match self {
            TransportKind::Udp | TransportKind::Quic => 17,
            TransportKind::Icmp => 1,
            TransportKind::Proto58 => 58,
            TransportKind::Tcp => 6,
            TransportKind::Ipip => 4,
            TransportKind::Gre => 47,
        }
    }
}

/// Per-frame AEAD selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AeadKind {
    /// ChaCha20-Poly1305 (default, constant-time in software everywhere).
    Chacha20Poly1305,
    /// AES-256-GCM (preferred when the CPU has AES-NI; auto-tune may pick it).
    Aes256Gcm,
}

/// Post-quantum ML-KEM parameter set for the hybrid handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PqLevel {
    MlKem512,
    MlKem768,
    MlKem1024,
}

/// FEC coding scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FecMode {
    /// Single-parity XOR: recovers one loss per group, minimal overhead.
    Xor,
    /// Reed-Solomon: recovers multiple losses per group.
    ReedSolomon,
}

/// Routing posture for the TUN interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingMode {
    /// Default route via the tunnel (all traffic).
    Full,
    /// Only the configured CIDRs/ports go via the tunnel.
    Split,
}

/// Performance posture used by the auto-tuner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PerfMode {
    Throughput,
    Latency,
    Balanced,
}

/// Congestion controller on the custom (non-QUIC) paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CongestionKind {
    /// BBR-like model-based controller.
    Bbr,
    /// Classic AIMD.
    Aimd,
    /// Disabled (QUIC transports always keep their own regardless).
    None,
}

/// Traffic-mimicry profile ("looks like ...").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MimicryProfile {
    None,
    Http2,
    Http3,
    Doh,
    WebSocket,
    VideoStream,
}

/// Browser TLS fingerprint to mimic (uTLS-style).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsFingerprint {
    Chrome,
    Firefox,
    Safari,
    /// Do not reshape — use the native rustls fingerprint (not recommended).
    Native,
}

// ---------------------------------------------------------------------------
// Sub-tables
// ---------------------------------------------------------------------------

/// `[spoof]` — IP spoofing and addressing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SpoofConfig {
    /// This host's real address on the physical NIC.
    pub real_ip: Ipv4Addr,
    /// The peer's real address (datagrams are ALWAYS destined here so returns
    /// reach the real peer; peer identity is verified cryptographically).
    pub peer_real_ip: Ipv4Addr,
    /// Forged SOURCE address stamped on our outgoing raw packets.
    pub spoofed_ip: Ipv4Addr,
    /// The peer's forged source (what we expect to *see*, never trusted).
    pub peer_spoofed_ip: Ipv4Addr,
    /// Cryptographically authorized peers (static public keys, hex). Empty =
    /// accept any peer that passes the handshake with the configured key.
    pub allowed_peers: Vec<String>,
    /// Pool of forged sources to rotate per session, to vary traffic patterns
    /// and resist per-source rate-limiting. Empty = use `spoofed_ip` only.
    pub spoofed_ip_pool: Vec<Ipv4Addr>,
    /// When true, spoofing is disabled: `spoofed_ip = real_ip` and
    /// `peer_spoofed_ip = peer_real_ip` are forced by the validator.
    pub no_spoof: bool,
}

impl Default for SpoofConfig {
    fn default() -> Self {
        SpoofConfig {
            real_ip: Ipv4Addr::UNSPECIFIED,
            peer_real_ip: Ipv4Addr::UNSPECIFIED,
            spoofed_ip: Ipv4Addr::UNSPECIFIED,
            peer_spoofed_ip: Ipv4Addr::UNSPECIFIED,
            allowed_peers: Vec::new(),
            spoofed_ip_pool: Vec::new(),
            no_spoof: false,
        }
    }
}

/// `[transport]` — wire transports and endpoint selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TransportConfig {
    /// Physical NIC to bind the raw socket to (e.g. `eth0`).
    pub interface: String,
    /// Uplink (client→server) transport.
    pub uplink_protocol: TransportKind,
    /// Downlink (server→client) transport.
    pub downlink_protocol: TransportKind,
    /// L4 port used by udp/tcp/quic transports; must match on both sides.
    pub data_port: u16,
    /// Rotate the data port on a schedule (udp/tcp only, never with QUIC).
    pub shuffle_data_port: bool,
    pub shuffle_port_min: u16,
    pub shuffle_port_max: u16,
    /// ICMP Echo identifier for the `icmp` transport.
    pub icmp_id: u16,
    /// Randomize `icmp_id` per session (blends with real ping traffic).
    pub randomize_icmp_id: bool,
    /// Operator-controlled server endpoints to hop among (ip:port). The first
    /// is primary. Empty = derive one endpoint from `peer_real_ip:data_port`.
    pub server_endpoints: Vec<SocketAddrV4>,
    /// Seconds between endpoint/port hops (0 = disabled).
    pub endpoint_hop_interval_secs: u64,
    /// Race all configured transports at startup and keep the fastest to
    /// establish; the rest become failover candidates.
    pub transport_racing: bool,
    /// Ordered failover list; the engine degrades to the next on block/loss.
    pub failover_order: Vec<TransportKind>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        TransportConfig {
            interface: "eth0".to_string(),
            uplink_protocol: TransportKind::Udp,
            downlink_protocol: TransportKind::Udp,
            data_port: 51820,
            shuffle_data_port: false,
            shuffle_port_min: 20000,
            shuffle_port_max: 60000,
            icmp_id: 0x1234,
            randomize_icmp_id: true,
            server_endpoints: Vec::new(),
            endpoint_hop_interval_secs: 0,
            transport_racing: false,
            failover_order: Vec::new(),
        }
    }
}

/// `[crypto]` — handshake, AEAD, rekey, post-quantum.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CryptoConfig {
    /// This host's Noise static private key (X25519), base64. Generated by the
    /// manager / `--genkey` when empty.
    pub static_private_key: String,
    /// This host's Noise static public key (X25519), base64 (informational).
    pub static_public_key: String,
    /// The peer's Noise static public key (X25519), base64 — required for IK.
    pub peer_public_key: String,
    /// Optional extra symmetric layer mixed into the handshake (WireGuard-style
    /// IKpsk2). base64 or passphrase; empty = no PSK layer.
    pub pre_shared_key: String,
    /// Per-frame AEAD construction.
    pub aead: AeadKind,
    /// Prefer AES-256-GCM automatically when the CPU exposes AES-NI.
    pub aead_auto_hardware: bool,
    /// Enable the X25519 + ML-KEM post-quantum hybrid handshake.
    pub pq_hybrid: bool,
    /// ML-KEM parameter set for the hybrid.
    pub pq_level: PqLevel,
    /// Rekey after this many bytes on a session (0 = disabled).
    pub rekey_bytes: u64,
    /// Rekey after this many seconds on a session (0 = disabled).
    pub rekey_secs: u64,
    /// Anti-replay sliding-window width in frames.
    pub replay_window: u32,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        CryptoConfig {
            static_private_key: String::new(),
            static_public_key: String::new(),
            peer_public_key: String::new(),
            pre_shared_key: String::new(),
            aead: AeadKind::Chacha20Poly1305,
            aead_auto_hardware: true,
            pq_hybrid: true,
            pq_level: PqLevel::MlKem768,
            rekey_bytes: 64 * 1024 * 1024 * 1024, // 64 GiB
            rekey_secs: 3600,
            replay_window: 2048,
        }
    }
}

/// `[tun]` — TUN device, routing, NAT, firewall.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TunConfig {
    /// TUN interface name (<= 15 chars).
    pub tun_name: String,
    /// This side's TUN address (point-to-point /30). Swapped between sides.
    pub tun_ip: Ipv4Addr,
    /// The peer's TUN address. Swapped between sides.
    pub tun_peer_ip: Ipv4Addr,
    /// TUN netmask (point-to-point link uses /30).
    pub tun_netmask: Ipv4Addr,
    /// Inner MTU on the TUN device; clamped to the engine `mtu`.
    pub tun_mtu: u32,
    /// Ports to NAT/forward to `tun_peer_ip` (TCP+UDP). Empty = all ports.
    pub forward_ports: Vec<u16>,
    /// Routing posture.
    pub routing_mode: RoutingMode,
    /// Split-tunnel CIDRs (e.g. `10.0.0.0/8`).
    pub split_cidrs: Vec<String>,
    /// Split-tunnel ports.
    pub split_ports: Vec<u16>,
    /// DNS servers to push/override for the tunnel.
    pub dns_servers: Vec<Ipv4Addr>,
    /// Resolve the tunnel's own names over DoH/DoT.
    pub dns_over_https: bool,
    /// Install a kill switch so a dropped tunnel does not leak over the NIC.
    pub kill_switch: bool,
}

impl Default for TunConfig {
    fn default() -> Self {
        TunConfig {
            tun_name: "freespoof0".to_string(),
            tun_ip: Ipv4Addr::new(10, 66, 0, 1),
            tun_peer_ip: Ipv4Addr::new(10, 66, 0, 2),
            tun_netmask: Ipv4Addr::new(255, 255, 255, 252), // /30
            tun_mtu: 1380,
            forward_ports: Vec::new(),
            routing_mode: RoutingMode::Full,
            split_cidrs: Vec::new(),
            split_ports: Vec::new(),
            dns_servers: vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(9, 9, 9, 9)],
            dns_over_https: false,
            kill_switch: true,
        }
    }
}

/// `[obfs]` — DPI obfuscation, mimicry and shaping.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ObfsConfig {
    /// Minimum random padding bytes appended per frame (0 = off).
    pub packet_padding: usize,
    /// Upper bound of random padding (1..=max chosen per frame).
    pub packet_padding_max: usize,
    /// TTL values chosen at random per packet (must match both sides).
    pub ttl_jitter: Vec<u8>,
    /// Prepend a 5-byte fake TLS Application-Data record on the TCP transport.
    pub fake_tls_header: bool,
    /// DSCP code points chosen at random per packet.
    pub random_dscp: Vec<u8>,
    /// Inter-packet timing jitter upper bound (milliseconds, 0 = off).
    pub timing_jitter_ms: u64,
    /// Constant-rate shaping: emit at a fixed packet cadence (0 = off).
    pub constant_rate_pps: u64,
    /// Pad every frame up to this fixed size (0 = off).
    pub pad_to_size: usize,
    /// Length-distribution mimicry profile.
    pub mimicry_profile: MimicryProfile,
    /// TLS fingerprint to mimic on tcp/quic.
    pub tls_fingerprint: TlsFingerprint,
    /// SNI presented by tcp/quic transports.
    pub sni: String,
    /// Use Encrypted Client Hello to hide the real SNI (when supported).
    pub ech: bool,
    /// Emit cover/chaff traffic to mask usage patterns (0 = off).
    pub cover_traffic_pps: u64,
    /// Active-probing decoy: reverse-proxy unauthenticated traffic to a real
    /// HTTPS site so probers see a legitimate website (Reality/Trojan-style).
    pub decoy_enabled: bool,
    /// Decoy upstream `host:port` to reverse-proxy to.
    pub decoy_target: String,
}

impl Default for ObfsConfig {
    fn default() -> Self {
        ObfsConfig {
            packet_padding: 0,
            packet_padding_max: 64,
            ttl_jitter: vec![64, 128, 255],
            fake_tls_header: false,
            random_dscp: vec![0x00, 0x28, 0x10],
            timing_jitter_ms: 0,
            constant_rate_pps: 0,
            pad_to_size: 0,
            mimicry_profile: MimicryProfile::None,
            tls_fingerprint: TlsFingerprint::Chrome,
            sni: "www.cloudflare.com".to_string(),
            ech: false,
            cover_traffic_pps: 0,
            decoy_enabled: false,
            decoy_target: "www.cloudflare.com:443".to_string(),
        }
    }
}

/// `[mux]` — packet batching.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MuxConfig {
    pub enable_multiplex: bool,
    /// Flush the batch after this many milliseconds even if not full.
    pub multiplex_flush_ms: u64,
    /// Max payload bytes per wire frame when batching.
    pub multiplex_max_payload: usize,
}

impl Default for MuxConfig {
    fn default() -> Self {
        MuxConfig {
            enable_multiplex: false,
            multiplex_flush_ms: 1,
            multiplex_max_payload: 1200,
        }
    }
}

/// `[fec]` — forward error correction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FecConfig {
    pub enable_fec: bool,
    /// Data shards per FEC group (>= 2).
    pub fec_group_size: usize,
    pub fec_mode: FecMode,
    /// Adapt redundancy to the measured loss rate.
    pub fec_adaptive: bool,
    /// Parity shards for Reed-Solomon mode (adaptive adjusts within bounds).
    pub fec_parity_shards: usize,
}

impl Default for FecConfig {
    fn default() -> Self {
        FecConfig {
            enable_fec: false,
            fec_group_size: 8,
            fec_mode: FecMode::ReedSolomon,
            fec_adaptive: true,
            fec_parity_shards: 2,
        }
    }
}

/// `[perf]` — parallelism, auto-tune, buffers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PerfConfig {
    /// Parallel independent tunnel streams (overridden by auto-tune).
    pub tunnel_count: usize,
    /// Detect CPU/RAM/NIC and set worker threads, tunnel count, capacities.
    pub auto_tune: bool,
    pub perf_mode: PerfMode,
    /// Effective engine MTU (the clamp for everything inner).
    pub mtu: u32,
    pub channel_capacity: usize,
    pub io_channel_capacity: usize,
    /// Tokio worker threads (0 = auto / number of cores).
    pub runtime_worker_threads: usize,
    /// Pin worker threads to CPUs at high throughput (best effort).
    pub cpu_pinning: bool,
    /// Use io_uring backend where available (best effort; falls back).
    pub io_uring: bool,
}

impl Default for PerfConfig {
    fn default() -> Self {
        PerfConfig {
            tunnel_count: 4,
            auto_tune: true,
            perf_mode: PerfMode::Balanced,
            mtu: 1380,
            channel_capacity: 1024,
            io_channel_capacity: 2048,
            runtime_worker_threads: 0,
            cpu_pinning: false,
            io_uring: false,
        }
    }
}

/// `[reliability]` — congestion control, keepalive, migration, reconnect.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ReliabilityConfig {
    pub congestion: CongestionKind,
    /// Keepalive/heartbeat interval (seconds, 0 = off).
    pub keepalive_secs: u64,
    /// Declare the peer dead after this many seconds without traffic.
    pub dead_peer_timeout_secs: u64,
    /// Auto-reconnect with exponential backoff on tunnel loss.
    pub auto_reconnect: bool,
    pub reconnect_backoff_min_ms: u64,
    pub reconnect_backoff_max_ms: u64,
    /// Survive client IP changes (Wi-Fi<->cellular) keyed by session id.
    pub enable_migration: bool,
}

impl Default for ReliabilityConfig {
    fn default() -> Self {
        ReliabilityConfig {
            congestion: CongestionKind::Bbr,
            keepalive_secs: 15,
            dead_peer_timeout_secs: 60,
            auto_reconnect: true,
            reconnect_backoff_min_ms: 500,
            reconnect_backoff_max_ms: 30_000,
            enable_migration: true,
        }
    }
}

/// `[observability]` — metrics, control socket, logging extras.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ObservabilityConfig {
    /// Prometheus `/metrics` listen address (empty = disabled).
    pub metrics_addr: String,
    /// Health/status `/health` listen address (empty = disabled).
    pub health_addr: String,
    /// Unix control socket for the admin CLI (empty = disabled).
    pub control_socket: String,
    /// Emit structured JSON logs alongside the pretty logs.
    pub json_logs: bool,
    /// Server-side: max handshake attempts per source IP per minute.
    pub handshake_rate_limit: u32,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        ObservabilityConfig {
            metrics_addr: String::new(),
            health_addr: String::new(),
            control_socket: "/run/freespoof.sock".to_string(),
            json_logs: false,
            handshake_rate_limit: 30,
        }
    }
}

/// `[quic]` — QUIC transport specifics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct QuicConfig {
    /// PEM certificate chain path (server). Generated by the manager.
    pub cert_path: String,
    /// PEM private key path (server).
    pub key_path: String,
    /// Server name the client validates / presents.
    pub server_name: String,
    /// Connection-level flow-control window (bytes).
    pub connection_window: u64,
    /// Per-stream flow-control window (bytes).
    pub stream_window: u64,
}

impl Default for QuicConfig {
    fn default() -> Self {
        QuicConfig {
            cert_path: "/etc/freespoof/quic-cert.pem".to_string(),
            key_path: "/etc/freespoof/quic-key.pem".to_string(),
            server_name: "www.cloudflare.com".to_string(),
            connection_window: 128 * 1024 * 1024, // 128 MB
            stream_window: 16 * 1024 * 1024,      // 16 MB
        }
    }
}

/// `[hardening]` — privilege drop & sandbox.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HardeningConfig {
    /// Drop to this user after acquiring caps / sockets / firewall (empty = no drop).
    pub run_as_user: String,
    /// Drop to this group after setup (empty = derive from user).
    pub run_as_group: String,
    /// Apply a seccomp/Landlock sandbox after init (best effort).
    pub sandbox: bool,
}

// ---------------------------------------------------------------------------
// Top-level config
// ---------------------------------------------------------------------------

/// The full `freespoof` configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// client | server. Also selectable on the CLI; CLI overrides the file.
    pub role: Role,
    /// Log level keyword: trace | debug | info | warn | error.
    pub log_level: String,
    /// Wire protocol version this build speaks (negotiated in the handshake).
    /// Informational in the file; the engine clamps it to [`crate::PROTOCOL_VERSION`].
    pub protocol_version: u8,

    pub spoof: SpoofConfig,
    pub transport: TransportConfig,
    pub crypto: CryptoConfig,
    pub tun: TunConfig,
    pub obfs: ObfsConfig,
    pub mux: MuxConfig,
    pub fec: FecConfig,
    pub perf: PerfConfig,
    pub reliability: ReliabilityConfig,
    pub observability: ObservabilityConfig,
    pub quic: QuicConfig,
    pub hardening: HardeningConfig,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            role: Role::Client,
            log_level: "info".to_string(),
            protocol_version: crate::PROTOCOL_VERSION,
            spoof: SpoofConfig::default(),
            transport: TransportConfig::default(),
            crypto: CryptoConfig::default(),
            tun: TunConfig::default(),
            obfs: ObfsConfig::default(),
            mux: MuxConfig::default(),
            fec: FecConfig::default(),
            perf: PerfConfig::default(),
            reliability: ReliabilityConfig::default(),
            observability: ObservabilityConfig::default(),
            quic: QuicConfig::default(),
            hardening: HardeningConfig::default(),
        }
    }
}

impl Config {
    /// Load a config from a TOML file, apply defaults, and fully validate it.
    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::config(format!("reading {}: {e}", path.display())))?;
        let mut cfg: Config =
            toml::from_str(&text).map_err(|e| Error::config(format!("parsing TOML: {e}")))?;
        cfg.normalize();
        cfg.validate()?;
        Ok(cfg)
    }

    /// Parse from a TOML string (used by tests and the pairing helper).
    pub fn from_toml_str(text: &str) -> Result<Config> {
        let mut cfg: Config =
            toml::from_str(text).map_err(|e| Error::config(format!("parsing TOML: {e}")))?;
        cfg.normalize();
        cfg.validate()?;
        Ok(cfg)
    }

    /// Serialize back to TOML (used by the pairing helper / manager).
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).map_err(|e| Error::config(format!("serializing TOML: {e}")))
    }

    /// Apply derived defaults that depend on other fields. Idempotent.
    fn normalize(&mut self) {
        // Clamp wire version to what this build actually speaks.
        self.protocol_version = crate::PROTOCOL_VERSION;

        // No-spoof mode forces real addresses everywhere.
        //
        // NOTE: QUIC is deliberately NOT auto-rewritten here. The spec requires
        // configs that combine QUIC with spoofing to be *rejected*, so the
        // validator surfaces an explicit error telling the operator to set
        // `no_spoof = true`, rather than silently changing their intent.
        if self.spoof.no_spoof {
            self.spoof.spoofed_ip = self.spoof.real_ip;
            self.spoof.peer_spoofed_ip = self.spoof.peer_real_ip;
            self.spoof.spoofed_ip_pool.clear();
        }

        // Clamp tun_mtu to engine mtu.
        if self.tun.tun_mtu > self.perf.mtu {
            self.tun.tun_mtu = self.perf.mtu;
        }

        // If no explicit endpoints, derive the primary from peer_real_ip.
        if self.transport.server_endpoints.is_empty()
            && self.spoof.peer_real_ip != Ipv4Addr::UNSPECIFIED
        {
            self.transport.server_endpoints.push(SocketAddrV4::new(
                self.spoof.peer_real_ip,
                self.transport.data_port,
            ));
        }
    }

    /// True if either direction uses QUIC.
    pub fn uses_quic(&self) -> bool {
        self.transport.uplink_protocol == TransportKind::Quic
            || self.transport.downlink_protocol == TransportKind::Quic
    }

    /// True if spoofing is active (not forced off).
    pub fn spoofing_active(&self) -> bool {
        !self.spoof.no_spoof && self.spoof.spoofed_ip != self.spoof.real_ip
    }

    /// Resolve the private-key path used by the manager / genkey helpers.
    pub fn default_key_dir() -> PathBuf {
        PathBuf::from("/etc/freespoof")
    }

    /// Run full validation (see [`validate`]).
    pub fn validate(&self) -> Result<()> {
        validate::validate(self)
    }
}
