//! # freespoof
//!
//! A bidirectional, DPI-resistant, IP-spoofing point-to-point tunnel for
//! **authorized** anti-censorship use on links where the operator controls
//! *both* endpoints and is permitted to emit spoofed-source packets on the
//! path.
//!
//! ## Trust model
//!
//! Every outgoing raw IPv4 packet carries a forged SOURCE address; the
//! DESTINATION is always the peer's real address, so returns reach the real
//! peer and routing works. Peer identity is **never** inferred from the forged
//! source field — it is established by a mutually-authenticated Noise_IK
//! handshake (optionally hybridized with ML-KEM). Unauthenticated traffic is
//! dropped silently (fail-closed) or diverted to a decoy site.
//!
//! ## Module map (mirrors the spec architecture)
//!
//! * [`config`]      — TOML schema, defaults, validation (incl. cross-side rules)
//! * [`log`]         — colored structured logging + startup banner
//! * [`crypto`]      — Noise_IK handshake, ML-KEM hybrid, AEAD, anti-replay, rekey
//! * [`spoof`]       — raw IPv4 construction, source forging, checksums, IP-ID
//! * [`wire`]        — on-wire framing + protocol versioning
//! * [`transport`]   — pluggable `Transport` trait + the seven transports
//! * [`tun`]         — TUN device, NAT/firewall, routing, kill switch
//! * [`session`]     — tunnel pool, failover, migration, reconnection, lifecycle
//!
//! Later milestones add [`mux`], [`fec`], [`obfs`], [`mtu`], [`tune`],
//! [`reliability`], [`metrics`] and [`control`].

#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(rust_2018_idioms)]

pub mod error;

pub mod app;
pub mod config;
pub mod crypto;
pub mod log;
pub mod session;
pub mod spoof;
pub mod transport;
pub mod tun;
pub mod wire;

pub use error::{Error, Result};

/// Human-readable product name used in banners and logs.
pub const PRODUCT: &str = "freespoof";

/// Crate version, surfaced in the banner and the handshake.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The on-wire protocol version. Bumped on any incompatible framing or
/// handshake change. It is embedded in the wire framing AND negotiated during
/// the handshake; a mismatch fails gracefully with [`Error::VersionMismatch`].
pub const PROTOCOL_VERSION: u8 = 1;

/// A 4-byte magic prefix on the handshake's first message, used only to make
/// logs/pcaps legible during development. It is NOT a security boundary and is
/// easily stripped by the obfuscation layer; real authentication is the Noise
/// handshake.
pub const HANDSHAKE_MAGIC: [u8; 4] = *b"FSPF";
