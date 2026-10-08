//! Library-wide error type.
//!
//! The crate follows the spec's error-handling rule: `thiserror` for the
//! library layer (this module) and `anyhow` only at the binary boundaries
//! (`src/cmd/*`). Every fallible function in the hot path returns
//! [`Result<T>`]; nothing in the packet path is allowed to `unwrap()` or
//! `panic!`.

use std::io;
use std::net::AddrParseError;

/// Convenient crate-wide result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// All errors produced by the `freespoof` library.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Configuration failed to parse or validate.
    #[error("config error: {0}")]
    Config(String),

    /// A cross-side agreement rule was violated (same psk/ports/aead, swapped
    /// tun ips, QUIC+spoof conflict, etc.).
    #[error("config validation: {0}")]
    Validation(String),

    /// Cryptographic handshake failure (Noise / ML-KEM / key schedule).
    #[error("handshake error: {0}")]
    Handshake(String),

    /// AEAD seal/open failure, replay, or nonce exhaustion.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// A frame failed strict, bounds-checked decoding. This is the primary
    /// attack-surface error and is always handled by dropping the frame.
    #[error("malformed frame: {0}")]
    Decode(String),

    /// Protocol version mismatch negotiated during handshake or seen on wire.
    #[error("protocol version mismatch: local={local} peer={peer}")]
    VersionMismatch { local: u8, peer: u8 },

    /// A transport (udp/icmp/proto58/tcp/quic/ipip/gre) failed to set up or run.
    #[error("transport error [{transport}]: {reason}")]
    Transport {
        transport: &'static str,
        reason: String,
    },

    /// TUN device / firewall / routing setup failure.
    #[error("tun/routing error: {0}")]
    Tun(String),

    /// Insufficient privileges (needs CAP_NET_RAW + CAP_NET_ADMIN or root).
    #[error("insufficient privileges: {0}")]
    Privilege(String),

    /// The peer is unauthenticated / unknown — fail closed, drop silently.
    #[error("unauthenticated peer")]
    Unauthenticated,

    /// Session lifecycle error (pool, failover, migration, reconnect).
    #[error("session error: {0}")]
    Session(String),

    /// Underlying OS/IO error.
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// Address parse error from config or wire.
    #[error("address parse error: {0}")]
    Addr(#[from] AddrParseError),
}

impl Error {
    /// Build a transport error without boilerplate.
    pub fn transport(transport: &'static str, reason: impl Into<String>) -> Self {
        Error::Transport {
            transport,
            reason: reason.into(),
        }
    }

    /// Build a config error.
    pub fn config(msg: impl Into<String>) -> Self {
        Error::Config(msg.into())
    }

    /// Build a validation error.
    pub fn validation(msg: impl Into<String>) -> Self {
        Error::Validation(msg.into())
    }

    /// Build a decode error (bounds-check failures in the raw parser).
    pub fn decode(msg: impl Into<String>) -> Self {
        Error::Decode(msg.into())
    }

    /// Build a crypto error.
    pub fn crypto(msg: impl Into<String>) -> Self {
        Error::Crypto(msg.into())
    }

    /// Build a handshake error.
    pub fn handshake(msg: impl Into<String>) -> Self {
        Error::Handshake(msg.into())
    }

    /// True for errors that should be handled by silently dropping a packet
    /// rather than tearing down a tunnel (fail-closed, anti-probing posture).
    pub fn is_droppable(&self) -> bool {
        matches!(
            self,
            Error::Decode(_)
                | Error::Crypto(_)
                | Error::Unauthenticated
                | Error::VersionMismatch { .. }
        )
    }
}
