//! IP spoofing: raw IPv4 construction, source forging, checksums, IP-ID.
//!
//! The forged SOURCE varies per session (from `spoofed_ip_pool`) to resist
//! per-source rate-limiting and flow tracking; the DESTINATION is always the
//! peer's real address so returns reach the real peer and routing works. Peer
//! identity is established cryptographically, never by the source field.

pub mod checksum;
pub mod ipv4;
pub mod socket;

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU16, Ordering};

pub use ipv4::{Ipv4Build, Ipv4View};
pub use socket::RawIpSocket;

/// A wrapping 16-bit IP identification counter (lock-free, one atomic add per
/// packet). Starts at a random value so flows aren't trivially correlated.
pub struct IpIdCounter(AtomicU16);

impl IpIdCounter {
    /// Create a counter seeded with a random start value.
    pub fn new() -> Self {
        let mut b = [0u8; 2];
        let _ = getrandom::getrandom(&mut b);
        IpIdCounter(AtomicU16::new(u16::from_ne_bytes(b)))
    }

    /// Next IP-ID (wraps at 2^16).
    #[inline]
    pub fn next(&self) -> u16 {
        self.0.fetch_add(1, Ordering::Relaxed)
    }
}

impl Default for IpIdCounter {
    fn default() -> Self {
        Self::new()
    }
}

/// Chooses the forged source address for a session.
#[derive(Debug, Clone)]
pub struct SpoofSource {
    primary: Ipv4Addr,
    pool: Vec<Ipv4Addr>,
}

impl SpoofSource {
    /// Build from the configured primary source and optional rotation pool.
    pub fn new(primary: Ipv4Addr, pool: Vec<Ipv4Addr>) -> Self {
        SpoofSource { primary, pool }
    }

    /// Pick the forged source for session index `idx`. With an empty pool the
    /// primary is always used; otherwise the pool is cycled deterministically
    /// so both ends can reason about which source a session uses.
    pub fn for_session(&self, idx: usize) -> Ipv4Addr {
        if self.pool.is_empty() {
            self.primary
        } else {
            self.pool[idx % self.pool.len()]
        }
    }

    /// Number of distinct forged sources available.
    pub fn len(&self) -> usize {
        self.pool.len().max(1)
    }

    /// Always false — there is always at least the primary source.
    pub fn is_empty(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_id_wraps() {
        let c = IpIdCounter(AtomicU16::new(u16::MAX));
        assert_eq!(c.next(), u16::MAX);
        assert_eq!(c.next(), 0);
    }

    #[test]
    fn source_rotation() {
        let s = SpoofSource::new(
            Ipv4Addr::new(10, 0, 0, 1),
            vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(2, 2, 2, 2)],
        );
        assert_eq!(s.for_session(0), Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(s.for_session(1), Ipv4Addr::new(2, 2, 2, 2));
        assert_eq!(s.for_session(2), Ipv4Addr::new(1, 1, 1, 1));

        let s2 = SpoofSource::new(Ipv4Addr::new(10, 0, 0, 1), vec![]);
        assert_eq!(s2.for_session(5), Ipv4Addr::new(10, 0, 0, 1));
    }
}
