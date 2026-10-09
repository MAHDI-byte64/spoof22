//! Keepalive / heartbeat and dead-peer detection.
//!
//! Tracks the last time we sent and received anything. If nothing has been
//! sent for `interval`, the data plane emits a `Keepalive` frame (which also
//! keeps NAT mappings warm). If nothing has been *received* for
//! `dead_after`, the peer is declared dead and the session layer triggers an
//! exponential-backoff reconnect.
//!
//! Times are passed in explicitly so the logic is unit-testable without
//! sleeping.

use std::time::{Duration, Instant};

/// Liveness tracker for one session.
#[derive(Debug, Clone, Copy)]
pub struct Liveness {
    last_rx: Instant,
    last_tx: Instant,
    interval: Duration,
    dead_after: Duration,
}

impl Liveness {
    /// Create a tracker. `keepalive_secs == 0` disables heartbeats;
    /// `dead_secs == 0` disables dead-peer detection.
    pub fn new(now: Instant, keepalive_secs: u64, dead_secs: u64) -> Liveness {
        Liveness {
            last_rx: now,
            last_tx: now,
            interval: Duration::from_secs(keepalive_secs),
            dead_after: Duration::from_secs(dead_secs),
        }
    }

    /// Record inbound activity.
    pub fn on_rx(&mut self, now: Instant) {
        self.last_rx = now;
    }

    /// Record outbound activity.
    pub fn on_tx(&mut self, now: Instant) {
        self.last_tx = now;
    }

    /// Should we send a keepalive now?
    pub fn needs_keepalive(&self, now: Instant) -> bool {
        !self.interval.is_zero() && now.duration_since(self.last_tx) >= self.interval
    }

    /// Has the peer gone silent past the dead-peer threshold?
    pub fn is_dead(&self, now: Instant) -> bool {
        !self.dead_after.is_zero() && now.duration_since(self.last_rx) >= self.dead_after
    }

    /// Keepalive poll interval (half the heartbeat, min 1s) for the timer.
    pub fn poll_interval(&self) -> Duration {
        if self.interval.is_zero() {
            Duration::from_secs(5)
        } else {
            (self.interval / 2).max(Duration::from_secs(1))
        }
    }
}

/// Exponential backoff for reconnection.
#[derive(Debug, Clone, Copy)]
pub struct Backoff {
    min: Duration,
    max: Duration,
    current: Duration,
}

impl Backoff {
    pub fn new(min_ms: u64, max_ms: u64) -> Backoff {
        let min = Duration::from_millis(min_ms.max(1));
        Backoff {
            min,
            max: Duration::from_millis(max_ms.max(min_ms.max(1))),
            current: min,
        }
    }

    /// Next delay, doubling up to `max`.
    pub fn next_delay(&mut self) -> Duration {
        let d = self.current;
        self.current = (self.current * 2).min(self.max);
        d
    }

    /// Reset to the minimum after a successful connection.
    pub fn reset(&mut self) {
        self.current = self.min;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keepalive_and_dead_thresholds() {
        let t0 = Instant::now();
        let mut l = Liveness::new(t0, 10, 60);
        assert!(!l.needs_keepalive(t0));
        assert!(l.needs_keepalive(t0 + Duration::from_secs(10)));
        assert!(!l.is_dead(t0 + Duration::from_secs(59)));
        assert!(l.is_dead(t0 + Duration::from_secs(60)));
        l.on_rx(t0 + Duration::from_secs(60));
        assert!(!l.is_dead(t0 + Duration::from_secs(60)));
    }

    #[test]
    fn disabled_when_zero() {
        let t0 = Instant::now();
        let l = Liveness::new(t0, 0, 0);
        assert!(!l.needs_keepalive(t0 + Duration::from_secs(3600)));
        assert!(!l.is_dead(t0 + Duration::from_secs(3600)));
    }

    #[test]
    fn backoff_doubles_and_caps() {
        let mut b = Backoff::new(500, 4000);
        assert_eq!(b.next_delay(), Duration::from_millis(500));
        assert_eq!(b.next_delay(), Duration::from_millis(1000));
        assert_eq!(b.next_delay(), Duration::from_millis(2000));
        assert_eq!(b.next_delay(), Duration::from_millis(4000));
        assert_eq!(b.next_delay(), Duration::from_millis(4000)); // capped
        b.reset();
        assert_eq!(b.next_delay(), Duration::from_millis(500));
    }
}
