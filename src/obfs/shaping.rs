//! Traffic shaping: inter-packet timing jitter and constant-rate pacing.
//!
//! * **Timing jitter** adds a small random delay before each send to blur
//!   inter-packet timing, defeating simple timing-correlation analysis.
//! * **Constant-rate** pacing emits at a fixed cadence regardless of load; the
//!   session fills idle slots with cover/chaff frames so the flow's timing is
//!   independent of the real traffic. [`Pacer`] computes the slot interval.

use std::time::Duration;

use rand::Rng;

/// A random jitter delay in `0..=max_ms` milliseconds (zero if `max_ms == 0`).
pub fn jitter(max_ms: u64) -> Duration {
    if max_ms == 0 {
        return Duration::ZERO;
    }
    let ms = rand::thread_rng().gen_range(0..=max_ms);
    Duration::from_millis(ms)
}

/// Fixed-cadence pacer for constant-rate shaping.
#[derive(Debug, Clone, Copy)]
pub struct Pacer {
    interval: Duration,
}

impl Pacer {
    /// Build a pacer for `pps` packets per second (returns `None` if disabled).
    pub fn new(pps: u64) -> Option<Pacer> {
        if pps == 0 {
            None
        } else {
            Some(Pacer {
                interval: Duration::from_nanos(1_000_000_000 / pps.max(1)),
            })
        }
    }

    /// The inter-slot interval.
    pub fn interval(&self) -> Duration {
        self.interval
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_within_bounds() {
        for _ in 0..100 {
            assert!(jitter(10) <= Duration::from_millis(10));
        }
        assert_eq!(jitter(0), Duration::ZERO);
    }

    #[test]
    fn pacer_interval() {
        assert!(Pacer::new(0).is_none());
        let p = Pacer::new(1000).unwrap();
        assert_eq!(p.interval(), Duration::from_millis(1));
    }
}
