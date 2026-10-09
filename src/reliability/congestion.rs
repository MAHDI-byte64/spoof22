//! Congestion control for the custom (non-QUIC) datagram paths.
//!
//! Two controllers are provided so the tunnel is a good citizen under loss:
//!
//! * [`Aimd`] — classic additive-increase / multiplicative-decrease over a
//!   packet-based congestion window with slow start.
//! * [`BbrLite`] — a simplified BBR: estimates bottleneck bandwidth (windowed
//!   max of delivery rate) and min RTT, and paces at `bw * gain`.
//!
//! Feedback comes from the periodic STATS control frame (see
//! [`super::keepalive`]): the receiver reports how many datagrams it got, from
//! which the sender derives deliveries and losses. QUIC keeps its own
//! controller and bypasses this entirely.

use std::time::Duration;

use crate::config::CongestionKind;

/// A congestion controller the sender consults for its window / pacing.
pub enum Congestion {
    Aimd(Aimd),
    Bbr(BbrLite),
    None,
}

impl Congestion {
    /// Build from config.
    pub fn new(kind: CongestionKind) -> Congestion {
        match kind {
            CongestionKind::Aimd => Congestion::Aimd(Aimd::new()),
            CongestionKind::Bbr => Congestion::Bbr(BbrLite::new()),
            CongestionKind::None => Congestion::None,
        }
    }

    /// Record a feedback round: `delivered` datagrams acked over `rtt`, each
    /// about `mss` bytes.
    pub fn on_feedback(&mut self, delivered: u64, lost: u64, rtt: Duration, mss: usize) {
        match self {
            Congestion::Aimd(a) => {
                for _ in 0..delivered {
                    a.on_ack();
                }
                if lost > 0 {
                    a.on_loss();
                }
            }
            Congestion::Bbr(b) => b.on_feedback(delivered, lost, rtt, mss),
            Congestion::None => {}
        }
    }

    /// Congestion window in packets (sender may have this many in flight).
    pub fn cwnd_packets(&self) -> usize {
        match self {
            Congestion::Aimd(a) => a.cwnd().max(1.0) as usize,
            Congestion::Bbr(b) => b.cwnd_packets(),
            Congestion::None => usize::MAX,
        }
    }

    /// Inter-packet pacing interval for a packet of `mss` bytes (zero = no pacing).
    pub fn pacing_interval(&self, mss: usize) -> Duration {
        match self {
            Congestion::Bbr(b) => b.pacing_interval(mss),
            _ => Duration::ZERO,
        }
    }
}

/// Classic AIMD controller.
pub struct Aimd {
    cwnd: f64,
    ssthresh: f64,
    min: f64,
    max: f64,
}

impl Aimd {
    pub fn new() -> Aimd {
        Aimd {
            cwnd: 10.0,
            ssthresh: 64.0,
            min: 2.0,
            max: 100_000.0,
        }
    }

    pub fn on_ack(&mut self) {
        if self.cwnd < self.ssthresh {
            self.cwnd += 1.0; // slow start
        } else {
            self.cwnd += 1.0 / self.cwnd; // congestion avoidance
        }
        self.cwnd = self.cwnd.min(self.max);
    }

    pub fn on_loss(&mut self) {
        self.ssthresh = (self.cwnd / 2.0).max(self.min);
        self.cwnd = self.ssthresh;
    }

    pub fn cwnd(&self) -> f64 {
        self.cwnd
    }
}

impl Default for Aimd {
    fn default() -> Self {
        Self::new()
    }
}

/// Simplified BBR: windowed max bandwidth + min RTT, paces at bw * gain.
pub struct BbrLite {
    btlbw_bps: f64, // bottleneck bandwidth estimate, bytes/sec
    rtprop: Duration,
    gain: f64,
}

impl BbrLite {
    pub fn new() -> BbrLite {
        BbrLite {
            btlbw_bps: 1_000_000.0,
            rtprop: Duration::from_millis(50),
            gain: 1.25,
        }
    }

    pub fn on_feedback(&mut self, delivered: u64, lost: u64, rtt: Duration, mss: usize) {
        if !rtt.is_zero() && delivered > 0 {
            let bytes = delivered as f64 * mss as f64;
            let rate = bytes / rtt.as_secs_f64();
            // Windowed max: take the larger, decay slowly otherwise.
            if rate > self.btlbw_bps {
                self.btlbw_bps = rate;
            } else {
                self.btlbw_bps = 0.95 * self.btlbw_bps + 0.05 * rate;
            }
            if rtt < self.rtprop || self.rtprop.is_zero() {
                self.rtprop = rtt;
            }
        }
        if lost > 0 {
            // Back off the bandwidth estimate under loss.
            self.btlbw_bps *= 0.85;
        }
    }

    pub fn cwnd_packets(&self) -> usize {
        // BDP in packets ≈ bw * rtprop / mss, with 2x headroom. Use 1500 MSS.
        let bdp_bytes = self.btlbw_bps * self.rtprop.as_secs_f64();
        ((bdp_bytes * 2.0) / 1500.0).ceil().max(4.0) as usize
    }

    pub fn pacing_interval(&self, mss: usize) -> Duration {
        let rate = (self.btlbw_bps * self.gain).max(1.0);
        Duration::from_secs_f64(mss as f64 / rate)
    }
}

impl Default for BbrLite {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aimd_grows_then_backs_off() {
        let mut a = Aimd::new();
        let start = a.cwnd();
        for _ in 0..20 {
            a.on_ack();
        }
        assert!(a.cwnd() > start);
        let before = a.cwnd();
        a.on_loss();
        assert!(a.cwnd() < before);
        assert!(a.cwnd() >= a.min);
    }

    #[test]
    fn bbr_tracks_bandwidth() {
        let mut b = BbrLite::new();
        b.on_feedback(100, 0, Duration::from_millis(20), 1500);
        assert!(b.cwnd_packets() >= 4);
        assert!(b.pacing_interval(1500) > Duration::ZERO);
    }

    #[test]
    fn congestion_none_is_unbounded() {
        let c = Congestion::new(CongestionKind::None);
        assert_eq!(c.cwnd_packets(), usize::MAX);
        assert_eq!(c.pacing_interval(1500), Duration::ZERO);
    }
}
