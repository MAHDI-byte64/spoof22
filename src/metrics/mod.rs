//! Observability metrics in Prometheus text-exposition format.
//!
//! Hand-rolled over atomics (no extra dependency): throughput, packets, RTT,
//! loss, FEC recovery, active tunnels, rekeys, and labeled counters for
//! drops-by-reason and per-transport stats. [`Metrics::encode`] renders the
//! Prometheus text format consumed by both the `/metrics` HTTP endpoint and the
//! control socket's `stats` command.

pub mod server;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;

/// Shared metrics handle (clone is cheap — it is an `Arc`).
#[derive(Clone)]
pub struct Metrics(Arc<Inner>);

struct Inner {
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    tx_packets: AtomicU64,
    rx_packets: AtomicU64,
    rtt_us: AtomicU64,
    loss_ppm: AtomicU64, // loss rate in parts-per-million
    fec_recovered: AtomicU64,
    active_tunnels: AtomicU64,
    rekeys: AtomicU64,
    reconnects: AtomicU64,
    drops: Mutex<HashMap<&'static str, u64>>,
    per_transport_tx: Mutex<HashMap<String, u64>>,
}

/// Reasons a frame can be dropped (bounded, static set for the label).
pub mod drop_reason {
    pub const REPLAY: &str = "replay";
    pub const AEAD: &str = "aead";
    pub const DECODE: &str = "decode";
    pub const UNAUTH: &str = "unauthenticated";
    pub const VERSION: &str = "version";
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    /// Create a fresh metrics registry.
    pub fn new() -> Metrics {
        Metrics(Arc::new(Inner {
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            rtt_us: AtomicU64::new(0),
            loss_ppm: AtomicU64::new(0),
            fec_recovered: AtomicU64::new(0),
            active_tunnels: AtomicU64::new(0),
            rekeys: AtomicU64::new(0),
            reconnects: AtomicU64::new(0),
            drops: Mutex::new(HashMap::new()),
            per_transport_tx: Mutex::new(HashMap::new()),
        }))
    }

    #[inline]
    pub fn add_tx(&self, bytes: usize) {
        self.0.tx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        self.0.tx_packets.fetch_add(1, Ordering::Relaxed);
    }
    #[inline]
    pub fn add_rx(&self, bytes: usize) {
        self.0.rx_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        self.0.rx_packets.fetch_add(1, Ordering::Relaxed);
    }
    pub fn add_transport_tx(&self, transport: &str, bytes: usize) {
        *self
            .0
            .per_transport_tx
            .lock()
            .entry(transport.to_string())
            .or_insert(0) += bytes as u64;
    }
    pub fn drop_frame(&self, reason: &'static str) {
        *self.0.drops.lock().entry(reason).or_insert(0) += 1;
    }
    pub fn set_rtt_us(&self, us: u64) {
        self.0.rtt_us.store(us, Ordering::Relaxed);
    }
    pub fn set_loss_ppm(&self, ppm: u64) {
        self.0.loss_ppm.store(ppm, Ordering::Relaxed);
    }
    pub fn add_fec_recovered(&self, n: u64) {
        self.0.fec_recovered.fetch_add(n, Ordering::Relaxed);
    }
    pub fn set_active_tunnels(&self, n: u64) {
        self.0.active_tunnels.store(n, Ordering::Relaxed);
    }
    pub fn inc_rekeys(&self) {
        self.0.rekeys.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_reconnects(&self) {
        self.0.reconnects.fetch_add(1, Ordering::Relaxed);
    }

    /// Render the Prometheus text exposition format.
    pub fn encode(&self) -> String {
        let i = &self.0;
        let mut s = String::with_capacity(1024);
        let g = |s: &mut String, name: &str, help: &str, ty: &str, val: u64| {
            s.push_str(&format!("# HELP freespoof_{name} {help}\n"));
            s.push_str(&format!("# TYPE freespoof_{name} {ty}\n"));
            s.push_str(&format!("freespoof_{name} {val}\n"));
        };
        g(
            &mut s,
            "tx_bytes_total",
            "Bytes sent over transports",
            "counter",
            i.tx_bytes.load(Ordering::Relaxed),
        );
        g(
            &mut s,
            "rx_bytes_total",
            "Bytes received",
            "counter",
            i.rx_bytes.load(Ordering::Relaxed),
        );
        g(
            &mut s,
            "tx_packets_total",
            "Frames sent",
            "counter",
            i.tx_packets.load(Ordering::Relaxed),
        );
        g(
            &mut s,
            "rx_packets_total",
            "Frames received",
            "counter",
            i.rx_packets.load(Ordering::Relaxed),
        );
        g(
            &mut s,
            "rtt_microseconds",
            "Estimated RTT",
            "gauge",
            i.rtt_us.load(Ordering::Relaxed),
        );
        g(
            &mut s,
            "loss_ppm",
            "Estimated loss (parts per million)",
            "gauge",
            i.loss_ppm.load(Ordering::Relaxed),
        );
        g(
            &mut s,
            "fec_recovered_total",
            "Frames recovered by FEC",
            "counter",
            i.fec_recovered.load(Ordering::Relaxed),
        );
        g(
            &mut s,
            "active_tunnels",
            "Active tunnel streams",
            "gauge",
            i.active_tunnels.load(Ordering::Relaxed),
        );
        g(
            &mut s,
            "rekeys_total",
            "Rekey events",
            "counter",
            i.rekeys.load(Ordering::Relaxed),
        );
        g(
            &mut s,
            "reconnects_total",
            "Reconnect events",
            "counter",
            i.reconnects.load(Ordering::Relaxed),
        );

        s.push_str("# HELP freespoof_drops_total Dropped frames by reason\n");
        s.push_str("# TYPE freespoof_drops_total counter\n");
        for (reason, n) in i.drops.lock().iter() {
            s.push_str(&format!(
                "freespoof_drops_total{{reason=\"{reason}\"}} {n}\n"
            ));
        }
        s.push_str("# HELP freespoof_transport_tx_bytes_total Bytes sent per transport\n");
        s.push_str("# TYPE freespoof_transport_tx_bytes_total counter\n");
        for (t, n) in i.per_transport_tx.lock().iter() {
            s.push_str(&format!(
                "freespoof_transport_tx_bytes_total{{transport=\"{t}\"}} {n}\n"
            ));
        }
        s
    }

    /// A compact JSON health/status snapshot for the `/health` endpoint.
    pub fn health_json(&self) -> String {
        let i = &self.0;
        format!(
            "{{\"status\":\"ok\",\"tx_bytes\":{},\"rx_bytes\":{},\"active_tunnels\":{},\"rekeys\":{},\"reconnects\":{}}}",
            i.tx_bytes.load(Ordering::Relaxed),
            i.rx_bytes.load(Ordering::Relaxed),
            i.active_tunnels.load(Ordering::Relaxed),
            i.rekeys.load(Ordering::Relaxed),
            i.reconnects.load(Ordering::Relaxed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_prometheus_text() {
        let m = Metrics::new();
        m.add_tx(1000);
        m.add_rx(500);
        m.drop_frame(drop_reason::REPLAY);
        m.add_transport_tx("udp", 1000);
        let text = m.encode();
        assert!(text.contains("freespoof_tx_bytes_total 1000"));
        assert!(text.contains("freespoof_rx_bytes_total 500"));
        assert!(text.contains("reason=\"replay\""));
        assert!(text.contains("transport=\"udp\""));
    }

    #[test]
    fn health_is_json() {
        let m = Metrics::new();
        m.add_tx(42);
        assert!(m.health_json().contains("\"tx_bytes\":42"));
    }
}
