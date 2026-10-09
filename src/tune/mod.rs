//! Hardware auto-detection and runtime parameter selection.
//!
//! Detects CPU cores, RAM and NIC link speed, then derives a [`ResolvedPlan`]
//! (worker threads, tunnel count, channel capacities, mux settings) from the
//! configured [`PerfMode`]. When `auto_tune` is off the configured values are
//! used verbatim. The pure planning function is unit-tested against synthetic
//! hardware so the policy is verifiable without special hardware.

use std::fs;

use crate::config::{Config, PerfMode};

/// Detected hardware facts.
#[derive(Debug, Clone, Copy)]
pub struct HwInfo {
    /// Logical CPU cores.
    pub cores: usize,
    /// Total RAM in MiB.
    pub ram_mib: u64,
    /// NIC link speed in Mbps (0 = unknown).
    pub nic_mbps: u64,
}

impl HwInfo {
    /// Detect hardware from the running system (Linux `/proc` + `/sys`).
    pub fn detect(interface: &str) -> HwInfo {
        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let ram_mib = read_mem_total_mib().unwrap_or(1024);
        let nic_mbps = read_nic_speed_mbps(interface).unwrap_or(0);
        HwInfo {
            cores,
            ram_mib,
            nic_mbps,
        }
    }
}

/// Resolved runtime plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedPlan {
    pub worker_threads: usize,
    pub tunnel_count: usize,
    pub channel_capacity: usize,
    pub io_channel_capacity: usize,
    pub mux_enabled: bool,
    pub mux_flush_ms: u64,
}

/// NIC speed → extra tunnels (+1 @1G, +2 @2G, +3 @5G, +4 @10G).
fn nic_boost(nic_mbps: u64) -> usize {
    match nic_mbps {
        0..=999 => 0,
        1000..=1999 => 1,
        2000..=4999 => 2,
        5000..=9999 => 3,
        _ => 4,
    }
}

/// Compute the runtime plan from config + detected hardware.
///
/// With `auto_tune = false` the configured values win (only clamped to sane
/// minimums). Otherwise the `PerfMode` policy from the spec applies.
pub fn plan(cfg: &Config, hw: HwInfo) -> ResolvedPlan {
    if !cfg.perf.auto_tune {
        return ResolvedPlan {
            worker_threads: if cfg.perf.runtime_worker_threads == 0 {
                hw.cores
            } else {
                cfg.perf.runtime_worker_threads
            },
            tunnel_count: cfg.perf.tunnel_count.max(1),
            channel_capacity: cfg.perf.channel_capacity.max(8),
            io_channel_capacity: cfg.perf.io_channel_capacity.max(8),
            mux_enabled: cfg.mux.enable_multiplex,
            mux_flush_ms: cfg.mux.multiplex_flush_ms.max(1),
        };
    }

    let cores = hw.cores.max(1);
    let boost = nic_boost(hw.nic_mbps);

    let (worker_threads, tunnel_count, mux_enabled, mux_flush_ms) = match cfg.perf.perf_mode {
        PerfMode::Throughput => {
            let tunnels = (cores * 2 + boost).min(64);
            (cores, tunnels, true, 1)
        }
        PerfMode::Latency => {
            let workers = cores.min(4);
            let tunnels = (cores / 2).max(1);
            (workers, tunnels, false, cfg.mux.multiplex_flush_ms.max(1))
        }
        PerfMode::Balanced => {
            let tunnels = (cores + boost).clamp(1, 32);
            (
                cores,
                tunnels,
                cfg.mux.enable_multiplex,
                cfg.mux.multiplex_flush_ms.max(1),
            )
        }
    };

    // Channel capacities scale with RAM, bounded.
    let ram_factor = (hw.ram_mib / 512).clamp(1, 16) as usize;
    let channel_capacity = (256 * ram_factor).clamp(256, 8192);
    let io_channel_capacity = (512 * ram_factor).clamp(512, 16384);

    ResolvedPlan {
        worker_threads: worker_threads.max(1),
        tunnel_count: tunnel_count.max(1),
        channel_capacity,
        io_channel_capacity,
        mux_enabled,
        mux_flush_ms,
    }
}

fn read_mem_total_mib() -> Option<u64> {
    let text = fs::read_to_string("/proc/meminfo").ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb / 1024);
        }
    }
    None
}

fn read_nic_speed_mbps(interface: &str) -> Option<u64> {
    if interface.is_empty() {
        return None;
    }
    let path = format!("/sys/class/net/{interface}/speed");
    let text = fs::read_to_string(path).ok()?;
    // Can be -1 for virtual/unknown devices.
    text.trim()
        .parse::<i64>()
        .ok()
        .filter(|v| *v > 0)
        .map(|v| v as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_mode(mode: PerfMode, auto: bool) -> Config {
        let mut c = Config::default();
        c.perf.auto_tune = auto;
        c.perf.perf_mode = mode;
        c
    }

    #[test]
    fn throughput_uses_all_cores_and_boost() {
        let hw = HwInfo {
            cores: 8,
            ram_mib: 8192,
            nic_mbps: 10_000,
        };
        let p = plan(&cfg_mode(PerfMode::Throughput, true), hw);
        assert_eq!(p.worker_threads, 8);
        assert_eq!(p.tunnel_count, 8 * 2 + 4); // +4 for 10G
        assert!(p.mux_enabled);
        assert_eq!(p.mux_flush_ms, 1);
    }

    #[test]
    fn latency_caps_workers_and_disables_mux() {
        let hw = HwInfo {
            cores: 16,
            ram_mib: 4096,
            nic_mbps: 1000,
        };
        let p = plan(&cfg_mode(PerfMode::Latency, true), hw);
        assert_eq!(p.worker_threads, 4);
        assert_eq!(p.tunnel_count, 8);
        assert!(!p.mux_enabled);
    }

    #[test]
    fn tunnel_count_capped_at_64() {
        let hw = HwInfo {
            cores: 64,
            ram_mib: 65536,
            nic_mbps: 100_000,
        };
        let p = plan(&cfg_mode(PerfMode::Throughput, true), hw);
        assert_eq!(p.tunnel_count, 64);
    }

    #[test]
    fn manual_respects_config() {
        let mut c = cfg_mode(PerfMode::Balanced, false);
        c.perf.tunnel_count = 3;
        c.perf.runtime_worker_threads = 2;
        let hw = HwInfo {
            cores: 8,
            ram_mib: 8192,
            nic_mbps: 1000,
        };
        let p = plan(&c, hw);
        assert_eq!(p.tunnel_count, 3);
        assert_eq!(p.worker_threads, 2);
    }

    #[test]
    fn nic_boost_tiers() {
        assert_eq!(nic_boost(100), 0);
        assert_eq!(nic_boost(1000), 1);
        assert_eq!(nic_boost(2500), 2);
        assert_eq!(nic_boost(5000), 3);
        assert_eq!(nic_boost(10_000), 4);
    }
}
