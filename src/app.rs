//! Application bootstrap shared by the three binaries (`freespoof`,
//! `freespoof-client`, `freespoof-server`). Keeps the entry points thin.
//!
//! The Tokio runtime is built *here* (not via `#[tokio::main]`) so the worker
//! thread count comes from the hardware auto-tuner.

use std::path::Path;

use crate::config::{Config, Role};
use crate::error::{Error, Result};
use crate::session::Engine;
use crate::tune::{self, HwInfo};

/// Load a config file and apply CLI overrides (role, log level).
pub fn load_config(
    path: &Path,
    role_override: Option<Role>,
    log_override: Option<String>,
) -> Result<Config> {
    let mut cfg = Config::load(path)?;
    if let Some(r) = role_override {
        cfg.role = r;
    }
    if let Some(l) = log_override {
        cfg.log_level = l;
    }
    Ok(cfg)
}

/// Detect hardware, resolve the runtime plan, build the Tokio runtime with the
/// tuned worker-thread count, and run the engine to completion. This is the
/// synchronous entry point the binaries call.
pub fn bootstrap(cfg: Config) -> Result<()> {
    let hw = HwInfo::detect(&cfg.transport.interface);
    let plan = tune::plan(&cfg, hw);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(plan.worker_threads.max(1))
        .enable_all()
        .thread_name("freespoof-worker")
        .build()
        .map_err(Error::from)?;

    rt.block_on(async move {
        crate::log::init(&cfg.log_level, cfg.observability.json_logs);
        crate::log::banner(&cfg);
        tracing::info!(
            cores = hw.cores,
            ram_mib = hw.ram_mib,
            nic_mbps = hw.nic_mbps,
            worker_threads = plan.worker_threads,
            tunnel_count = plan.tunnel_count,
            perf_mode = ?cfg.perf.perf_mode,
            "auto-tune plan resolved"
        );
        Engine::new(cfg).run().await
    })
}

/// Async variant retained for tests / embedding (uses the ambient runtime).
pub async fn run(cfg: Config) -> Result<()> {
    crate::log::init(&cfg.log_level, cfg.observability.json_logs);
    crate::log::banner(&cfg);
    Engine::new(cfg).run().await
}
