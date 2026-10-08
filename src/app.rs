//! Application bootstrap shared by the three binaries (`freespoof`,
//! `freespoof-client`, `freespoof-server`). Keeps the entry points thin.

use std::path::Path;

use crate::config::{Config, Role};
use crate::error::Result;
use crate::session::Engine;

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

/// Initialize logging, print the banner, and run the engine until shutdown.
pub async fn run(cfg: Config) -> Result<()> {
    crate::log::init(&cfg.log_level, cfg.observability.json_logs);
    crate::log::banner(&cfg);
    Engine::new(cfg).run().await
}
