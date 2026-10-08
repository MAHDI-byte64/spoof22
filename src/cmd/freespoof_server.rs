//! `freespoof-server`: role-locked server entry point over the same library.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use freespoof::config::Role;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// freespoof-server — اجرای تونل در نقش سرور.
#[derive(Parser)]
#[command(
    name = "freespoof-server",
    version,
    about = "اجرای freespoof در نقش server (نقش روی server قفل شده است)."
)]
struct Cli {
    /// مسیر فایل کانفیگ TOML
    #[arg(short, long, default_value = "/etc/freespoof/server.toml")]
    config: PathBuf,

    /// بازنویسی سطح لاگ (trace|debug|info|warn|error)
    #[arg(long)]
    log_level: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = freespoof::app::load_config(&cli.config, Some(Role::Server), cli.log_level)
        .context("loading server configuration")?;
    freespoof::app::run(cfg).await.map_err(anyhow::Error::from)
}
