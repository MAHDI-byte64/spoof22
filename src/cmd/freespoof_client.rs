//! `freespoof-client`: role-locked client entry point over the same library.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use freespoof::config::Role;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// freespoof-client — اجرای تونل در نقش کلاینت.
#[derive(Parser)]
#[command(
    name = "freespoof-client",
    version,
    about = "اجرای freespoof در نقش client (نقش روی client قفل شده است)."
)]
struct Cli {
    /// مسیر فایل کانفیگ TOML
    #[arg(short, long, default_value = "/etc/freespoof/client.toml")]
    config: PathBuf,

    /// بازنویسی سطح لاگ (trace|debug|info|warn|error)
    #[arg(long)]
    log_level: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = freespoof::app::load_config(&cli.config, Some(Role::Client), cli.log_level)
        .context("loading client configuration")?;
    freespoof::app::bootstrap(cfg).map_err(anyhow::Error::from)
}
