//! Unified `freespoof` binary: role is selected by the config file (or the
//! `--role` override). Also exposes the `genkey` helper.
//!
//! CLI help text is Persian (per the spec); option keywords stay English.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use freespoof::config::Role;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// freespoof — تونل ضدسانسور دوطرفه با جعل IP برای لینک نقطه‌به‌نقطه‌ی مجاز.
#[derive(Parser)]
#[command(
    name = "freespoof",
    version,
    about = "تونل ضدسانسور دوطرفه (IP spoofing + مقاوم در برابر DPI) — فقط برای لینک نقطه‌به‌نقطه‌ای که هر دو سرش را خودتان کنترل می‌کنید.",
    long_about = "freespoof یک تونل رمزنگاری‌شده‌ی نقطه‌به‌نقطه است که منبع بسته‌های IP را جعل می‌کند و ترافیک را در برابر DPI مقاوم می‌سازد. نقش (client/server) از روی فایل کانفیگ یا سوییچ --role انتخاب می‌شود."
)]
struct Cli {
    /// مسیر فایل کانفیگ TOML
    #[arg(short, long, default_value = "/etc/freespoof/config.toml")]
    config: PathBuf,

    /// بازنویسی نقش تعریف‌شده در کانفیگ (client یا server)
    #[arg(long, value_enum)]
    role: Option<RoleArg>,

    /// بازنویسی سطح لاگ (trace|debug|info|warn|error)
    #[arg(long)]
    log_level: Option<String>,

    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Clone, ValueEnum)]
enum RoleArg {
    Client,
    Server,
}

impl From<RoleArg> for Role {
    fn from(r: RoleArg) -> Role {
        match r {
            RoleArg::Client => Role::Client,
            RoleArg::Server => Role::Server,
        }
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// تولید یک جفت‌کلید استاتیک Noise (X25519) جدید و چاپ آن به صورت base64
    Genkey,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Cmd::Genkey) => {
            let kp = freespoof::crypto::generate_static_keypair()
                .context("generating static keypair")?;
            println!("# کلید خصوصی را در static_private_key همین طرف قرار دهید،");
            println!("# و کلید عمومی را در peer_public_key طرف مقابل بگذارید.");
            println!("static_private_key = \"{}\"", kp.private_b64);
            println!("static_public_key  = \"{}\"", kp.public_b64);
            Ok(())
        }
        None => {
            let cfg =
                freespoof::app::load_config(&cli.config, cli.role.map(Into::into), cli.log_level)
                    .context("loading configuration")?;
            freespoof::app::run(cfg).await.map_err(anyhow::Error::from)
        }
    }
}
