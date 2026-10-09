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
    /// ساخت کانفیگ کلاینت از روی کانفیگ سرور + تولید لینک اشتراک base64
    Pair {
        /// مسیر کانفیگ سرور
        #[arg(long)]
        server_config: PathBuf,
        /// مسیر خروجی کانفیگ کلاینت (پیش‌فرض: چاپ در stdout)
        #[arg(long)]
        client_out: Option<PathBuf>,
    },
    /// ارسال یک فرمان مدیریتی به نمونه‌ی در حال اجرا از طریق سوکت کنترل
    Ctl {
        /// مسیر سوکت کنترل یونیکس
        #[arg(long, default_value = "/run/freespoof.sock")]
        socket: String,
        /// فرمان: stats | status | rotate-key | switch-transport <kind> | reload
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
}

fn main() -> Result<()> {
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
        Some(Cmd::Pair {
            server_config,
            client_out,
        }) => {
            let pairing = freespoof::app::generate_client_config(&server_config)
                .context("generating client config")?;
            if let Some(path) = client_out {
                std::fs::write(&path, &pairing.client_toml).context("writing client config")?;
                eprintln!("# کانفیگ کلاینت در {} نوشته شد", path.display());
            } else {
                println!("{}", pairing.client_toml);
            }
            eprintln!("\n# لینک اشتراک (این را به کلاینت بدهید):");
            eprintln!("{}", pairing.share_link);
            eprintln!("\n# این کلید عمومی کلاینت را به peer_public_key یا spoof.allowed_peers سرور اضافه کنید:");
            eprintln!("{}", pairing.client_public_hex);
            Ok(())
        }
        Some(Cmd::Ctl { socket, command }) => {
            let cmd = command.join(" ");
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("building runtime")?;
            let reply = rt
                .block_on(freespoof::control::client(&socket, &cmd))
                .context("control request")?;
            print!("{reply}");
            Ok(())
        }
        None => {
            let cfg =
                freespoof::app::load_config(&cli.config, cli.role.map(Into::into), cli.log_level)
                    .context("loading configuration")?;
            freespoof::app::bootstrap(cfg).map_err(anyhow::Error::from)
        }
    }
}
