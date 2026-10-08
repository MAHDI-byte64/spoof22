//! Colored, aligned, structured logging + a startup banner.
//!
//! Uses `tracing` + `tracing-subscriber`. The level keyword comes from config
//! or `--log-level`; an optional JSON layer can run alongside the pretty logs
//! for machine consumption.

use std::io::IsTerminal;

use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, Layer};

use crate::config::Config;

// ANSI colors for the banner (kept tiny; tracing handles per-line coloring).
const C_RESET: &str = "\x1b[0m";
const C_BOLD: &str = "\x1b[1m";
const C_CYAN: &str = "\x1b[36m";
const C_MAGENTA: &str = "\x1b[35m";
const C_GREEN: &str = "\x1b[32m";
const C_YELLOW: &str = "\x1b[33m";
const C_GREY: &str = "\x1b[90m";

/// Initialize the global logging subscriber.
///
/// `level` is a keyword (trace|debug|info|warn|error). `json` adds a JSON
/// layer. Safe to call once at startup. The `RUST_LOG` env var, when set,
/// overrides `level` (standard tracing behavior).
pub fn init(level: &str, json: bool) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("freespoof={level},warn")));

    let use_ansi = std::io::stdout().is_terminal();

    let pretty = tracing_subscriber::fmt::layer()
        .with_ansi(use_ansi)
        .with_target(true)
        .with_level(true)
        .compact();

    // Build the subscriber. The JSON layer, when requested, writes to stderr so
    // it can be redirected independently of the pretty stdout stream.
    let json_layer = if json {
        Some(
            tracing_subscriber::fmt::layer()
                .json()
                .with_current_span(true)
                .with_writer(std::io::stderr)
                .with_filter(EnvFilter::new("freespoof=debug,warn")),
        )
    } else {
        None
    };

    let registry = tracing_subscriber::registry().with(pretty.with_filter(filter));

    // `.with(None)` is a no-op layer, so this composes cleanly either way.
    if let Err(e) = registry.with(json_layer).try_init() {
        // Already initialized (e.g. tests) — not fatal.
        eprintln!("logging init skipped: {e}");
    }
}

/// Print the startup banner with the key operational parameters.
pub fn banner(cfg: &Config) {
    let role = match cfg.role {
        crate::config::Role::Client => "CLIENT",
        crate::config::Role::Server => "SERVER",
    };
    let spoof = if cfg.spoofing_active() {
        "ON"
    } else {
        "OFF (real addresses)"
    };
    let up = cfg.transport.uplink_protocol.as_str();
    let down = cfg.transport.downlink_protocol.as_str();
    let pq = if cfg.crypto.pq_hybrid {
        "X25519+ML-KEM (hybrid)"
    } else {
        "X25519"
    };

    // The banner is intentionally plain ASCII art so it renders in any locale.
    println!(
        "{C_CYAN}{C_BOLD}\
\n  ███████╗██████╗ ███████╗███████╗███████╗██████╗  ██████╗  ██████╗ ███████╗\
\n  ██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔════╝\
\n  █████╗  ██████╔╝█████╗  █████╗  ███████╗██████╔╝██║   ██║██║   ██║█████╗  \
\n  ██╔══╝  ██╔══██╗██╔══╝  ██╔══╝  ╚════██║██╔═══╝ ██║   ██║██║   ██║██╔══╝  \
\n  ██║     ██║  ██║███████╗███████╗███████║██║     ╚██████╔╝╚██████╔╝██║     \
\n  ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝     {C_RESET}"
    );
    println!(
        "  {C_GREY}authorized anti-censorship tunnel · point-to-point · IPv4{C_RESET}  {C_MAGENTA}v{}{C_RESET}",
        crate::VERSION
    );
    println!(
        "  {C_GREY}────────────────────────────────────────────────────────────────────{C_RESET}"
    );
    row("role", &format!("{C_GREEN}{role}{C_RESET}"));
    row(
        "transports",
        &format!("uplink={C_YELLOW}{up}{C_RESET}  downlink={C_YELLOW}{down}{C_RESET}"),
    );
    row("spoofing", spoof);
    row("handshake", &format!("Noise_IK · {pq}"));
    row(
        "addresses",
        &format!(
            "real {} ↔ peer {}   (forged src {})",
            cfg.spoof.real_ip, cfg.spoof.peer_real_ip, cfg.spoof.spoofed_ip
        ),
    );
    row(
        "tun",
        &format!(
            "{} {} ↔ {}",
            cfg.tun.tun_name, cfg.tun.tun_ip, cfg.tun.tun_peer_ip
        ),
    );
    row(
        "mtu",
        &format!("engine={} tun={}", cfg.perf.mtu, cfg.tun.tun_mtu),
    );
    println!(
        "  {C_GREY}────────────────────────────────────────────────────────────────────{C_RESET}"
    );
}

fn row(key: &str, val: &str) {
    println!("  {C_BOLD}{key:<12}{C_RESET} {val}");
}
