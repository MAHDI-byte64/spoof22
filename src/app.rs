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

    let pin = cfg.perf.cpu_pinning;
    let pin_counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(plan.worker_threads.max(1))
        .enable_all()
        .thread_name("freespoof-worker")
        .on_thread_start(move || {
            // NUMA-aware / cache-friendly placement: pin each worker to a core.
            if pin {
                let core = pin_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tune::pin_current_thread(core);
            }
        })
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

/// Result of the pairing helper.
pub struct Pairing {
    /// The generated client config (TOML).
    pub client_toml: String,
    /// base64 share-link encoding of the client config.
    pub share_link: String,
    /// The client's new public key (hex) to add to the server's allowed_peers.
    pub client_public_hex: String,
}

/// Generate a client config from a server config file.
///
/// Mirrors the addressing (swaps real/peer and tun ips), copies the agreement
/// fields (transports, ports, psk, aead, obfuscation), generates a fresh client
/// keypair, and pins the server's static public key. The caller must add the
/// returned client public key to the server's `peer_public_key` /
/// `spoof.allowed_peers`.
pub fn generate_client_config(server_config: &Path) -> Result<Pairing> {
    use base64::Engine as _;
    use std::net::SocketAddrV4;

    let server = Config::load(server_config)?;
    if server.crypto.static_public_key.trim().is_empty() {
        return Err(crate::error::Error::config(
            "server config has no crypto.static_public_key; run `freespoof genkey` and fill it in",
        ));
    }

    let kp = crate::crypto::generate_static_keypair()?;
    let client_pub_hex = {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(kp.public_b64.trim())
            .map_err(|e| crate::error::Error::config(format!("decode client pub: {e}")))?;
        hex::encode(raw)
    };

    let mut client = server.clone();
    client.role = Role::Client;

    // Mirror addressing.
    std::mem::swap(&mut client.spoof.real_ip, &mut client.spoof.peer_real_ip);
    std::mem::swap(
        &mut client.spoof.spoofed_ip,
        &mut client.spoof.peer_spoofed_ip,
    );
    std::mem::swap(&mut client.tun.tun_ip, &mut client.tun.tun_peer_ip);

    // Keys: fresh client identity, pin the server's public key.
    client.crypto.static_private_key = kp.private_b64;
    client.crypto.static_public_key = kp.public_b64;
    client.crypto.peer_public_key = server.crypto.static_public_key.clone();
    client.spoof.allowed_peers.clear();

    // The client connects to the server's real address.
    client.transport.server_endpoints = vec![SocketAddrV4::new(
        server.spoof.real_ip,
        server.transport.data_port,
    )];

    let client_toml = client.to_toml()?;
    let share_link = format!(
        "freespoof://{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(client_toml.as_bytes())
    );

    Ok(Pairing {
        client_toml,
        share_link,
        client_public_hex: client_pub_hex,
    })
}
