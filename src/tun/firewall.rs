//! Firewall, NAT, kill switch, routing and the sysctls the data plane needs.
//!
//! Auto-detects `nftables` vs `iptables` and applies, on startup:
//!
//! * **sysctls** — `net.ipv4.ip_forward=1`, `rp_filter=0` on `all` and the
//!   physical NIC (required so spoofed-source packets are accepted), plus
//!   `icmp_echo_ignore_all=1` (ICMP transport) and an `OUTPUT` RST drop for the
//!   data port (synthetic-TCP transport) so the kernel does not fight the
//!   userspace transports;
//! * **NAT** — masquerade tunnelled traffic, and DNAT the configured
//!   `forward_ports` to `tun_peer_ip`;
//! * **kill switch** — drop traffic that would leave over the physical NIC
//!   instead of the tunnel, except the encrypted link to the peer, so a dropped
//!   tunnel never leaks;
//! * **routing** — full-tunnel default route or split-tunnel CIDRs.
//!
//! Every applied rule and changed sysctl is recorded and reverted on
//! [`Firewall::teardown`], which also runs from `Drop` as a best-effort net.

use std::net::Ipv4Addr;

use tokio::process::Command;
use tracing::{debug, info, warn};

use crate::config::{Config, RoutingMode, TransportKind};
use crate::error::Result;

/// Which firewall backend is in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Backend {
    Nftables,
    Iptables,
    /// Neither tool found — NAT/kill-switch are skipped (logged).
    None,
}

/// Records what was applied so it can be reverted cleanly.
pub struct Firewall {
    backend: Backend,
    iface: String,
    /// iptables rule argument-vectors to delete on teardown (`-D` form).
    iptables_rules: Vec<Vec<String>>,
    /// `true` once our nft table was created.
    nft_table: bool,
    /// (key, original value) sysctls to restore.
    sysctls: Vec<(String, String)>,
    /// `ip` argument-vectors to run on teardown to restore routing.
    route_restore: Vec<Vec<String>>,
    /// Set once we overwrote /etc/resolv.conf: the original bytes to put back,
    /// or `None` if there was no original file (restore = delete).
    resolv_backup: Option<Option<Vec<u8>>>,
    torn_down: bool,
}

impl Firewall {
    /// Apply sysctls, NAT, kill switch and routing for this config.
    pub async fn setup(cfg: &Config) -> Result<Firewall> {
        let backend = detect_backend().await;
        let mut fw = Firewall {
            backend,
            iface: cfg.transport.interface.clone(),
            iptables_rules: Vec::new(),
            nft_table: false,
            sysctls: Vec::new(),
            route_restore: Vec::new(),
            resolv_backup: None,
            torn_down: false,
        };

        fw.apply_sysctls(cfg).await;
        if let Err(e) = fw.apply_nat(cfg).await {
            warn!(err = %e, "NAT setup incomplete (continuing in degraded mode)");
        }
        if cfg.tun.kill_switch {
            if let Err(e) = fw.apply_kill_switch(cfg).await {
                warn!(err = %e, "kill switch setup failed");
            }
        }
        if let Err(e) = fw.apply_routing(cfg).await {
            warn!(err = %e, "routing setup incomplete");
        }
        info!(backend = ?fw.backend, "firewall/NAT/routing applied");
        Ok(fw)
    }

    /// Revert everything applied. Idempotent.
    pub async fn teardown(&mut self) {
        if self.torn_down {
            return;
        }
        self.torn_down = true;

        // Reverse iptables rules (delete in reverse insertion order).
        for rule in self.iptables_rules.iter().rev() {
            let mut args = vec!["-D".to_string()];
            // Each stored rule begins with the table-and-chain spec already as
            // `-t <table> <chain> ...` or `<chain> ...`; we replace the leading
            // `-A` marker by deleting with the same spec.
            args.extend(rule.iter().cloned());
            let _ = run("iptables", &args).await;
        }
        if self.nft_table {
            let _ = run("nft", &["delete", "table", "ip", "freespoof"]).await;
        }
        // Restore routing (default route / split CIDRs).
        for rule in self.route_restore.iter().rev() {
            let _ = run("ip", rule).await;
        }
        // Restore /etc/resolv.conf (put the original back, or clear ours). The
        // write/remove needs filesystem-write privilege at teardown: it works
        // when we still run privileged, but the in-process privilege drop
        // (hardening.run_as_user) removes DAC write to the root-owned file, so
        // this is best-effort and surfaced on failure rather than silently lost.
        if let Some(orig) = &self.resolv_backup {
            let res = match orig {
                Some(bytes) => std::fs::write("/etc/resolv.conf", bytes),
                // Prefer unlinking our file; if that is blocked (e.g. Landlock
                // grants no RemoveFile on /etc) fall back to a neutral
                // placeholder so tunnel resolvers are never left behind.
                None => std::fs::remove_file("/etc/resolv.conf")
                    .or_else(|_| std::fs::write("/etc/resolv.conf", b"# cleared by freespoof\n")),
            };
            if let Err(e) = res {
                warn!(err = %e, "could not restore /etc/resolv.conf (DNS may still point at tunnel resolvers; teardown needs filesystem-write privilege)");
            }
        }
        // Restore sysctls.
        for (k, v) in self.sysctls.iter().rev() {
            let _ = run("sysctl", &["-w", &format!("{k}={v}")]).await;
        }
        info!("firewall/NAT/routing reverted");
    }

    async fn apply_sysctls(&mut self, cfg: &Config) {
        let iface = &cfg.transport.interface;
        let mut wanted = vec![
            ("net.ipv4.ip_forward".to_string(), "1".to_string()),
            ("net.ipv4.conf.all.rp_filter".to_string(), "0".to_string()),
            (format!("net.ipv4.conf.{iface}.rp_filter"), "0".to_string()),
        ];
        // ICMP transport: stop the kernel answering echo requests itself.
        if cfg.transport.uplink_protocol == TransportKind::Icmp
            || cfg.transport.downlink_protocol == TransportKind::Icmp
        {
            wanted.push(("net.ipv4.icmp_echo_ignore_all".to_string(), "1".to_string()));
        }
        for (k, v) in wanted {
            if let Some(orig) = get_sysctl(&k).await {
                if orig != v && run("sysctl", &["-w", &format!("{k}={v}")]).await.is_ok() {
                    self.sysctls.push((k, orig));
                }
            }
        }
    }

    async fn apply_nat(&mut self, cfg: &Config) -> Result<()> {
        if self.backend == Backend::None {
            return Ok(());
        }
        let peer = cfg.tun.tun_peer_ip;
        let iface = self.iface.clone();

        // Masquerade tunnelled traffic out the physical NIC.
        self.add_iptables(&["-t", "nat", "POSTROUTING", "-o", &iface, "-j", "MASQUERADE"])
            .await;

        // Allow forwarding to/from the TUN.
        self.add_iptables(&["FORWARD", "-i", &cfg.tun.tun_name, "-j", "ACCEPT"])
            .await;
        self.add_iptables(&["FORWARD", "-o", &cfg.tun.tun_name, "-j", "ACCEPT"])
            .await;

        // Port forwarding: DNAT configured ports to the peer's TUN address.
        for port in &cfg.tun.forward_ports {
            for proto in ["tcp", "udp"] {
                self.add_iptables(&[
                    "-t",
                    "nat",
                    "PREROUTING",
                    "-p",
                    proto,
                    "--dport",
                    &port.to_string(),
                    "-j",
                    "DNAT",
                    "--to-destination",
                    &peer.to_string(),
                ])
                .await;
            }
        }
        // TCP transport: drop outbound RSTs for the data port so the kernel
        // does not reset our synthetic segments.
        if cfg.transport.uplink_protocol == TransportKind::Tcp
            || cfg.transport.downlink_protocol == TransportKind::Tcp
        {
            self.add_iptables(&[
                "OUTPUT",
                "-p",
                "tcp",
                "--sport",
                &cfg.transport.data_port.to_string(),
                "--tcp-flags",
                "RST",
                "RST",
                "-j",
                "DROP",
            ])
            .await;
        }
        Ok(())
    }

    async fn apply_kill_switch(&mut self, cfg: &Config) -> Result<()> {
        if self.backend == Backend::None {
            return Ok(());
        }
        let peer = cfg.spoof.peer_real_ip.to_string();
        let iface = self.iface.clone();
        // Allow the encrypted link to the peer and anything over the TUN;
        // drop everything else leaving the physical NIC (prevents leaks).
        self.add_iptables(&["OUTPUT", "-o", &cfg.tun.tun_name, "-j", "ACCEPT"])
            .await;
        self.add_iptables(&["OUTPUT", "-o", &iface, "-d", &peer, "-j", "ACCEPT"])
            .await;
        // Permit loopback + established. NOTE: the ESTABLISHED,RELATED accept is
        // a deliberate trade-off — it keeps the operator's own pre-existing
        // connections (e.g. the SSH session managing this host) from being cut
        // when the tunnel drops. The cost is that flows already established over
        // the physical NIC before the tunnel came up can keep egressing in the
        // clear. Operators who need a strict no-exceptions kill switch should
        // drop this rule (and accept that it may sever their control channel).
        self.add_iptables(&["OUTPUT", "-o", "lo", "-j", "ACCEPT"])
            .await;
        self.add_iptables(&[
            "OUTPUT",
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ])
        .await;
        // Default drop on the physical NIC for everything else.
        self.add_iptables(&["OUTPUT", "-o", &iface, "-j", "DROP"])
            .await;
        Ok(())
    }

    async fn apply_routing(&mut self, cfg: &Config) -> Result<()> {
        match cfg.tun.routing_mode {
            RoutingMode::Full => {
                // Full tunnel: default via the TUN. Capture the current default
                // route first so teardown can put it back (otherwise the host is
                // left with no working default route once the TUN disappears).
                match ip_default_route().await {
                    Some(orig) => {
                        let mut restore = vec!["route".to_string(), "replace".to_string()];
                        restore.extend(orig.split_whitespace().map(|s| s.to_string()));
                        self.route_restore.push(restore);
                    }
                    None => self.route_restore.push(vec![
                        "route".to_string(),
                        "del".to_string(),
                        "default".to_string(),
                        "dev".to_string(),
                        cfg.tun.tun_name.clone(),
                    ]),
                }
                let _ = run(
                    "ip",
                    &["route", "replace", "default", "dev", &cfg.tun.tun_name],
                )
                .await;
            }
            RoutingMode::Split => {
                for cidr in &cfg.tun.split_cidrs {
                    // On teardown, remove the route we added for each CIDR.
                    self.route_restore.push(vec![
                        "route".to_string(),
                        "del".to_string(),
                        cidr.clone(),
                        "dev".to_string(),
                        cfg.tun.tun_name.clone(),
                    ]);
                    let _ = run("ip", &["route", "replace", cidr, "dev", &cfg.tun.tun_name]).await;
                }
            }
        }
        // DNS leak prevention: push configured resolvers, backing up the
        // original /etc/resolv.conf so teardown restores it (otherwise the host
        // is left pointing at tunnel-only resolvers after exit).
        if !cfg.tun.dns_servers.is_empty() {
            self.resolv_backup = Some(std::fs::read("/etc/resolv.conf").ok());
            push_dns(&cfg.tun.dns_servers);
        }
        Ok(())
    }

    /// Add an iptables rule (via `-A`) and record it for teardown.
    async fn add_iptables(&mut self, spec: &[&str]) {
        if self.backend != Backend::Iptables && self.backend != Backend::Nftables {
            return;
        }
        // We drive iptables (the nft backend provides an iptables-nft shim on
        // modern distros); record the spec for a matching `-D` on teardown.
        let owned: Vec<String> = spec.iter().map(|s| s.to_string()).collect();
        let mut args = vec!["-A".to_string()];
        args.extend(owned.iter().cloned());
        match run("iptables", &args).await {
            Ok(()) => self.iptables_rules.push(owned),
            Err(e) => debug!(err = %e, rule = ?spec, "iptables rule failed"),
        }
    }
}

impl Drop for Firewall {
    fn drop(&mut self) {
        if self.torn_down {
            return;
        }
        // Best-effort synchronous cleanup from Drop (e.g. on panic/abort). The
        // async teardown() is preferred and usually already ran.
        for rule in self.iptables_rules.iter().rev() {
            let mut args = vec!["-D".to_string()];
            args.extend(rule.iter().cloned());
            let _ = std::process::Command::new("iptables").args(&args).output();
        }
        if self.nft_table {
            let _ = std::process::Command::new("nft")
                .args(["delete", "table", "ip", "freespoof"])
                .output();
        }
        for rule in self.route_restore.iter().rev() {
            let _ = std::process::Command::new("ip").args(rule).output();
        }
        if let Some(orig) = &self.resolv_backup {
            let _ = match orig {
                Some(bytes) => std::fs::write("/etc/resolv.conf", bytes),
                None => std::fs::remove_file("/etc/resolv.conf")
                    .or_else(|_| std::fs::write("/etc/resolv.conf", b"# cleared by freespoof\n")),
            };
        }
        for (k, v) in self.sysctls.iter().rev() {
            let _ = std::process::Command::new("sysctl")
                .args(["-w", &format!("{k}={v}")])
                .output();
        }
    }
}

/// Detect the available firewall backend.
async fn detect_backend() -> Backend {
    if which("nft").await {
        // iptables-nft usually coexists; prefer driving iptables syntax which
        // the nft shim understands, but note nft is present.
        if which("iptables").await {
            Backend::Iptables
        } else {
            Backend::Nftables
        }
    } else if which("iptables").await {
        Backend::Iptables
    } else {
        warn!("no nftables/iptables found; NAT and kill switch disabled");
        Backend::None
    }
}

async fn which(cmd: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {cmd}"))
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// The current IPv4 default route as a single `ip route` spec line (e.g.
/// "default via 192.168.1.1 dev eth0 ..."), or `None` if there is none.
async fn ip_default_route() -> Option<String> {
    let out = Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
}

async fn get_sysctl(key: &str) -> Option<String> {
    let out = Command::new("sysctl")
        .args(["-n", key])
        .output()
        .await
        .ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        None
    }
}

/// Push DNS resolvers by rewriting /etc/resolv.conf (best effort; the manager
/// documents DoH/DoT alternatives).
fn push_dns(servers: &[Ipv4Addr]) {
    let mut body = String::from("# written by freespoof\n");
    for s in servers {
        body.push_str(&format!("nameserver {s}\n"));
    }
    if let Err(e) = std::fs::write("/etc/resolv.conf", body) {
        debug!(err = %e, "could not push DNS (resolv.conf)");
    }
}

async fn run<S: AsRef<str>>(cmd: &str, args: &[S]) -> Result<()> {
    let out = Command::new(cmd)
        .args(args.iter().map(|a| a.as_ref()))
        .output()
        .await
        .map_err(|e| crate::error::Error::Tun(format!("spawn {cmd}: {e}")))?;
    if out.status.success() {
        Ok(())
    } else {
        let joined = args
            .iter()
            .map(|a| a.as_ref())
            .collect::<Vec<_>>()
            .join(" ");
        Err(crate::error::Error::Tun(format!(
            "{cmd} {joined}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }
}
