//! Session lifecycle: handshake, then the bidirectional data plane.
//!
//! The data plane is a small pipeline:
//!
//! ```text
//!  egress:  TUN read ──▶ [mux batch] ──▶ seal (AEAD) ──▶ [FEC shard+parity] ──▶ transport
//!  ingress: transport ──▶ [FEC reconstruct] ──▶ open (AEAD) ──▶ [mux debatch] ──▶ TUN write
//! ```
//!
//! Multiplexing and FEC apply only to the datagram transports
//! (udp/icmp/proto58/ipip); for tcp/quic they are bypassed. Separate
//! `uplink`/`downlink` transports are supported: we send on the uplink and
//! receive on the downlink (they are the same object when equal).
//!
//! Transport racing, failover, endpoint/port hopping, migration and
//! auto-reconnect are layered on in the session-lifecycle milestone.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tracing::{debug, info, warn};

use crate::config::{Config, FecMode, Role, TransportKind};
use crate::crypto::{self, ReplayWindow, SessionCrypto};
use crate::error::{Error, Result};
use crate::fec::{FecDecoder, FecEncoder};
use crate::metrics::{drop_reason, Metrics};
use crate::mux::{self, BatchAccumulator};
use crate::obfs::{self, Obfs};
use crate::reliability::{Backoff, Congestion};
use crate::transport::{self, Transport};
use crate::tun::TunDevice;
use crate::wire::{flags, FrameType, Header, HEADER_LEN};

/// Max datagram we will receive from a transport (UDP ceiling).
const RECV_CAP: usize = 65_535;

/// Parameters controlling the data-plane pipeline for a session.
#[derive(Clone, Copy)]
struct PlaneParams {
    mtu: usize,
    mux_enabled: bool,
    mux_max_payload: usize,
    mux_flush: Duration,
    fec_enabled: bool,
    fec_mode: FecMode,
    fec_data_shards: usize,
    fec_parity_shards: usize,
    shard_len: usize,
    fec_max_groups: usize,
    obfs: Obfs,
    keepalive_secs: u64,
    dead_secs: u64,
    migration: bool,
    data_port: u16,
    is_server: bool,
    replay_window: u32,
    /// Number of parallel tunnel streams (from auto-tune or config).
    tunnel_count: usize,
    /// Whether feedback-driven congestion control is active (non-QUIC paths).
    cong_enabled: bool,
    cong_kind: crate::config::CongestionKind,
}

impl PlaneParams {
    fn from_config(cfg: &Config, transport_kind: TransportKind) -> PlaneParams {
        let datagram = transport_kind.supports_mux_fec();
        let mtu = cfg.perf.mtu as usize;
        let mux_max = cfg.mux.multiplex_max_payload.max(mtu);
        // Shard must hold the largest sealed frame + padding + length prefix.
        let max_frame =
            HEADER_LEN + mux_max.max(mtu) + crypto::TAG_LEN + cfg.obfs.packet_padding_max;

        // Resolve the parallel-stream count from the auto-tuner (or config).
        let tunnel_count = {
            let hw = crate::tune::HwInfo::detect(&cfg.transport.interface);
            crate::tune::plan(cfg, hw).tunnel_count.max(1)
        };
        let cong_enabled = datagram
            && !matches!(
                cfg.reliability.congestion,
                crate::config::CongestionKind::None
            );

        PlaneParams {
            mtu,
            mux_enabled: datagram && cfg.mux.enable_multiplex,
            mux_max_payload: cfg.mux.multiplex_max_payload,
            mux_flush: Duration::from_millis(cfg.mux.multiplex_flush_ms.max(1)),
            fec_enabled: datagram && cfg.fec.enable_fec,
            fec_mode: cfg.fec.fec_mode,
            fec_data_shards: cfg.fec.fec_group_size,
            fec_parity_shards: cfg.fec.fec_parity_shards,
            shard_len: max_frame + 16,
            fec_max_groups: 64,
            obfs: Obfs::from_config(cfg),
            keepalive_secs: cfg.reliability.keepalive_secs,
            dead_secs: cfg.reliability.dead_peer_timeout_secs,
            migration: cfg.reliability.enable_migration,
            data_port: cfg.transport.data_port,
            is_server: matches!(cfg.role, Role::Server),
            replay_window: cfg.crypto.replay_window,
            tunnel_count,
            cong_enabled,
            cong_kind: cfg.reliability.congestion,
        }
    }
}

/// Shared liveness state between the data-plane tasks and the supervisor.
#[derive(Clone)]
struct Life {
    /// Wall-clock millis of the last inbound frame.
    last_rx: Arc<std::sync::atomic::AtomicU64>,
    /// Notified once when the session should end (dead peer / fatal error).
    ended: Arc<tokio::sync::Notify>,
}

impl Life {
    fn new() -> Life {
        Life {
            last_rx: Arc::new(std::sync::atomic::AtomicU64::new(unix_millis())),
            ended: Arc::new(tokio::sync::Notify::new()),
        }
    }
    fn mark_rx(&self) {
        self.last_rx
            .store(unix_millis(), std::sync::atomic::Ordering::Relaxed);
    }
    fn last_rx_ms(&self) -> u64 {
        self.last_rx.load(std::sync::atomic::Ordering::Relaxed)
    }
    fn end(&self) {
        self.ended.notify_one();
    }
}

/// Wall-clock milliseconds, used for liveness and the hop schedule.
fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Aborts its tasks when dropped — guarantees data-plane cleanup on shutdown.
struct AbortGuard(Vec<tokio::task::JoinHandle<()>>);
impl Drop for AbortGuard {
    fn drop(&mut self) {
        for h in &self.0 {
            h.abort();
        }
    }
}

/// Control-frame subtypes (first plaintext byte of a sealed `Control` frame).
mod ctrl {
    /// Congestion/loss feedback report.
    pub const STATS: u8 = 1;
}

/// Feedback-driven congestion state shared between a session's sender and
/// receiver tasks. The sender reads [`Cong::pacing_nanos`] (lock-free) each
/// packet; the receiver updates the controller only when a STATS report
/// arrives, so the hot path never contends on the mutex.
#[derive(Clone)]
struct Cong {
    mss: usize,
    /// Data frames we have sent (for the peer's loss estimate of our stream).
    tx_data: Arc<AtomicU64>,
    /// Data frames we have received (reported to the peer in our STATS).
    rx_data: Arc<AtomicU64>,
    /// The peer's latest STATS timestamp, to echo back for an RTT sample.
    last_peer_ts: Arc<AtomicU64>,
    /// Inter-packet pacing for our sender in nanoseconds (0 = unpaced).
    pacing_nanos: Arc<AtomicU64>,
    ctl: Arc<Mutex<Congestion>>,
    fb: Arc<Mutex<Feedback>>,
}

impl Cong {
    fn new(kind: crate::config::CongestionKind, mss: usize) -> Cong {
        Cong {
            mss,
            tx_data: Arc::new(AtomicU64::new(0)),
            rx_data: Arc::new(AtomicU64::new(0)),
            last_peer_ts: Arc::new(AtomicU64::new(0)),
            pacing_nanos: Arc::new(AtomicU64::new(0)),
            ctl: Arc::new(Mutex::new(Congestion::new(kind))),
            fb: Arc::new(Mutex::new(Feedback::default())),
        }
    }
}

/// Previous-sample snapshot for computing per-interval deltas.
#[derive(Default)]
struct Feedback {
    prev_sent: u64,
    prev_recv: u64,
}

/// Shared data-plane state across all parallel tunnel streams of one session.
#[derive(Clone)]
struct Plane {
    params: PlaneParams,
    session: Arc<SessionCrypto>,
    metrics: Metrics,
    life: Life,
    /// Monotonic nonce counter, shared so the nonce never repeats under a key
    /// even across parallel streams.
    tx_counter: Arc<AtomicU64>,
    /// Inbound anti-replay window, shared across receiver streams.
    replay: Arc<Mutex<ReplayWindow>>,
    /// FEC encoder/decoder, serialized across streams when FEC is enabled.
    fec_enc: Option<Arc<Mutex<FecEncoder>>>,
    fec_dec: Option<Arc<Mutex<FecDecoder>>>,
    /// Congestion control, when active.
    cong: Option<Cong>,
}

impl Plane {
    /// Next nonce counter (unique across streams).
    fn next_counter(&self) -> u64 {
        self.tx_counter.fetch_add(1, Ordering::Relaxed)
    }
}

/// Encode a STATS control body: `[subtype | rx_data | my_ts | echo_ts]`.
fn encode_stats(rx_data: u64, my_ts: u64, echo_ts: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + 24);
    v.push(ctrl::STATS);
    v.extend_from_slice(&rx_data.to_be_bytes());
    v.extend_from_slice(&my_ts.to_be_bytes());
    v.extend_from_slice(&echo_ts.to_be_bytes());
    v
}

/// Strictly decode a STATS control body.
fn decode_stats(b: &[u8]) -> Option<(u64, u64, u64)> {
    if b.len() < 25 || b[0] != ctrl::STATS {
        return None;
    }
    let rx = u64::from_be_bytes(b[1..9].try_into().ok()?);
    let my_ts = u64::from_be_bytes(b[9..17].try_into().ok()?);
    let echo = u64::from_be_bytes(b[17..25].try_into().ok()?);
    Some((rx, my_ts, echo))
}

/// The running engine for one endpoint.
pub struct Engine {
    cfg: Config,
}

impl Engine {
    /// Construct an engine from a validated config.
    pub fn new(cfg: Config) -> Engine {
        Engine { cfg }
    }

    /// Run until a shutdown signal (SIGINT/SIGTERM) arrives, reconnecting with
    /// backoff/failover as needed. Sets up the TUN, firewall/NAT/kill-switch,
    /// observability endpoints and (optionally) drops privileges before the
    /// reconnect loop, and tears the firewall down on every exit path.
    pub async fn run(self) -> Result<()> {
        let cfg = Arc::new(self.cfg);
        let role = cfg.role;

        // TUN persists across reconnects (keys change, the device does not).
        let tun = Arc::new(TunDevice::create(&cfg.tun).await?);
        info!(dev = tun.name(), mtu = tun.mtu(), "tun device up");

        // Firewall / NAT / kill switch / routing (needs CAP_NET_ADMIN).
        let mut firewall = crate::tun::Firewall::setup(&cfg).await?;

        // Observability: bind the metrics + control listeners BEFORE dropping
        // privileges (the control socket may live in a root-owned dir).
        let control = crate::control::Control::new(crate::metrics::Metrics::new());
        control.set_status(format!("{:?} starting", role));
        let metrics_listener = if cfg.observability.metrics_addr.is_empty() {
            None
        } else {
            crate::metrics::server::bind(&cfg.observability.metrics_addr)
                .await
                .ok()
        };
        let control_listener = if cfg.observability.control_socket.is_empty() {
            None
        } else {
            crate::control::bind(&cfg.observability.control_socket).ok()
        };

        // Sandbox + privilege drop (retains CAP_NET_RAW/ADMIN for reconnects).
        // Order: Landlock (needs the listeners/TUN already open) → drop uid/gid
        // → seccomp (must not filter the setuid/capset path).
        crate::hardening::landlock_sandbox(cfg.hardening.sandbox);
        if let Err(e) = crate::hardening::drop_privileges(
            &cfg.hardening.run_as_user,
            &cfg.hardening.run_as_group,
        ) {
            warn!(err = %e, "privilege drop failed; continuing with current privileges");
        }
        crate::hardening::seccomp_filter(cfg.hardening.seccomp);

        // Spawn observability servers on the pre-bound listeners.
        if let Some(l) = metrics_listener {
            let m = control.metrics().clone();
            tokio::spawn(crate::metrics::server::serve_listener(l, m));
        }
        if let Some(l) = control_listener {
            tokio::spawn(crate::control::serve_listener(l, control.clone()));
        }

        // Active-probe decoy (server).
        if role == Role::Server && cfg.obfs.decoy_enabled {
            let listen = obfs::decoy::listen_addr(&cfg.obfs.decoy_listen, cfg.spoof.real_ip);
            let target = cfg.obfs.decoy_target.clone();
            tokio::spawn(async move {
                if let Err(e) = obfs::decoy::run(listen, target).await {
                    warn!(err = %e, "decoy reverse proxy exited");
                }
            });
        }

        // SIGHUP → signal a config reload (applied on the next session).
        spawn_sighup(control.clone());

        // Reconnect loop vs. shutdown.
        let result = tokio::select! {
            r = reconnect_loop(cfg.clone(), tun.clone(), control.clone()) => r,
            _ = wait_for_shutdown() => {
                info!("shutdown signal received; draining tunnel");
                Ok(())
            }
        };

        // Always revert firewall/NAT/routing on exit.
        firewall.teardown().await;
        result
    }
}

/// Spawn a task that forwards SIGHUP into a reload request.
fn spawn_sighup(control: crate::control::Control) {
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut hup) = signal(SignalKind::hangup()) {
            while hup.recv().await.is_some() {
                info!("SIGHUP received; requesting reload");
                control.signal_reload();
            }
        }
    });
}

/// Candidate transport pairs to try, in order: the configured uplink/downlink
/// first, then each `failover_order` protocol (used for both directions).
fn candidate_transports(cfg: &Config) -> Vec<(TransportKind, TransportKind)> {
    let mut out = vec![(
        cfg.transport.uplink_protocol,
        cfg.transport.downlink_protocol,
    )];
    for k in &cfg.transport.failover_order {
        let pair = (*k, *k);
        if !out.contains(&pair) {
            out.push(pair);
        }
    }
    out
}

/// Reconnect/failover loop. Returns only when auto-reconnect is off and an
/// attempt fails, or a session ends with auto-reconnect off.
async fn reconnect_loop(
    cfg: Arc<Config>,
    tun: Arc<TunDevice>,
    control: crate::control::Control,
) -> Result<()> {
    let candidates = candidate_transports(&cfg);
    let mut backoff = Backoff::new(
        cfg.reliability.reconnect_backoff_min_ms,
        cfg.reliability.reconnect_backoff_max_ms,
    );
    let mut idx = 0usize;
    let mut first = true;

    loop {
        // A live `switch-transport` override takes precedence over the
        // candidate rotation.
        let (up, down) = match control.desired_transport() {
            Some(k) => (k, k),
            None => candidates[idx % candidates.len()],
        };
        if cfg.transport.transport_racing && candidates.len() > 1 {
            info!(transport = up.as_str(), "racing/trying transport");
        }
        if !first {
            control.metrics().inc_reconnects();
        }
        first = false;

        match connect_and_run(&cfg, tun.clone(), up, down, &control).await {
            Ok(SessionOutcome::Shutdown) => return Ok(()),
            Ok(SessionOutcome::Reconnect) => {
                backoff.reset();
                if !cfg.reliability.auto_reconnect {
                    return Ok(());
                }
                info!("session ended; reconnecting");
            }
            Err(e) => {
                warn!(err = %e, transport = up.as_str(), "session attempt failed");
                if !cfg.reliability.auto_reconnect {
                    return Err(e);
                }
                idx += 1; // failover to the next candidate
            }
        }
        let d = backoff.next_delay();
        debug!(delay_ms = d.as_millis() as u64, "reconnect backoff");
        tokio::time::sleep(d).await;
    }
}

/// How a session finished.
enum SessionOutcome {
    Reconnect,
    Shutdown,
}

/// Build transports for `(up, down)`, perform the handshake (with a racing
/// timeout when enabled), and run the data plane until it ends.
async fn connect_and_run(
    cfg: &Arc<Config>,
    tun: Arc<TunDevice>,
    up: TransportKind,
    down: TransportKind,
    control: &crate::control::Control,
) -> Result<SessionOutcome> {
    let role = cfg.role;
    let send_t = transport::build(up, cfg, role).await?;
    let recv_t: Arc<dyn Transport> = if down == up {
        send_t.clone()
    } else {
        transport::build(down, cfg, role).await?
    };
    info!(
        uplink = up.as_str(),
        downlink = down.as_str(),
        "transports ready"
    );

    let hs_params = crypto::handshake_params(cfg)?;
    // Racing: cap the client handshake so a blocked transport fails over fast.
    let session = match role {
        Role::Client => {
            let fut = client_handshake(&*send_t, &*recv_t, hs_params);
            if cfg.transport.transport_racing {
                match tokio::time::timeout(Duration::from_secs(6), fut).await {
                    Ok(r) => r?,
                    Err(_) => return Err(Error::Session("transport race timed out".into())),
                }
            } else {
                fut.await?
            }
        }
        Role::Server => {
            server_handshake(
                &*send_t,
                &*recv_t,
                hs_params,
                cfg.observability.handshake_rate_limit,
            )
            .await?
        }
    };
    info!(
        session = format_args!("{:#018x}", session.session_id),
        pq = session.pq_active,
        aead = ?session.aead,
        "session established"
    );
    log_overhead(cfg, up);
    control.set_status(format!(
        "{:?} up: {}/{} session={:#018x} pq={}",
        role,
        up.as_str(),
        down.as_str(),
        session.session_id,
        session.pq_active
    ));

    Ok(run_session(
        cfg.clone(),
        tun,
        send_t,
        recv_t,
        Arc::new(session),
        up,
        control.clone(),
    )
    .await)
}

/// Spawn the data-plane tasks + keepalive + hopping, and supervise until the
/// session ends (dead peer / fatal error) or shutdown.
#[allow(clippy::too_many_arguments)]
async fn run_session(
    cfg: Arc<Config>,
    tun: Arc<TunDevice>,
    send_t: Arc<dyn Transport>,
    recv_t: Arc<dyn Transport>,
    session: Arc<SessionCrypto>,
    up: TransportKind,
    control: crate::control::Control,
) -> SessionOutcome {
    let params = PlaneParams::from_config(&cfg, up);
    let life = Life::new();
    let metrics = control.metrics().clone();
    let streams = params.tunnel_count.max(1);
    metrics.set_active_tunnels(streams as u64);

    // Shared FEC enc/dec (serialized across streams) when FEC is enabled.
    let fec_enc = if params.fec_enabled {
        match FecEncoder::new(
            params.fec_mode,
            params.fec_data_shards,
            params.fec_parity_shards,
            params.shard_len,
        ) {
            Ok(e) => Some(Arc::new(Mutex::new(e))),
            Err(e) => {
                warn!(err = %e, "FEC disabled: encoder init failed");
                None
            }
        }
    } else {
        None
    };
    let fec_dec = if params.fec_enabled && fec_enc.is_some() {
        Some(Arc::new(Mutex::new(FecDecoder::new(
            params.fec_mode,
            params.fec_max_groups,
        ))))
    } else {
        None
    };
    let cong = if params.cong_enabled {
        Some(Cong::new(params.cong_kind, params.mtu))
    } else {
        None
    };

    let plane = Plane {
        params,
        session: session.clone(),
        metrics: metrics.clone(),
        life: life.clone(),
        tx_counter: Arc::new(AtomicU64::new(0)),
        replay: Arc::new(Mutex::new(ReplayWindow::new(params.replay_window))),
        fec_enc,
        fec_dec,
        cong,
    };

    info!(streams, cong = plane.cong.is_some(), "data plane starting");

    let mut handles = Vec::new();
    for i in 0..streams {
        handles.push(tokio::spawn(tun_to_net(
            tun.clone(),
            send_t.clone(),
            plane.clone(),
            i,
        )));
        handles.push(tokio::spawn(net_to_tun(
            tun.clone(),
            recv_t.clone(),
            send_t.clone(),
            plane.clone(),
        )));
    }

    // Endpoint hopping (client only): rotate among server endpoints on a
    // wall-clock schedule both sides compute identically.
    if cfg.role == Role::Client
        && cfg.transport.endpoint_hop_interval_secs > 0
        && cfg.transport.server_endpoints.len() > 1
        && send_t.supports_hop()
    {
        let endpoints = cfg.transport.server_endpoints.clone();
        let interval = cfg.transport.endpoint_hop_interval_secs;
        let st = send_t.clone();
        handles.push(tokio::spawn(async move {
            hop_loop(st, endpoints, interval).await;
        }));
    }

    let _guard = AbortGuard(handles);

    let outcome = tokio::select! {
        _ = life.ended.notified() => SessionOutcome::Reconnect,
        _ = control.rekey().notified() => {
            info!("rekey/transport-switch requested; restarting session");
            control.metrics().inc_rekeys();
            SessionOutcome::Reconnect
        }
        _ = control.reload().notified() => {
            info!("reload requested; restarting session");
            SessionOutcome::Reconnect
        }
        _ = wait_for_shutdown() => SessionOutcome::Shutdown,
    };
    control.metrics().set_active_tunnels(0);
    outcome
}

/// Rotate the send transport's endpoint on a time-synchronized schedule.
async fn hop_loop(
    send_t: Arc<dyn Transport>,
    endpoints: Vec<std::net::SocketAddrV4>,
    interval_secs: u64,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs.max(1)));
    loop {
        ticker.tick().await;
        // Index derived from wall-clock so both ends pick the same endpoint.
        let slot = (unix_millis() / 1000 / interval_secs.max(1)) as usize % endpoints.len();
        let ep = endpoints[slot];
        send_t.set_peer(ep);
        debug!(endpoint = %ep, "endpoint hop");
    }
}

/// Log the computed cumulative per-layer overhead so operators can reason
/// about the effective inner payload vs. the path MTU.
fn log_overhead(cfg: &Config, up: TransportKind) {
    let mut overhead = 20 /* outer IPv4 */ + HEADER_LEN + crypto::TAG_LEN;
    overhead += match up {
        TransportKind::Udp | TransportKind::Quic => 8,
        TransportKind::Gre => 4,
        TransportKind::Icmp => 8,
        TransportKind::Tcp => 20,
        TransportKind::Proto58 | TransportKind::Ipip => 0,
    };
    if cfg.fec.enable_fec && up.supports_mux_fec() {
        overhead += crate::fec::FEC_HEADER + 2;
    }
    info!(
        transport = up.as_str(),
        per_packet_overhead = overhead,
        engine_mtu = cfg.perf.mtu,
        effective_inner = cfg.perf.mtu as usize - overhead.min(cfg.perf.mtu as usize),
        "computed tunnel overhead"
    );
}

/// Client side: initiate the handshake with retransmission until the reply.
async fn client_handshake(
    send_t: &dyn Transport,
    recv_t: &dyn Transport,
    params: crypto::HandshakeParams,
) -> Result<SessionCrypto> {
    let (initiator, msg1) = crypto::Initiator::start(params)?;
    let frame = frame_with(FrameType::Handshake1, &msg1);

    let mut buf = vec![0u8; RECV_CAP];
    let mut attempts = 0u32;
    loop {
        send_t.send_frame(&frame).await?;
        attempts += 1;
        match tokio::time::timeout(
            Duration::from_secs(2),
            wait_for_type(recv_t, &mut buf, FrameType::Handshake2),
        )
        .await
        {
            Ok(Ok(body)) => {
                let result = initiator.finish(&body)?;
                return Ok(SessionCrypto::from_handshake(Role::Client, &result));
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                if attempts >= 15 {
                    return Err(Error::Session("handshake timed out (no response)".into()));
                }
                debug!(attempts, "handshake retransmit");
            }
        }
    }
}

/// Server side: wait for a valid Handshake1, rate-limit per source, then
/// authenticate and reply. Unauthenticated/over-limit traffic is dropped
/// silently (fail-closed, anti-probing).
async fn server_handshake(
    send_t: &dyn Transport,
    recv_t: &dyn Transport,
    params: crypto::HandshakeParams,
    rate_limit: u32,
) -> Result<SessionCrypto> {
    let mut buf = vec![0u8; RECV_CAP];
    let mut limiter = HandshakeRateLimiter::new(rate_limit);
    loop {
        let (n, src) = match recv_t.recv_frame_from(&mut buf).await {
            Ok(x) => x,
            Err(e) if e.is_droppable() => continue,
            Err(e) => return Err(e),
        };
        let (h, body) = match Header::decode(&buf[..n]) {
            Ok((h, b)) if h.ftype == FrameType::Handshake1 => (h, b.to_vec()),
            _ => continue, // not a handshake-1 — ignore
        };
        let _ = h;

        // Anti-abuse: rate-limit handshake attempts per source address.
        if let Some(ip) = src {
            if !limiter.allow(ip, unix_millis()) {
                debug!(peer = %ip, "handshake rate-limited");
                continue;
            }
        }

        let responder = crypto::Responder::start(params.clone())?;
        match responder.respond(&body) {
            Ok((msg2, result)) => {
                let reply = frame_with(FrameType::Handshake2, &msg2);
                send_t.send_frame(&reply).await?;
                return Ok(SessionCrypto::from_handshake(Role::Server, &result));
            }
            Err(e) if e.is_droppable() => {
                warn!(err = %e, "dropping unauthenticated/invalid handshake");
                continue;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Per-source sliding-window handshake rate limiter (server anti-abuse).
struct HandshakeRateLimiter {
    max_per_min: u32,
    seen: std::collections::HashMap<std::net::Ipv4Addr, (u64, u32)>,
}

impl HandshakeRateLimiter {
    fn new(max_per_min: u32) -> HandshakeRateLimiter {
        HandshakeRateLimiter {
            max_per_min,
            seen: std::collections::HashMap::new(),
        }
    }

    /// Returns true if an attempt from `ip` at `now_ms` is within the limit.
    fn allow(&mut self, ip: std::net::Ipv4Addr, now_ms: u64) -> bool {
        if self.max_per_min == 0 {
            return true; // disabled
        }
        let window = now_ms / 60_000;
        let entry = self.seen.entry(ip).or_insert((window, 0));
        if entry.0 != window {
            *entry = (window, 0);
        }
        entry.1 += 1;
        // Opportunistically bound the table size.
        if self.seen.len() > 10_000 {
            self.seen.retain(|_, (w, _)| *w == window);
        }
        self.seen
            .get(&ip)
            .map(|(_, c)| *c <= self.max_per_min)
            .unwrap_or(true)
    }
}

/// Receive frames until one of `want` arrives, returning its body (a copy).
async fn wait_for_type(
    transport: &dyn Transport,
    buf: &mut [u8],
    want: FrameType,
) -> Result<Vec<u8>> {
    loop {
        let n = transport.recv_frame(buf).await?;
        let frame = &buf[..n];
        match Header::decode(frame) {
            Ok((h, body)) if h.ftype == want => return Ok(body.to_vec()),
            Ok(_) => continue,
            Err(_) => continue,
        }
    }
}

/// Build a handshake/control frame: header (counter 0) + body.
fn frame_with(ftype: FrameType, body: &[u8]) -> Vec<u8> {
    let header = Header::new(ftype, 0, 0, 0);
    let mut v = Vec::with_capacity(HEADER_LEN + body.len());
    v.extend_from_slice(&header.to_bytes());
    v.extend_from_slice(body);
    v
}

/// Seal a payload into a frame (header authenticated as AAD), applying the
/// padding policy. The `PADDED` flag is set automatically when padding applies.
fn seal_typed(
    session: &SessionCrypto,
    ftype: FrameType,
    counter: u64,
    base_flags: u8,
    payload: &[u8],
    pad: &obfs::PadPolicy,
) -> Result<Vec<u8>> {
    let mut frame_flags = base_flags;
    let padded = pad.apply(payload);
    let plaintext: &[u8] = match &padded {
        Some(p) => {
            frame_flags |= flags::PADDED;
            p
        }
        None => payload,
    };

    let header = Header::new(ftype, frame_flags, session.session_id, counter);
    let hdr = header.to_bytes();
    let mut body = plaintext.to_vec();
    session.tx.seal(counter, &hdr, &mut body)?;
    let mut frame = Vec::with_capacity(HEADER_LEN + body.len());
    frame.extend_from_slice(&hdr);
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Seal a `Data` frame.
fn seal_frame(
    session: &SessionCrypto,
    counter: u64,
    extra_flags: u8,
    payload: &[u8],
    pad: &obfs::PadPolicy,
) -> Result<Vec<u8>> {
    seal_typed(session, FrameType::Data, counter, extra_flags, payload, pad)
}

/// Seal a `Chaff` cover-traffic frame with a random payload.
fn seal_chaff(session: &SessionCrypto, counter: u64, pad: &obfs::PadPolicy) -> Result<Vec<u8>> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let len = rng.gen_range(16..=256);
    let mut body = vec![0u8; len];
    rng.fill(&mut body[..]);
    seal_typed(session, FrameType::Chaff, counter, 0, &body, pad)
}

/// Send a sealed frame, applying FEC (shared encoder) if enabled. The FEC
/// mutex is held only for the synchronous `push`, never across the send.
async fn emit_frame(send_t: &dyn Transport, plane: &Plane, frame: &[u8]) -> Result<()> {
    let datagrams: Vec<Vec<u8>> = if let Some(enc) = &plane.fec_enc {
        let out = { enc.lock().push(frame)? };
        let mut v = Vec::with_capacity(1 + out.parity.len());
        v.push(out.data);
        v.extend(out.parity);
        v
    } else {
        vec![frame.to_vec()]
    };
    if datagrams.len() == 1 {
        send_t.send_frame(&datagrams[0]).await?;
    } else {
        // A data shard plus its parity shards: coalesce into one sendmmsg(2)
        // on transports that support it (default falls back to a send loop).
        let refs: Vec<&[u8]> = datagrams.iter().map(|d| d.as_slice()).collect();
        send_t.send_batch(&refs).await?;
    }
    Ok(())
}

/// Emit a sealed frame after an optional timing-jitter delay, recording metrics.
async fn emit_with_jitter(send_t: &dyn Transport, plane: &Plane, frame: &[u8]) {
    let d = obfs::shaping::jitter(plane.params.obfs.timing_jitter_ms);
    if !d.is_zero() {
        tokio::time::sleep(d).await;
    }
    match emit_frame(send_t, plane, frame).await {
        Ok(()) => {
            plane.metrics.add_tx(frame.len());
            plane
                .metrics
                .add_transport_tx(send_t.kind().as_str(), frame.len());
        }
        Err(e) => warn!(err = %e, "transport send error"),
    }
}

/// Apply congestion pacing before a data send. With N parallel streams each
/// paces at N× the aggregate interval so the combined rate matches the target.
async fn pace(plane: &Plane) {
    if let Some(c) = &plane.cong {
        let ns = c.pacing_nanos.load(Ordering::Relaxed);
        if ns > 0 {
            let per = ns.saturating_mul(plane.params.tunnel_count.max(1) as u64);
            tokio::time::sleep(Duration::from_nanos(per)).await;
        }
    }
}

/// Consume a peer STATS report: feed the congestion controller and update the
/// pacing rate + loss/RTT metrics.
fn handle_control(plane: &Plane, body: &[u8]) {
    let Some((peer_rx, peer_ts, echo)) = decode_stats(body) else {
        return;
    };
    let Some(c) = &plane.cong else {
        return;
    };
    c.last_peer_ts.store(peer_ts, Ordering::Relaxed);

    let now = unix_millis();
    let rtt = if echo != 0 && now >= echo {
        Duration::from_millis(now - echo)
    } else {
        Duration::ZERO
    };
    let sent = c.tx_data.load(Ordering::Relaxed);

    let (sent_delta, recv_delta) = {
        let mut fb = c.fb.lock();
        let sd = sent.saturating_sub(fb.prev_sent);
        let rd = peer_rx.saturating_sub(fb.prev_recv);
        fb.prev_sent = sent;
        fb.prev_recv = peer_rx;
        (sd, rd)
    };
    if sent_delta == 0 {
        return;
    }
    let lost = sent_delta.saturating_sub(recv_delta);
    let eff_rtt = if rtt.is_zero() {
        Duration::from_millis(50)
    } else {
        rtt
    };
    let pacing = {
        let mut ctl = c.ctl.lock();
        ctl.on_feedback(recv_delta, lost, eff_rtt, c.mss);
        ctl.pacing_interval(c.mss)
    };
    c.pacing_nanos
        .store(pacing.as_nanos() as u64, Ordering::Relaxed);
    plane
        .metrics
        .set_loss_ppm(lost.saturating_mul(1_000_000) / sent_delta);
    if !rtt.is_zero() {
        plane.metrics.set_rtt_us(rtt.as_micros() as u64);
    }
}

/// `tun → net`: batch (optional) → pad → encrypt → FEC (optional) → jitter → send,
/// plus optional cover/chaff traffic on idle slots. One task owns the tx
/// counter, the FEC encoder and the mux accumulator (no locking in the hot path).
async fn tun_to_net(
    tun: Arc<TunDevice>,
    send_t: Arc<dyn Transport>,
    plane: Plane,
    stream_idx: usize,
) {
    let p = plane.params;
    let mut inbuf = vec![0u8; p.mtu + 256];
    let overhead = HEADER_LEN + crypto::TAG_LEN;
    // Stream 0 owns the single-instance duties (keepalive, STATS, cover, dead
    // peer) so they are not multiplied by the stream count.
    let is_primary = stream_idx == 0;
    let mut last_tx = unix_millis();

    let mut acc = if p.mux_enabled {
        Some(BatchAccumulator::new(p.mux_max_payload))
    } else {
        None
    };
    let mut mux_ticker = tokio::time::interval(p.mux_flush);
    let cover_on = is_primary && p.obfs.cover_pps > 0;
    let cover_interval = if cover_on {
        Duration::from_nanos(1_000_000_000 / p.obfs.cover_pps.max(1))
    } else {
        Duration::from_secs(3600)
    };
    let mut cover_ticker = tokio::time::interval(cover_interval);
    let ka_poll = if p.keepalive_secs > 0 {
        (p.keepalive_secs / 2).max(1)
    } else {
        5
    };
    let mut ka_ticker = tokio::time::interval(Duration::from_secs(ka_poll));

    loop {
        tokio::select! {
            r = tun.recv(&mut inbuf) => {
                let n = match r { Ok(n) => n, Err(e) => { warn!(err=%e, "tun read error"); continue; } };
                if n == 0 { continue; }
                last_tx = unix_millis();
                if let Some(a) = &mut acc {
                    if a.would_overflow(n) { flush_batch(&send_t, &plane, a).await; }
                    let _ = a.push(&inbuf[..n]);
                    if a.encoded_len() >= p.mux_max_payload { flush_batch(&send_t, &plane, a).await; }
                } else {
                    let counter = plane.next_counter();
                    let pad = p.obfs.frame_pad(overhead);
                    match seal_frame(&plane.session, counter, 0, &inbuf[..n], &pad) {
                        Ok(frame) => {
                            if let Some(c) = &plane.cong { c.tx_data.fetch_add(1, Ordering::Relaxed); }
                            pace(&plane).await;
                            emit_with_jitter(&*send_t, &plane, &frame).await;
                        }
                        Err(e) => warn!(err = %e, "seal failed (rekey needed?)"),
                    }
                }
            }
            _ = mux_ticker.tick(), if acc.is_some() => {
                if let Some(a) = &mut acc {
                    if !a.is_empty() { flush_batch(&send_t, &plane, a).await; }
                }
            }
            _ = cover_ticker.tick(), if cover_on => {
                let counter = plane.next_counter();
                let pad = p.obfs.frame_pad(overhead);
                if let Ok(frame) = seal_chaff(&plane.session, counter, &pad) {
                    emit_with_jitter(&*send_t, &plane, &frame).await;
                    last_tx = unix_millis();
                }
            }
            _ = ka_ticker.tick(), if is_primary => {
                let now = unix_millis();
                // Dead-peer detection → end the session (triggers reconnect).
                if p.dead_secs > 0 && now.saturating_sub(plane.life.last_rx_ms()) >= p.dead_secs * 1000 {
                    warn!("dead peer detected (no traffic); ending session");
                    plane.life.end();
                    return;
                }
                // Congestion STATS report to the peer.
                if let Some(c) = &plane.cong {
                    let counter = plane.next_counter();
                    let body = encode_stats(
                        c.rx_data.load(Ordering::Relaxed),
                        now,
                        c.last_peer_ts.load(Ordering::Relaxed),
                    );
                    let nopad = obfs::PadPolicy { min: 0, max: 0, pad_to: 0 };
                    if let Ok(frame) = seal_typed(&plane.session, FrameType::Control, counter, 0, &body, &nopad) {
                        emit_with_jitter(&*send_t, &plane, &frame).await;
                        last_tx = now;
                    }
                }
                // Heartbeat when idle (also keeps NAT mappings warm).
                if p.keepalive_secs > 0 && now.saturating_sub(last_tx) >= p.keepalive_secs * 1000 {
                    let counter = plane.next_counter();
                    let pad = p.obfs.frame_pad(overhead);
                    if let Ok(frame) = seal_typed(&plane.session, FrameType::Keepalive, counter, 0, &[], &pad) {
                        emit_with_jitter(&*send_t, &plane, &frame).await;
                        last_tx = now;
                    }
                }
            }
        }
    }
}

/// Flush the mux accumulator as one padded, batched Data frame.
async fn flush_batch(send_t: &Arc<dyn Transport>, plane: &Plane, acc: &mut BatchAccumulator) {
    let Some(batch) = acc.take() else { return };
    let counter = plane.next_counter();
    let pad = plane.params.obfs.frame_pad(HEADER_LEN + crypto::TAG_LEN);
    match seal_frame(&plane.session, counter, flags::MUX_BATCH, &batch, &pad) {
        Ok(frame) => {
            if let Some(c) = &plane.cong {
                c.tx_data.fetch_add(1, Ordering::Relaxed);
            }
            pace(plane).await;
            emit_with_jitter(&**send_t, plane, &frame).await;
        }
        Err(e) => warn!(err = %e, "seal batch failed"),
    }
}

/// `net → tun`: FEC reconstruct (optional), decrypt, debatch (if mux), deliver,
/// plus liveness tracking and auth-gated connection migration.
async fn net_to_tun(
    tun: Arc<TunDevice>,
    recv_t: Arc<dyn Transport>,
    send_t: Arc<dyn Transport>,
    plane: Plane,
) {
    let p = plane.params;
    let mut buf = vec![0u8; RECV_CAP];
    let mut cur_peer: Option<std::net::Ipv4Addr> = None;

    loop {
        let (n, src) = match recv_t.recv_frame_from(&mut buf).await {
            Ok(x) => x,
            Err(e) => {
                // A fatal transport error (e.g. QUIC connection closed) ends
                // the session so the manager can reconnect.
                warn!(err = %e, "transport recv error; ending session");
                plane.life.end();
                return;
            }
        };
        if n == 0 {
            continue;
        }
        plane.life.mark_rx();
        plane.metrics.add_rx(n);

        // FEC stage (shared decoder) yields 0+ sealed frames; otherwise the
        // datagram is the sealed frame. The mutex is held only for `push`.
        let sealed_frames: Vec<Vec<u8>> = if let Some(dec) = &plane.fec_dec {
            match dec.lock().push(&buf[..n]) {
                Ok(v) => v,
                Err(_) => {
                    plane.metrics.drop_frame(drop_reason::DECODE);
                    continue; // malformed FEC datagram — drop
                }
            }
        } else {
            vec![buf[..n].to_vec()]
        };

        let mut authed = false;
        for frame in sealed_frames {
            authed |= process_sealed(&tun, &plane, &frame).await;
        }

        // Connection migration: once an authenticated frame arrives from a new
        // source, adopt it as the peer (server side). Never trust the source
        // before authentication.
        if authed && p.migration && p.is_server && send_t.supports_hop() {
            if let Some(ip) = src {
                if cur_peer != Some(ip) {
                    send_t.set_peer(std::net::SocketAddrV4::new(ip, p.data_port));
                    cur_peer = Some(ip);
                    info!(peer = %ip, "connection migrated to new peer source");
                }
            }
        }
    }
}

/// Decode, anti-replay, decrypt, and deliver one sealed frame. Returns `true`
/// if an authenticated `Data` frame was processed (used to gate migration).
async fn process_sealed(tun: &TunDevice, plane: &Plane, frame: &[u8]) -> bool {
    let metrics = &plane.metrics;
    if frame.len() < HEADER_LEN {
        metrics.drop_frame(drop_reason::DECODE);
        return false;
    }
    let (header, _) = match Header::decode(frame) {
        Ok(x) => x,
        Err(_) => {
            metrics.drop_frame(drop_reason::DECODE);
            return false; // malformed — drop silently
        }
    };
    match header.ftype {
        FrameType::Data => {
            if !plane.replay.lock().check_and_update(header.counter) {
                debug!(counter = header.counter, "replay/stale frame dropped");
                metrics.drop_frame(drop_reason::REPLAY);
                return false;
            }
            let aad = &frame[..HEADER_LEN];
            let mut body = frame[HEADER_LEN..].to_vec();
            if plane
                .session
                .rx
                .open(header.counter, aad, &mut body)
                .is_err()
            {
                metrics.drop_frame(drop_reason::AEAD);
                return false; // fail-closed
            }
            // Strip padding if present, then (if batched) split.
            let payload: &[u8] = if header.flags & flags::PADDED != 0 {
                match obfs::padding::strip(&body) {
                    Some(p) => p,
                    None => {
                        metrics.drop_frame(drop_reason::DECODE);
                        return false; // malformed padding trailer — drop
                    }
                }
            } else {
                &body
            };
            if let Some(c) = &plane.cong {
                c.rx_data.fetch_add(1, Ordering::Relaxed);
            }
            if header.flags & flags::MUX_BATCH != 0 {
                if let Ok(pkts) = mux::decode_batch(payload) {
                    for pk in pkts {
                        let _ = tun.send(pk).await;
                    }
                }
            } else {
                let _ = tun.send(payload).await;
            }
            true
        }
        FrameType::Control => {
            if !plane.replay.lock().check_and_update(header.counter) {
                return false;
            }
            let aad = &frame[..HEADER_LEN];
            let mut body = frame[HEADER_LEN..].to_vec();
            if plane
                .session
                .rx
                .open(header.counter, aad, &mut body)
                .is_err()
            {
                metrics.drop_frame(drop_reason::AEAD);
                return false; // fail-closed
            }
            handle_control(plane, &body);
            false
        }
        FrameType::Keepalive => {
            // Liveness only (the arrival already refreshed last_rx in the
            // caller). Migration conservatively requires a decrypted Data frame.
            debug!("keepalive received");
            false
        }
        // Chaff/cover frames decrypt to nothing meaningful — drop silently.
        _ => false,
    }
}

/// Resolve when SIGINT or SIGTERM is received.
async fn wait_for_shutdown() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    let mut int = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    tokio::select! {
        _ = term.recv() => {},
        _ = int.recv() => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AeadKind, PqLevel};
    use crate::crypto::HandshakeParams;
    use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
    use tokio::sync::Mutex as AsyncMutex;

    /// An in-memory transport: a crossed pair of channels.
    struct MemTransport {
        tx: UnboundedSender<Vec<u8>>,
        rx: AsyncMutex<UnboundedReceiver<Vec<u8>>>,
    }

    impl MemTransport {
        fn pair() -> (MemTransport, MemTransport) {
            let (a_tx, a_rx) = unbounded_channel();
            let (b_tx, b_rx) = unbounded_channel();
            (
                MemTransport {
                    tx: a_tx,
                    rx: AsyncMutex::new(b_rx),
                },
                MemTransport {
                    tx: b_tx,
                    rx: AsyncMutex::new(a_rx),
                },
            )
        }
    }

    #[async_trait::async_trait]
    impl Transport for MemTransport {
        fn kind(&self) -> TransportKind {
            TransportKind::Udp
        }
        async fn send_frame(&self, frame: &[u8]) -> Result<()> {
            self.tx
                .send(frame.to_vec())
                .map_err(|_| Error::Session("mem closed".into()))
        }
        async fn recv_frame(&self, buf: &mut [u8]) -> Result<usize> {
            let mut rx = self.rx.lock().await;
            let v = rx
                .recv()
                .await
                .ok_or_else(|| Error::Session("mem closed".into()))?;
            let n = v.len().min(buf.len());
            buf[..n].copy_from_slice(&v[..n]);
            Ok(n)
        }
    }

    fn keypair() -> ([u8; 32], [u8; 32]) {
        let kp = crate::crypto::generate_static_keypair().unwrap();
        (
            crate::crypto::decode_key_b64(&kp.private_b64, "p").unwrap(),
            crate::crypto::decode_key_b64(&kp.public_b64, "P").unwrap(),
        )
    }

    fn params(local: [u8; 32], peer: [u8; 32]) -> HandshakeParams {
        HandshakeParams {
            local_private: local,
            peer_public: peer,
            psk: None,
            pq_hybrid: true,
            pq_level: PqLevel::MlKem768,
            aead: AeadKind::Chacha20Poly1305,
            local_version: crate::PROTOCOL_VERSION,
            allowed_peers: vec![],
        }
    }

    /// Full wire-path e2e: handshake over an in-memory transport, then a sealed
    /// Data frame survives framing + anti-replay + AEAD open unchanged.
    #[tokio::test]
    async fn end_to_end_handshake_and_data_frame() {
        let (c_priv, c_pub) = keypair();
        let (s_priv, s_pub) = keypair();
        let (client_t, server_t) = MemTransport::pair();

        let cp = params(c_priv, s_pub);
        let sp = params(s_priv, c_pub);

        let server = tokio::spawn(async move {
            let sess = server_handshake(&server_t, &server_t, sp, 0).await.unwrap();
            (sess, server_t)
        });
        let client_sess = client_handshake(&client_t, &client_t, cp).await.unwrap();
        let (server_sess, server_t) = server.await.unwrap();

        assert_eq!(client_sess.session_id, server_sess.session_id);
        assert!(client_sess.pq_active && server_sess.pq_active);

        let inner = b"\x45\x00 a tiny pretend IP packet";
        let no_pad = obfs::PadPolicy {
            min: 0,
            max: 0,
            pad_to: 0,
        };
        let frame = seal_frame(&client_sess, 1, 0, inner, &no_pad).unwrap();
        client_t.send_frame(&frame).await.unwrap();

        let mut buf = vec![0u8; RECV_CAP];
        let n = server_t.recv_frame(&mut buf).await.unwrap();
        let (rh, _) = Header::decode(&buf[..n]).unwrap();
        assert_eq!(rh.ftype, FrameType::Data);

        let aad = &buf[..HEADER_LEN];
        let mut opened = buf[HEADER_LEN..n].to_vec();
        server_sess.rx.open(rh.counter, aad, &mut opened).unwrap();
        assert_eq!(opened, inner);
    }
}
