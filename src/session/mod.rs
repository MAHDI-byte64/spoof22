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

use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::config::{Config, FecMode, Role, TransportKind};
use crate::crypto::{self, SessionCrypto};
use crate::error::{Error, Result};
use crate::fec::{FecDecoder, FecEncoder};
use crate::mux::{self, BatchAccumulator};
use crate::obfs::{self, Obfs};
use crate::reliability::Backoff;
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
}

impl PlaneParams {
    fn from_config(cfg: &Config, transport_kind: TransportKind) -> PlaneParams {
        let datagram = transport_kind.supports_mux_fec();
        let mtu = cfg.perf.mtu as usize;
        let mux_max = cfg.mux.multiplex_max_payload.max(mtu);
        // Shard must hold the largest sealed frame + padding + length prefix.
        let max_frame =
            HEADER_LEN + mux_max.max(mtu) + crypto::TAG_LEN + cfg.obfs.packet_padding_max;
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
    /// backoff/failover as needed.
    pub async fn run(self) -> Result<()> {
        let cfg = Arc::new(self.cfg);
        let role = cfg.role;

        // TUN persists across reconnects (keys change, the device does not).
        let tun = Arc::new(TunDevice::create(&cfg.tun).await?);
        info!(dev = tun.name(), mtu = tun.mtu(), "tun device up");

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

        // Reconnect loop vs. shutdown. On shutdown the reconnect-loop future is
        // dropped; any in-flight session's AbortGuard then cleans up its tasks.
        tokio::select! {
            r = reconnect_loop(cfg.clone(), tun.clone()) => r,
            _ = wait_for_shutdown() => {
                info!("shutdown signal received; draining tunnel");
                Ok(())
            }
        }
    }
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
async fn reconnect_loop(cfg: Arc<Config>, tun: Arc<TunDevice>) -> Result<()> {
    let candidates = candidate_transports(&cfg);
    let mut backoff = Backoff::new(
        cfg.reliability.reconnect_backoff_min_ms,
        cfg.reliability.reconnect_backoff_max_ms,
    );
    let mut idx = 0usize;

    loop {
        let (up, down) = candidates[idx % candidates.len()];
        if cfg.transport.transport_racing && candidates.len() > 1 {
            info!(transport = up.as_str(), "racing/trying transport");
        }
        match connect_and_run(&cfg, tun.clone(), up, down).await {
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
        Role::Server => server_handshake(&*send_t, &*recv_t, hs_params).await?,
    };
    info!(
        session = format_args!("{:#018x}", session.session_id),
        pq = session.pq_active,
        aead = ?session.aead,
        "session established"
    );
    log_overhead(cfg, up);

    Ok(run_session(cfg.clone(), tun, send_t, recv_t, Arc::new(session), up).await)
}

/// Spawn the data-plane tasks + keepalive + hopping, and supervise until the
/// session ends (dead peer / fatal error) or shutdown.
async fn run_session(
    cfg: Arc<Config>,
    tun: Arc<TunDevice>,
    send_t: Arc<dyn Transport>,
    recv_t: Arc<dyn Transport>,
    session: Arc<SessionCrypto>,
    up: TransportKind,
) -> SessionOutcome {
    let plane = PlaneParams::from_config(&cfg, up);
    let life = Life::new();

    let mut handles = Vec::new();
    handles.push(tokio::spawn(tun_to_net(
        tun.clone(),
        send_t.clone(),
        session.clone(),
        plane,
        life.clone(),
    )));
    handles.push(tokio::spawn(net_to_tun(
        tun.clone(),
        recv_t.clone(),
        send_t.clone(),
        session.clone(),
        plane,
        life.clone(),
    )));

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

    tokio::select! {
        _ = life.ended.notified() => SessionOutcome::Reconnect,
        _ = wait_for_shutdown() => SessionOutcome::Shutdown,
    }
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

/// Server side: wait for a valid Handshake1, authenticate, reply.
async fn server_handshake(
    send_t: &dyn Transport,
    recv_t: &dyn Transport,
    params: crypto::HandshakeParams,
) -> Result<SessionCrypto> {
    let mut buf = vec![0u8; RECV_CAP];
    loop {
        let body = match wait_for_type(recv_t, &mut buf, FrameType::Handshake1).await {
            Ok(b) => b,
            Err(e) if e.is_droppable() => continue,
            Err(e) => return Err(e),
        };
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

/// Send a sealed frame, applying FEC if enabled.
async fn emit_frame(
    send_t: &dyn Transport,
    fec: &mut Option<FecEncoder>,
    frame: &[u8],
) -> Result<()> {
    if let Some(enc) = fec {
        let out = enc.push(frame)?;
        send_t.send_frame(&out.data).await?;
        for p in out.parity {
            send_t.send_frame(&p).await?;
        }
    } else {
        send_t.send_frame(frame).await?;
    }
    Ok(())
}

/// Emit a sealed frame after an optional timing-jitter delay.
async fn emit_with_jitter(
    send_t: &dyn Transport,
    fec: &mut Option<FecEncoder>,
    frame: &[u8],
    jitter_ms: u64,
) {
    let d = obfs::shaping::jitter(jitter_ms);
    if !d.is_zero() {
        tokio::time::sleep(d).await;
    }
    if let Err(e) = emit_frame(send_t, fec, frame).await {
        warn!(err = %e, "transport send error");
    }
}

/// `tun → net`: batch (optional) → pad → encrypt → FEC (optional) → jitter → send,
/// plus optional cover/chaff traffic on idle slots. One task owns the tx
/// counter, the FEC encoder and the mux accumulator (no locking in the hot path).
async fn tun_to_net(
    tun: Arc<TunDevice>,
    send_t: Arc<dyn Transport>,
    session: Arc<SessionCrypto>,
    plane: PlaneParams,
    life: Life,
) {
    let mut tx_counter: u64 = 0;
    let mut inbuf = vec![0u8; plane.mtu + 256];
    let overhead = HEADER_LEN + crypto::TAG_LEN;
    let jitter_ms = plane.obfs.timing_jitter_ms;
    let mut last_tx = unix_millis();

    let mut fec = if plane.fec_enabled {
        match FecEncoder::new(
            plane.fec_mode,
            plane.fec_data_shards,
            plane.fec_parity_shards,
            plane.shard_len,
        ) {
            Ok(e) => Some(e),
            Err(e) => {
                warn!(err = %e, "FEC disabled: encoder init failed");
                None
            }
        }
    } else {
        None
    };

    let mut acc = if plane.mux_enabled {
        Some(BatchAccumulator::new(plane.mux_max_payload))
    } else {
        None
    };
    let mut mux_ticker = tokio::time::interval(plane.mux_flush);
    let cover_on = plane.obfs.cover_pps > 0;
    let cover_interval = if cover_on {
        Duration::from_nanos(1_000_000_000 / plane.obfs.cover_pps.max(1))
    } else {
        Duration::from_secs(3600)
    };
    let mut cover_ticker = tokio::time::interval(cover_interval);

    let ka_poll = if plane.keepalive_secs > 0 {
        (plane.keepalive_secs / 2).max(1)
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
                    if a.would_overflow(n) {
                        flush_batch(&send_t, &session, &mut tx_counter, &mut fec, a, &plane).await;
                    }
                    let _ = a.push(&inbuf[..n]);
                    if a.encoded_len() >= plane.mux_max_payload {
                        flush_batch(&send_t, &session, &mut tx_counter, &mut fec, a, &plane).await;
                    }
                } else {
                    let counter = tx_counter;
                    tx_counter += 1;
                    let pad = plane.obfs.frame_pad(overhead);
                    match seal_frame(&session, counter, 0, &inbuf[..n], &pad) {
                        Ok(frame) => emit_with_jitter(&*send_t, &mut fec, &frame, jitter_ms).await,
                        Err(e) => warn!(err = %e, "seal failed (rekey needed?)"),
                    }
                }
            }
            _ = mux_ticker.tick(), if acc.is_some() => {
                if let Some(a) = &mut acc {
                    if !a.is_empty() {
                        flush_batch(&send_t, &session, &mut tx_counter, &mut fec, a, &plane).await;
                    }
                }
            }
            _ = cover_ticker.tick(), if cover_on => {
                let counter = tx_counter;
                tx_counter += 1;
                let pad = plane.obfs.frame_pad(overhead);
                if let Ok(frame) = seal_chaff(&session, counter, &pad) {
                    emit_with_jitter(&*send_t, &mut fec, &frame, jitter_ms).await;
                    last_tx = unix_millis();
                }
            }
            _ = ka_ticker.tick() => {
                let now = unix_millis();
                // Dead-peer detection → end the session (triggers reconnect).
                if plane.dead_secs > 0 && now.saturating_sub(life.last_rx_ms()) >= plane.dead_secs * 1000 {
                    warn!("dead peer detected (no traffic); ending session");
                    life.end();
                    return;
                }
                // Heartbeat when idle (also keeps NAT mappings warm).
                if plane.keepalive_secs > 0 && now.saturating_sub(last_tx) >= plane.keepalive_secs * 1000 {
                    let counter = tx_counter;
                    tx_counter += 1;
                    let pad = plane.obfs.frame_pad(overhead);
                    if let Ok(frame) = seal_typed(&session, FrameType::Keepalive, counter, 0, &[], &pad) {
                        emit_with_jitter(&*send_t, &mut fec, &frame, jitter_ms).await;
                        last_tx = now;
                    }
                }
            }
        }
    }
}

/// Flush the mux accumulator as one padded, batched Data frame.
async fn flush_batch(
    send_t: &Arc<dyn Transport>,
    session: &Arc<SessionCrypto>,
    tx_counter: &mut u64,
    fec: &mut Option<FecEncoder>,
    acc: &mut BatchAccumulator,
    plane: &PlaneParams,
) {
    let Some(batch) = acc.take() else { return };
    let counter = *tx_counter;
    *tx_counter += 1;
    let pad = plane.obfs.frame_pad(HEADER_LEN + crypto::TAG_LEN);
    match seal_frame(session, counter, flags::MUX_BATCH, &batch, &pad) {
        Ok(frame) => emit_with_jitter(&**send_t, fec, &frame, plane.obfs.timing_jitter_ms).await,
        Err(e) => warn!(err = %e, "seal batch failed"),
    }
}

/// `net → tun`: FEC reconstruct (optional), decrypt, debatch (if mux), deliver,
/// plus liveness tracking and auth-gated connection migration.
async fn net_to_tun(
    tun: Arc<TunDevice>,
    recv_t: Arc<dyn Transport>,
    send_t: Arc<dyn Transport>,
    session: Arc<SessionCrypto>,
    plane: PlaneParams,
    life: Life,
) {
    use crate::crypto::ReplayWindow;
    let mut replay = ReplayWindow::new(plane.replay_window);
    let mut dec = if plane.fec_enabled {
        Some(FecDecoder::new(plane.fec_mode, plane.fec_max_groups))
    } else {
        None
    };
    let mut buf = vec![0u8; RECV_CAP];
    let mut cur_peer: Option<std::net::Ipv4Addr> = None;

    loop {
        let (n, src) = match recv_t.recv_frame_from(&mut buf).await {
            Ok(x) => x,
            Err(e) => {
                // A fatal transport error (e.g. QUIC connection closed) ends
                // the session so the manager can reconnect.
                warn!(err = %e, "transport recv error; ending session");
                life.end();
                return;
            }
        };
        if n == 0 {
            continue;
        }
        life.mark_rx();

        // FEC stage (if enabled) yields 0+ sealed frames; otherwise the
        // datagram is the sealed frame.
        let sealed_frames: Vec<Vec<u8>> = if let Some(d) = &mut dec {
            match d.push(&buf[..n]) {
                Ok(v) => v,
                Err(_) => continue, // malformed FEC datagram — drop
            }
        } else {
            vec![buf[..n].to_vec()]
        };

        let mut authed = false;
        for frame in sealed_frames {
            authed |= process_sealed(&tun, &session, &mut replay, &frame).await;
        }

        // Connection migration: once an authenticated frame arrives from a new
        // source, adopt it as the peer (server side). Never trust the source
        // before authentication.
        if authed && plane.migration && plane.is_server && send_t.supports_hop() {
            if let Some(ip) = src {
                if cur_peer != Some(ip) {
                    send_t.set_peer(std::net::SocketAddrV4::new(ip, plane.data_port));
                    cur_peer = Some(ip);
                    info!(peer = %ip, "connection migrated to new peer source");
                }
            }
        }
    }
}

/// Decode, anti-replay, decrypt, and deliver one sealed frame. Returns `true`
/// if an authenticated `Data` frame was processed (used to gate migration).
async fn process_sealed(
    tun: &TunDevice,
    session: &SessionCrypto,
    replay: &mut crate::crypto::ReplayWindow,
    frame: &[u8],
) -> bool {
    if frame.len() < HEADER_LEN {
        return false;
    }
    let (header, _) = match Header::decode(frame) {
        Ok(x) => x,
        Err(_) => return false, // malformed — drop silently
    };
    match header.ftype {
        FrameType::Data => {
            if !replay.check_and_update(header.counter) {
                debug!(counter = header.counter, "replay/stale frame dropped");
                return false;
            }
            let aad = &frame[..HEADER_LEN];
            let mut body = frame[HEADER_LEN..].to_vec();
            if session.rx.open(header.counter, aad, &mut body).is_err() {
                return false; // fail-closed
            }
            // Strip padding if present, then (if batched) split.
            let payload: &[u8] = if header.flags & flags::PADDED != 0 {
                match obfs::padding::strip(&body) {
                    Some(p) => p,
                    None => return false, // malformed padding trailer — drop
                }
            } else {
                &body
            };
            if header.flags & flags::MUX_BATCH != 0 {
                if let Ok(pkts) = mux::decode_batch(payload) {
                    for p in pkts {
                        let _ = tun.send(p).await;
                    }
                }
            } else {
                let _ = tun.send(payload).await;
            }
            true
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
            let sess = server_handshake(&server_t, &server_t, sp).await.unwrap();
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
