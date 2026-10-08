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
}

impl PlaneParams {
    fn from_config(cfg: &Config, transport_kind: TransportKind) -> PlaneParams {
        let datagram = transport_kind.supports_mux_fec();
        let mtu = cfg.perf.mtu as usize;
        let mux_max = cfg.mux.multiplex_max_payload.max(mtu);
        // Shard must hold the largest sealed frame + the 2-byte FEC length prefix.
        let max_frame = HEADER_LEN + mux_max.max(mtu) + crypto::TAG_LEN;
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

    /// Run until a shutdown signal (SIGINT/SIGTERM) arrives.
    pub async fn run(self) -> Result<()> {
        let cfg = self.cfg;
        let role = cfg.role;

        // --- Transports (send = uplink, recv = downlink) ------------------
        let up = cfg.transport.uplink_protocol;
        let down = cfg.transport.downlink_protocol;
        let send_t = transport::build(up, &cfg, role).await?;
        let recv_t: Arc<dyn Transport> = if down == up {
            send_t.clone()
        } else {
            transport::build(down, &cfg, role).await?
        };
        info!(
            uplink = up.as_str(),
            downlink = down.as_str(),
            "transports ready"
        );

        // --- TUN ----------------------------------------------------------
        let tun = Arc::new(TunDevice::create(&cfg.tun).await?);
        info!(dev = tun.name(), mtu = tun.mtu(), "tun device up");

        // --- Handshake ----------------------------------------------------
        let hs_params = crypto::handshake_params(&cfg)?;
        let session = match role {
            Role::Client => client_handshake(&*send_t, &*recv_t, hs_params).await?,
            Role::Server => server_handshake(&*send_t, &*recv_t, hs_params).await?,
        };
        info!(
            session = format_args!("{:#018x}", session.session_id),
            pq = session.pq_active,
            aead = ?session.aead,
            "session established"
        );
        log_overhead(&cfg, up);

        let session = Arc::new(session);
        let plane = PlaneParams::from_config(&cfg, up);

        // --- Data plane ---------------------------------------------------
        let up_task = tokio::spawn(tun_to_net(
            tun.clone(),
            send_t.clone(),
            session.clone(),
            plane,
        ));
        let down_task = tokio::spawn(net_to_tun(
            tun.clone(),
            recv_t.clone(),
            session.clone(),
            plane,
        ));

        wait_for_shutdown().await;
        info!("shutting down; draining tunnel");
        up_task.abort();
        down_task.abort();
        Ok(())
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

/// Seal a plaintext payload into a `Data` frame (header authenticated as AAD).
fn seal_frame(
    session: &SessionCrypto,
    counter: u64,
    extra_flags: u8,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let header = Header::new(FrameType::Data, extra_flags, session.session_id, counter);
    let hdr = header.to_bytes();
    let mut body = payload.to_vec();
    session.tx.seal(counter, &hdr, &mut body)?;
    let mut frame = Vec::with_capacity(HEADER_LEN + body.len());
    frame.extend_from_slice(&hdr);
    frame.extend_from_slice(&body);
    Ok(frame)
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

/// `tun → net`: batch (optional), encrypt, FEC (optional), send.
async fn tun_to_net(
    tun: Arc<TunDevice>,
    send_t: Arc<dyn Transport>,
    session: Arc<SessionCrypto>,
    plane: PlaneParams,
) {
    let mut tx_counter: u64 = 0;
    let mut inbuf = vec![0u8; plane.mtu + 256];

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

    if plane.mux_enabled {
        let mut acc = BatchAccumulator::new(plane.mux_max_payload);
        let mut ticker = tokio::time::interval(plane.mux_flush);
        loop {
            tokio::select! {
                r = tun.recv(&mut inbuf) => {
                    let n = match r { Ok(n) => n, Err(e) => { warn!(err=%e, "tun read"); continue; } };
                    if n == 0 { continue; }
                    if acc.would_overflow(n) {
                        flush_batch(&send_t, &session, &mut tx_counter, &mut fec, &mut acc).await;
                    }
                    if acc.push(&inbuf[..n]).is_err() { continue; }
                    if acc.encoded_len() >= plane.mux_max_payload {
                        flush_batch(&send_t, &session, &mut tx_counter, &mut fec, &mut acc).await;
                    }
                }
                _ = ticker.tick() => {
                    if !acc.is_empty() {
                        flush_batch(&send_t, &session, &mut tx_counter, &mut fec, &mut acc).await;
                    }
                }
            }
        }
    } else {
        loop {
            let n = match tun.recv(&mut inbuf).await {
                Ok(n) => n,
                Err(e) => {
                    warn!(err = %e, "tun read error");
                    continue;
                }
            };
            if n == 0 {
                continue;
            }
            let counter = tx_counter;
            tx_counter += 1;
            match seal_frame(&session, counter, 0, &inbuf[..n]) {
                Ok(frame) => {
                    if let Err(e) = emit_frame(&*send_t, &mut fec, &frame).await {
                        warn!(err = %e, "transport send error");
                    }
                }
                Err(e) => warn!(err = %e, "seal failed (rekey needed?)"),
            }
        }
    }
}

/// Flush the mux accumulator as one batched Data frame.
async fn flush_batch(
    send_t: &Arc<dyn Transport>,
    session: &Arc<SessionCrypto>,
    tx_counter: &mut u64,
    fec: &mut Option<FecEncoder>,
    acc: &mut BatchAccumulator,
) {
    let Some(batch) = acc.take() else { return };
    let counter = *tx_counter;
    *tx_counter += 1;
    match seal_frame(session, counter, flags::MUX_BATCH, &batch) {
        Ok(frame) => {
            if let Err(e) = emit_frame(&**send_t, fec, &frame).await {
                warn!(err = %e, "transport send error");
            }
        }
        Err(e) => warn!(err = %e, "seal batch failed"),
    }
}

/// `net → tun`: FEC reconstruct (optional), decrypt, debatch (if mux), deliver.
async fn net_to_tun(
    tun: Arc<TunDevice>,
    recv_t: Arc<dyn Transport>,
    session: Arc<SessionCrypto>,
    plane: PlaneParams,
) {
    use crate::crypto::ReplayWindow;
    let mut replay = ReplayWindow::new(2048);
    let mut dec = if plane.fec_enabled {
        Some(FecDecoder::new(plane.fec_mode, plane.fec_max_groups))
    } else {
        None
    };
    let mut buf = vec![0u8; RECV_CAP];

    loop {
        let n = match recv_t.recv_frame(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                warn!(err = %e, "transport recv error");
                continue;
            }
        };
        if n == 0 {
            continue;
        }

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

        for frame in sealed_frames {
            process_sealed(&tun, &session, &mut replay, &frame).await;
        }
    }
}

/// Decode, anti-replay, decrypt, and deliver one sealed frame.
async fn process_sealed(
    tun: &TunDevice,
    session: &SessionCrypto,
    replay: &mut crate::crypto::ReplayWindow,
    frame: &[u8],
) {
    if frame.len() < HEADER_LEN {
        return;
    }
    let (header, _) = match Header::decode(frame) {
        Ok(x) => x,
        Err(_) => return, // malformed — drop silently
    };
    match header.ftype {
        FrameType::Data => {
            if !replay.check_and_update(header.counter) {
                debug!(counter = header.counter, "replay/stale frame dropped");
                return;
            }
            let aad = &frame[..HEADER_LEN];
            let mut body = frame[HEADER_LEN..].to_vec();
            if session.rx.open(header.counter, aad, &mut body).is_err() {
                return; // fail-closed
            }
            if header.flags & flags::MUX_BATCH != 0 {
                if let Ok(pkts) = mux::decode_batch(&body) {
                    for p in pkts {
                        let _ = tun.send(p).await;
                    }
                }
            } else {
                let _ = tun.send(&body).await;
            }
        }
        FrameType::Keepalive => debug!("keepalive received"),
        _ => {}
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
        let frame = seal_frame(&client_sess, 1, 0, inner).unwrap();
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
