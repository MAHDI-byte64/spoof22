//! Session lifecycle: handshake, then the bidirectional data plane.
//!
//! Milestone 1 implements a single point-to-point session over one transport:
//!
//! * the client initiates the Noise_IK(+ML-KEM) handshake, the server responds;
//! * once keys are established, two tasks run concurrently:
//!     - `tun → net`: read an inner IP packet from the TUN, seal it into a
//!       `Data` frame (header authenticated as AAD), send it over the transport;
//!     - `net → tun`: receive a frame, route by type, anti-replay + open `Data`
//!       frames, write the inner packet to the TUN.
//!
//! The tunnel pool, failover, migration and reconnection are layered on in
//! later milestones; the lifecycle hooks here are the extension points.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tracing::{debug, info, warn};

use crate::config::{Config, Role};
use crate::crypto::{self, ReplayWindow, SessionCrypto};
use crate::error::{Error, Result};
use crate::transport::{self, Transport, TransportParams};
use crate::tun::TunDevice;
use crate::wire::{FrameType, Header, HEADER_LEN};

/// Max datagram we will receive from a transport (UDP ceiling).
const RECV_CAP: usize = 65_535;

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

        // --- Transport ----------------------------------------------------
        let params = TransportParams::from_config(&cfg, cfg.role);
        let up = cfg.transport.uplink_protocol;
        let transport = transport::build(up, &params).await?;
        info!(transport = up.as_str(), "transport ready");

        // --- TUN ----------------------------------------------------------
        let tun = Arc::new(TunDevice::create(&cfg.tun).await?);
        info!(dev = tun.name(), mtu = tun.mtu(), "tun device up");

        // --- Handshake ----------------------------------------------------
        let hs_params = crypto::handshake_params(&cfg)?;
        let session = match cfg.role {
            Role::Client => client_handshake(&*transport, hs_params).await?,
            Role::Server => server_handshake(&*transport, hs_params).await?,
        };
        info!(
            session = format_args!("{:#018x}", session.session_id),
            pq = session.pq_active,
            aead = ?session.aead,
            "session established"
        );

        let session = Arc::new(session);
        let tx_counter = Arc::new(AtomicU64::new(0));
        let replay = Arc::new(Mutex::new(ReplayWindow::new(cfg.crypto.replay_window)));

        // --- Data plane ---------------------------------------------------
        let up_task = tokio::spawn(tun_to_net(
            tun.clone(),
            transport.clone(),
            session.clone(),
            tx_counter.clone(),
            cfg.perf.mtu as usize,
        ));
        let down_task = tokio::spawn(net_to_tun(
            tun.clone(),
            transport.clone(),
            session.clone(),
            replay,
        ));

        // --- Wait for shutdown --------------------------------------------
        wait_for_shutdown().await;
        info!("shutting down; draining tunnel");
        up_task.abort();
        down_task.abort();
        Ok(())
    }
}

/// Client side: initiate the handshake with retransmission until the reply.
async fn client_handshake(
    transport: &dyn Transport,
    params: crypto::HandshakeParams,
) -> Result<SessionCrypto> {
    let (initiator, msg1) = crypto::Initiator::start(params)?;
    let frame = frame_with(FrameType::Handshake1, &msg1);

    let mut buf = vec![0u8; RECV_CAP];
    let mut attempts = 0u32;
    loop {
        transport.send_frame(&frame).await?;
        attempts += 1;
        match tokio::time::timeout(
            Duration::from_secs(2),
            wait_for_type(transport, &mut buf, FrameType::Handshake2),
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
///
/// Unauthenticated/garbage traffic is dropped silently (fail-closed) and we
/// keep waiting — no response reveals the tunnel exists.
async fn server_handshake(
    transport: &dyn Transport,
    params: crypto::HandshakeParams,
) -> Result<SessionCrypto> {
    let mut buf = vec![0u8; RECV_CAP];
    loop {
        let body = match wait_for_type(transport, &mut buf, FrameType::Handshake1).await {
            Ok(b) => b,
            Err(e) if e.is_droppable() => continue,
            Err(e) => return Err(e),
        };
        let responder = crypto::Responder::start(params.clone())?;
        match responder.respond(&body) {
            Ok((msg2, result)) => {
                let reply = frame_with(FrameType::Handshake2, &msg2);
                transport.send_frame(&reply).await?;
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
            Ok(_) => continue,  // some other frame type; ignore
            Err(_) => continue, // malformed; drop
        }
    }
}

/// Build a frame: header (counter 0 for control/handshake) + body.
fn frame_with(ftype: FrameType, body: &[u8]) -> Vec<u8> {
    let header = Header::new(ftype, 0, 0, 0);
    let mut v = Vec::with_capacity(HEADER_LEN + body.len());
    v.extend_from_slice(&header.to_bytes());
    v.extend_from_slice(body);
    v
}

/// `tun → net`: encrypt inner packets and send them.
async fn tun_to_net(
    tun: Arc<TunDevice>,
    transport: Arc<dyn Transport>,
    session: Arc<SessionCrypto>,
    tx_counter: Arc<AtomicU64>,
    mtu: usize,
) {
    let mut inbuf = vec![0u8; mtu + 128];
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
        let counter = tx_counter.fetch_add(1, Ordering::Relaxed);
        let header = Header::new(FrameType::Data, 0, session.session_id, counter);
        let hdr = header.to_bytes();

        // Body = inner IP packet, sealed in place (ciphertext + tag).
        let mut body = inbuf[..n].to_vec();
        if let Err(e) = session.tx.seal(counter, &hdr, &mut body) {
            warn!(err = %e, "seal failed (rekey needed?)");
            continue;
        }

        let mut frame = Vec::with_capacity(HEADER_LEN + body.len());
        frame.extend_from_slice(&hdr);
        frame.extend_from_slice(&body);

        if let Err(e) = transport.send_frame(&frame).await {
            warn!(err = %e, "transport send error");
        }
    }
}

/// `net → tun`: receive, anti-replay, decrypt, deliver.
async fn net_to_tun(
    tun: Arc<TunDevice>,
    transport: Arc<dyn Transport>,
    session: Arc<SessionCrypto>,
    replay: Arc<Mutex<ReplayWindow>>,
) {
    let mut buf = vec![0u8; RECV_CAP];
    loop {
        let n = match transport.recv_frame(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                warn!(err = %e, "transport recv error");
                continue;
            }
        };
        if n < HEADER_LEN {
            continue; // too short — drop
        }
        let frame = &buf[..n];
        let (header, _) = match Header::decode(frame) {
            Ok(x) => x,
            Err(_) => continue, // malformed — drop silently
        };

        match header.ftype {
            FrameType::Data => {
                // Anti-replay before doing crypto work.
                if !replay.lock().check_and_update(header.counter) {
                    debug!(counter = header.counter, "replay/stale frame dropped");
                    continue;
                }
                let aad = &frame[..HEADER_LEN];
                let mut body = frame[HEADER_LEN..].to_vec();
                if session.rx.open(header.counter, aad, &mut body).is_err() {
                    // Fail-closed: unauthenticated frame, drop silently.
                    continue;
                }
                if let Err(e) = tun.send(&body).await {
                    warn!(err = %e, "tun write error");
                }
            }
            FrameType::Keepalive => {
                debug!("keepalive received");
            }
            _ => { /* ignore stray handshake/control frames in data phase */ }
        }
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

    /// An in-memory transport: a crossed pair of channels, so a client and a
    /// server engine can exchange frames without raw sockets or a TUN.
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
        fn kind(&self) -> crate::config::TransportKind {
            crate::config::TransportKind::Udp
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
    /// Data frame survives framing + anti-replay + AEAD open unchanged, while a
    /// replayed frame is rejected.
    #[tokio::test]
    async fn end_to_end_handshake_and_data_frame() {
        let (c_priv, c_pub) = keypair();
        let (s_priv, s_pub) = keypair();
        let (client_t, server_t) = MemTransport::pair();

        let cp = params(c_priv, s_pub);
        let sp = params(s_priv, c_pub);

        // Run both handshake halves concurrently.
        let server = tokio::spawn(async move {
            let sess = server_handshake(&server_t, sp).await.unwrap();
            (sess, server_t)
        });
        let client_sess = client_handshake(&client_t, cp).await.unwrap();
        let (server_sess, server_t) = server.await.unwrap();

        assert_eq!(client_sess.session_id, server_sess.session_id);
        assert!(client_sess.pq_active && server_sess.pq_active);

        // Client seals an inner "IP packet" into a Data frame.
        let inner = b"\x45\x00 a tiny pretend IP packet";
        let counter = 1u64;
        let header = Header::new(FrameType::Data, 0, client_sess.session_id, counter);
        let hdr = header.to_bytes();
        let mut body = inner.to_vec();
        client_sess.tx.seal(counter, &hdr, &mut body).unwrap();
        let mut frame = hdr.to_vec();
        frame.extend_from_slice(&body);
        client_t.send_frame(&frame).await.unwrap();

        // Server receives, decodes, replay-checks, opens.
        let mut buf = vec![0u8; RECV_CAP];
        let n = server_t.recv_frame(&mut buf).await.unwrap();
        let rframe = &buf[..n];
        let (rh, _) = Header::decode(rframe).unwrap();
        assert_eq!(rh.ftype, FrameType::Data);

        let mut replay = ReplayWindow::new(1024);
        assert!(replay.check_and_update(rh.counter));
        let aad = &rframe[..HEADER_LEN];
        let mut opened = rframe[HEADER_LEN..].to_vec();
        server_sess.rx.open(rh.counter, aad, &mut opened).unwrap();
        assert_eq!(opened, inner);

        // A replay of the same counter is rejected.
        assert!(!replay.check_and_update(rh.counter));
    }
}
