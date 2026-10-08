//! Active-probing resistance: a decoy reverse proxy.
//!
//! When an unauthenticated client (an active prober or a censor's scanner)
//! connects to the server's advertised service, it is transparently
//! reverse-proxied to a real HTTPS site. The prober therefore sees a
//! legitimate website — not silence, a reset, or an anomaly — which is the
//! Reality/Trojan anti-probing posture.
//!
//! Because the tunnel's data-plane transports are raw-crafted (they do not own
//! a kernel TCP socket), the decoy can safely own a real `TcpListener` on the
//! server's public TLS port and byte-forward every connection to the decoy
//! upstream (TLS passes through untouched). Tunnel clients never connect here;
//! only probes do.

use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use crate::error::{Error, Result};

/// Run the decoy reverse proxy until the process exits.
///
/// `listen` is `ip:port` to bind; `target` is the upstream `host:port` to
/// forward every accepted connection to.
pub async fn run(listen: String, target: String) -> Result<()> {
    let listener = TcpListener::bind(&listen)
        .await
        .map_err(|e| Error::transport("decoy", format!("bind {listen}: {e}")))?;
    info!(%listen, %target, "active-probe decoy reverse proxy listening");

    loop {
        let (mut inbound, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(err = %e, "decoy accept error");
                continue;
            }
        };
        let target = target.clone();
        tokio::spawn(async move {
            debug!(%peer, "decoy: forwarding probe to upstream");
            match TcpStream::connect(&target).await {
                Ok(mut upstream) => {
                    // Transparent byte forwarding in both directions.
                    let _ = copy_bidirectional(&mut inbound, &mut upstream).await;
                }
                Err(e) => debug!(err = %e, "decoy upstream connect failed"),
            }
        });
    }
}

/// Resolve the decoy listen address, defaulting to the real IP on :443.
pub fn listen_addr(decoy_listen: &str, real_ip: std::net::Ipv4Addr) -> String {
    if decoy_listen.trim().is_empty() {
        format!("{real_ip}:443")
    } else {
        decoy_listen.trim().to_string()
    }
}
