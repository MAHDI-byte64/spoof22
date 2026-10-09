//! Live admin control over a Unix socket, plus the client the CLI uses.
//!
//! A running instance listens on `observability.control_socket`. The admin CLI
//! (`freespoof ctl <cmd>`) connects and issues a one-line command:
//!
//! * `stats` — Prometheus text dump of the live metrics
//! * `status` — a one-line human status (role, transport, session id)
//! * `rotate-key` — force a rekey (ends the session so a fresh handshake runs)
//! * `switch-transport <kind>` — switch the active transport live
//! * `reload` — re-read the config file and apply on the next session
//! * `help` — list commands
//!
//! `rotate-key`, `switch-transport` and `reload` set shared state that the
//! session manager observes; none of them require a restart.

use std::str::FromStr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Notify;
use tracing::{info, warn};

use crate::config::TransportKind;
use crate::error::{Error, Result};
use crate::metrics::Metrics;

/// Shared control state, cloneable (an `Arc` inside).
#[derive(Clone)]
pub struct Control {
    inner: Arc<Inner>,
}

struct Inner {
    metrics: Metrics,
    rekey: Notify,
    reload: Notify,
    desired_transport: ArcSwap<Option<TransportKind>>,
    status: ArcSwap<String>,
}

impl Control {
    /// Create control state bound to a metrics registry.
    pub fn new(metrics: Metrics) -> Control {
        Control {
            inner: Arc::new(Inner {
                metrics,
                rekey: Notify::new(),
                reload: Notify::new(),
                desired_transport: ArcSwap::from_pointee(None),
                status: ArcSwap::from_pointee(String::from("starting")),
            }),
        }
    }

    /// The metrics handle.
    pub fn metrics(&self) -> &Metrics {
        &self.inner.metrics
    }

    /// Future that resolves when a rekey (or transport switch) is requested.
    pub fn rekey(&self) -> &Notify {
        &self.inner.rekey
    }

    /// Future that resolves when a config reload is requested.
    pub fn reload(&self) -> &Notify {
        &self.inner.reload
    }

    /// Operator-requested transport override (switch-transport), if any.
    pub fn desired_transport(&self) -> Option<TransportKind> {
        **self.inner.desired_transport.load()
    }

    /// Update the human-readable status line.
    pub fn set_status(&self, status: impl Into<String>) {
        self.inner.status.store(Arc::new(status.into()));
    }

    /// Trigger a reload (used by the SIGHUP handler).
    pub fn signal_reload(&self) {
        self.inner.reload.notify_one();
    }

    fn dispatch(&self, line: &str) -> String {
        let mut parts = line.split_whitespace();
        match parts.next() {
            Some("stats") => self.inner.metrics.encode(),
            Some("status") => format!("{}\n", self.inner.status.load()),
            Some("rotate-key") => {
                self.inner.rekey.notify_one();
                "rekey requested; session will re-handshake\n".to_string()
            }
            Some("switch-transport") => match parts.next() {
                Some(k) => match TransportKind::from_str(k) {
                    Ok(kind) => {
                        self.inner.desired_transport.store(Arc::new(Some(kind)));
                        self.inner.rekey.notify_one();
                        format!("switching to {}\n", kind.as_str())
                    }
                    Err(_) => format!("unknown transport '{k}'\n"),
                },
                None => {
                    "usage: switch-transport <udp|icmp|proto58|tcp|quic|ipip|gre>\n".to_string()
                }
            },
            Some("reload") => {
                self.inner.reload.notify_one();
                "reload requested; applies on next session\n".to_string()
            }
            Some("help") | None => {
                "commands: stats | status | rotate-key | switch-transport <kind> | reload | help\n"
                    .to_string()
            }
            Some(other) => format!("unknown command '{other}' (try 'help')\n"),
        }
    }
}

// Lets `switch-transport` parse a transport name.
impl FromStr for TransportKind {
    type Err = ();
    fn from_str(s: &str) -> std::result::Result<TransportKind, ()> {
        Ok(match s {
            "udp" => TransportKind::Udp,
            "icmp" => TransportKind::Icmp,
            "proto58" => TransportKind::Proto58,
            "tcp" => TransportKind::Tcp,
            "quic" => TransportKind::Quic,
            "ipip" => TransportKind::Ipip,
            "gre" => TransportKind::Gre,
            _ => return Err(()),
        })
    }
}

/// Bind the control socket (do this before dropping privileges).
pub fn bind(path: &str) -> Result<UnixListener> {
    let _ = std::fs::remove_file(path);
    UnixListener::bind(path).map_err(|e| Error::Session(format!("bind control socket {path}: {e}")))
}

/// Serve an already-bound control socket until the task is aborted.
pub async fn serve_listener(listener: UnixListener, control: Control) {
    info!("control socket listening");
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(err = %e, "control accept error");
                continue;
            }
        };
        let c = control.clone();
        tokio::spawn(async move {
            handle_conn(stream, c).await;
        });
    }
}

async fn handle_conn(mut stream: UnixStream, control: Control) {
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap_or(0);
    if n == 0 {
        return;
    }
    let line = String::from_utf8_lossy(&buf[..n]);
    let reply = control.dispatch(line.trim());
    let _ = stream.write_all(reply.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// Admin client: connect to the control socket, send `cmd`, return the reply.
pub async fn client(path: &str, cmd: &str) -> Result<String> {
    let mut stream = UnixStream::connect(path)
        .await
        .map_err(|e| Error::Session(format!("connect control socket {path}: {e}")))?;
    stream
        .write_all(cmd.as_bytes())
        .await
        .map_err(Error::from)?;
    stream.write_all(b"\n").await.map_err(Error::from)?;
    stream.shutdown().await.map_err(Error::from)?;
    let mut reply = String::new();
    stream
        .read_to_string(&mut reply)
        .await
        .map_err(Error::from)?;
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_basic() {
        let c = Control::new(Metrics::new());
        assert!(c.dispatch("help").contains("stats"));
        assert!(c.dispatch("stats").contains("freespoof_tx_bytes_total"));
        assert!(c.dispatch("rotate-key").contains("rekey"));
        assert!(c.dispatch("switch-transport gre").contains("gre"));
        assert_eq!(c.desired_transport(), Some(TransportKind::Gre));
        assert!(c.dispatch("switch-transport nope").contains("unknown"));
        assert!(c.dispatch("bogus").contains("unknown command"));
    }
}
