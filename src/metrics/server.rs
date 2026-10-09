//! Minimal HTTP/1.1 server for `/metrics` (Prometheus) and `/health` (JSON).
//!
//! Hand-rolled over tokio to avoid a heavy HTTP dependency: it reads the
//! request line, routes on the path, and writes a single response. It is not a
//! general web server — only these two read-only endpoints are served.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, info};

use super::Metrics;

/// Bind the metrics listener (before dropping privileges).
pub async fn bind(addr: &str) -> crate::error::Result<TcpListener> {
    TcpListener::bind(addr)
        .await
        .map_err(|e| crate::error::Error::Session(format!("bind metrics {addr}: {e}")))
}

/// Serve `/metrics` and `/health` on an already-bound listener.
pub async fn serve_listener(listener: TcpListener, metrics: Metrics) {
    info!("metrics/health endpoint listening");
    loop {
        let (mut sock, _) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                debug!(err = %e, "metrics accept error");
                continue;
            }
        };
        let m = metrics.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let path = req.split_whitespace().nth(1).unwrap_or("/");

            let (status, ctype, body) = match path {
                "/metrics" => ("200 OK", "text/plain; version=0.0.4", m.encode()),
                "/health" => ("200 OK", "application/json", m.health_json()),
                _ => ("404 Not Found", "text/plain", "not found\n".to_string()),
            };
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.shutdown().await;
        });
    }
}
