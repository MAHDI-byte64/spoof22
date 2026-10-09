//! Shared core for the raw-crafted transports (`icmp`, `proto58`, `ipip`,
//! `gre`). Each such transport differs only in its IP protocol number and a
//! thin L4 wrapper around the wire frame; everything else — building the
//! forged IPv4 header, sending on the raw socket, receiving + parsing +
//! source/protocol filtering — is identical and lives here.

use std::collections::VecDeque;
use std::net::Ipv4Addr;

use arc_swap::ArcSwap;
use parking_lot::Mutex;

use crate::error::Result;
use crate::spoof::ipv4::{self, Ipv4Build};
use crate::spoof::{IpIdCounter, RawIpSocket};

use super::TransportParams;

/// How many packets the batched receive path pulls per `recvmmsg` syscall.
const RECV_BATCH: usize = 16;
/// Per-message scratch size for the batched receive (jumbo-frame safe).
const RECV_BUF: usize = 9216;

/// A reusable raw-IPv4 send/receive core bound to one protocol.
pub struct RawCore {
    raw: RawIpSocket,
    src: Ipv4Addr,
    /// Dynamic destination (hopping/migration) — one atomic load per packet.
    dst: ArcSwap<Ipv4Addr>,
    expect_src: Ipv4Addr,
    accept_any: bool,
    ttl_pool: Vec<u8>,
    dscp_pool: Vec<u8>,
    protocol: u8,
    ip_id: IpIdCounter,
    /// Validated inbound payloads drained from a `recvmmsg` burst, served one
    /// at a time by [`RawCore::recv_l4`] (shared across the per-tunnel tasks).
    recv_q: Mutex<VecDeque<(Vec<u8>, Ipv4Addr)>>,
    /// Optional io_uring backend for the batched send path (feature-gated).
    #[cfg(feature = "io_uring")]
    uring: Option<std::sync::Arc<crate::spoof::uring::UringSender>>,
}

impl RawCore {
    /// Create a raw core for `protocol` using the transport parameters.
    pub fn new(protocol: u8, p: &TransportParams) -> Result<RawCore> {
        let raw = RawIpSocket::new(protocol, &p.interface, p.sndbuf, p.rcvbuf)?;
        Ok(RawCore {
            raw,
            src: p.forged_src,
            dst: ArcSwap::from_pointee(p.peer_real),
            expect_src: p.peer_spoofed,
            accept_any: p.accept_any_src,
            ttl_pool: p.ttl_pool.clone(),
            dscp_pool: p.dscp_pool.clone(),
            protocol,
            ip_id: IpIdCounter::new(),
            recv_q: Mutex::new(VecDeque::new()),
            #[cfg(feature = "io_uring")]
            uring: match crate::spoof::uring::UringSender::new(256) {
                Ok(s) => Some(std::sync::Arc::new(s)),
                Err(e) => {
                    tracing::warn!(err = %e, "io_uring init failed; using sendmmsg path");
                    None
                }
            },
        })
    }

    /// Update the destination address (endpoint hopping / migration).
    pub fn set_dst(&self, dst: Ipv4Addr) {
        self.dst.store(std::sync::Arc::new(dst));
    }

    /// Build the IPv4 packet around an already-formed L4 payload and send it,
    /// applying per-packet TTL jitter and DSCP marking.
    pub async fn send_l4(&self, l4: &[u8]) -> Result<()> {
        let dst = **self.dst.load();
        let pkt = ipv4::build(&Ipv4Build {
            src: self.src,
            dst,
            protocol: self.protocol,
            ttl: super::pick(&self.ttl_pool, 64),
            tos: super::pick(&self.dscp_pool, 0),
            id: self.ip_id.next(),
            payload: l4,
        });
        self.raw.send_to(&pkt, dst).await?;
        Ok(())
    }

    /// Build IPv4 packets around each already-formed L4 payload and send the
    /// whole set with one `sendmmsg(2)` syscall (per-packet TTL/DSCP/IP-ID are
    /// still applied). All packets go to the current destination.
    pub async fn send_l4_batch(&self, l4s: &[&[u8]]) -> Result<()> {
        if l4s.is_empty() {
            return Ok(());
        }
        if l4s.len() == 1 {
            return self.send_l4(l4s[0]).await;
        }
        let dst = **self.dst.load();
        let pkts: Vec<Vec<u8>> = l4s
            .iter()
            .map(|l4| {
                ipv4::build(&Ipv4Build {
                    src: self.src,
                    dst,
                    protocol: self.protocol,
                    ttl: super::pick(&self.ttl_pool, 64),
                    tos: super::pick(&self.dscp_pool, 0),
                    id: self.ip_id.next(),
                    payload: l4,
                })
            })
            .collect();
        // With the io_uring feature, route the batch through the ring on a
        // blocking thread (the backend blocks on submit_and_wait); otherwise
        // use the sendmmsg(2) path. Both fall back gracefully.
        #[cfg(feature = "io_uring")]
        if let Some(sender) = &self.uring {
            use std::os::fd::RawFd;
            let fd: RawFd = self.raw.raw_fd();
            let sender = sender.clone();
            let owned: Vec<(Vec<u8>, Ipv4Addr)> = pkts.iter().map(|p| (p.clone(), dst)).collect();
            let res = tokio::task::spawn_blocking(move || sender.send_batch_blocking(fd, &owned))
                .await
                .map_err(|e| {
                    crate::error::Error::transport("raw", format!("io_uring join: {e}"))
                })?;
            res.map_err(crate::error::Error::from)?;
            return Ok(());
        }

        let refs: Vec<(&[u8], Ipv4Addr)> = pkts.iter().map(|p| (p.as_slice(), dst)).collect();
        self.raw.send_mmsg(&refs).await?;
        Ok(())
    }

    /// Receive one inbound packet of our protocol, validate the IPv4 header,
    /// filter by expected source, and copy the L4 payload into `out`,
    /// returning `(payload_len, observed_source)`.
    ///
    /// Inbound packets are drained a burst at a time with `recvmmsg(2)` into an
    /// internal queue and then served one per call, so a flood costs far fewer
    /// syscalls than one `recv` per packet. The queue is shared across the
    /// per-tunnel receive tasks; two tasks finding it empty simply pull two
    /// bursts, which is harmless (frames are self-describing and order-
    /// independent at this layer).
    pub async fn recv_l4(&self, out: &mut [u8]) -> Result<(usize, Ipv4Addr)> {
        loop {
            if let Some((payload, src)) = self.recv_q.lock().pop_front() {
                let m = payload.len().min(out.len());
                out[..m].copy_from_slice(&payload[..m]);
                return Ok((m, src));
            }
            // Queue empty — pull a fresh burst (no lock held across the await).
            let mut bufs: Vec<Vec<u8>> = (0..RECV_BATCH).map(|_| vec![0u8; RECV_BUF]).collect();
            let lens = self.raw.recv_mmsg(&mut bufs).await?;
            let mut q = self.recv_q.lock();
            for (buf, &len) in bufs.iter().zip(lens.iter()) {
                let view = match ipv4::parse(&buf[..len]) {
                    Ok(v) => v,
                    Err(_) => continue, // malformed IP — skip
                };
                if view.protocol != self.protocol {
                    continue;
                }
                if !self.accept_any && view.src != self.expect_src {
                    continue; // not our peer's expected (forged) source — skip
                }
                q.push_back((view.payload.to_vec(), view.src));
            }
        }
    }
}
