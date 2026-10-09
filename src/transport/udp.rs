//! UDP transport (IP protocol 17).
//!
//! Outbound frames are emitted as UDP datagrams built on a raw socket, so the
//! IPv4 source can be forged. Inbound frames are received on a normal bound
//! UDP socket: the kernel then owns the port, so it will not answer with an
//! ICMP port-unreachable, and reverse-path filtering must be disabled on the
//! interface (the setup step / manager handles `rp_filter=0`).

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use tokio::net::UdpSocket;

use crate::config::TransportKind;
use crate::error::{Error, Result};
use crate::spoof::checksum;
use crate::spoof::ipv4::{self, Ipv4Build};
use crate::spoof::{IpIdCounter, RawIpSocket};

use super::{Transport, TransportParams};

/// UDP transport state.
pub struct UdpTransport {
    raw: RawIpSocket,
    recv_sock: UdpSocket,
    src: Ipv4Addr,
    dst: ArcSwap<Ipv4Addr>,
    src_port: u16,
    dst_port: u16,
    ttl_pool: Vec<u8>,
    dscp_pool: Vec<u8>,
    ip_id: IpIdCounter,
}

impl UdpTransport {
    /// Bind the raw send socket and the UDP receive socket.
    pub async fn bind(p: &TransportParams) -> Result<UdpTransport> {
        let raw = RawIpSocket::new(17, &p.interface, p.sndbuf, p.rcvbuf)?;
        let recv_sock = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            p.data_port,
        )))
        .await
        .map_err(|e| Error::transport("udp", format!("bind recv :{}: {e}", p.data_port)))?;

        Ok(UdpTransport {
            raw,
            recv_sock,
            src: p.forged_src,
            dst: ArcSwap::from_pointee(p.peer_real),
            src_port: p.data_port,
            dst_port: p.data_port,
            ttl_pool: p.ttl_pool.clone(),
            dscp_pool: p.dscp_pool.clone(),
            ip_id: IpIdCounter::new(),
        })
    }

    /// Build the full IPv4+UDP packet for one frame to `dst` (forged source,
    /// per-packet TTL/DSCP/IP-ID, UDP checksum).
    fn build_packet(&self, frame: &[u8], dst: Ipv4Addr) -> Result<Vec<u8>> {
        let udp_len = 8 + frame.len();
        if udp_len > u16::MAX as usize {
            return Err(Error::transport("udp", "frame too large for one datagram"));
        }
        let mut seg = Vec::with_capacity(udp_len);
        seg.extend_from_slice(&self.src_port.to_be_bytes());
        seg.extend_from_slice(&self.dst_port.to_be_bytes());
        seg.extend_from_slice(&(udp_len as u16).to_be_bytes());
        seg.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
        seg.extend_from_slice(frame);

        let csum = udp_checksum(self.src, dst, &seg);
        // A computed 0 is transmitted as 0xFFFF (0 means "no checksum" in IPv4 UDP).
        let csum = if csum == 0 { 0xFFFF } else { csum };
        seg[6..8].copy_from_slice(&csum.to_be_bytes());

        Ok(ipv4::build(&Ipv4Build {
            src: self.src,
            dst,
            protocol: 17,
            ttl: super::pick(&self.ttl_pool, 64),
            tos: super::pick(&self.dscp_pool, 0),
            id: self.ip_id.next(),
            payload: &seg,
        }))
    }
}

#[async_trait]
impl Transport for UdpTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Udp
    }

    async fn send_frame(&self, frame: &[u8]) -> Result<()> {
        let dst = **self.dst.load();
        let pkt = self.build_packet(frame, dst)?;
        self.raw.send_to(&pkt, dst).await?;
        Ok(())
    }

    async fn send_batch(&self, frames: &[&[u8]]) -> Result<()> {
        if frames.len() < 2 {
            if let Some(f) = frames.first() {
                return self.send_frame(f).await;
            }
            return Ok(());
        }
        let dst = **self.dst.load();
        let pkts: Vec<Vec<u8>> = frames
            .iter()
            .map(|f| self.build_packet(f, dst))
            .collect::<Result<_>>()?;
        let refs: Vec<(&[u8], Ipv4Addr)> = pkts.iter().map(|p| (p.as_slice(), dst)).collect();
        self.raw.send_mmsg(&refs).await?;
        Ok(())
    }

    async fn recv_frame(&self, buf: &mut [u8]) -> Result<usize> {
        let (n, _src) = self
            .recv_sock
            .recv_from(buf)
            .await
            .map_err(|e| Error::transport("udp", format!("recv: {e}")))?;
        Ok(n)
    }

    async fn recv_frame_from(&self, buf: &mut [u8]) -> Result<(usize, Option<Ipv4Addr>)> {
        let (n, src) = self
            .recv_sock
            .recv_from(buf)
            .await
            .map_err(|e| Error::transport("udp", format!("recv: {e}")))?;
        let ip = match src {
            SocketAddr::V4(v4) => Some(*v4.ip()),
            SocketAddr::V6(_) => None,
        };
        Ok((n, ip))
    }

    fn set_peer(&self, dst: SocketAddrV4) {
        self.dst.store(std::sync::Arc::new(*dst.ip()));
    }

    fn supports_hop(&self) -> bool {
        true
    }
}

/// Compute the UDP checksum over the pseudo-header + segment.
fn udp_checksum(src: Ipv4Addr, dst: Ipv4Addr, seg: &[u8]) -> u16 {
    let s = src.octets();
    let d = dst.octets();
    let mut sum: u32 = 0;
    sum += u16::from_be_bytes([s[0], s[1]]) as u32;
    sum += u16::from_be_bytes([s[2], s[3]]) as u32;
    sum += u16::from_be_bytes([d[0], d[1]]) as u32;
    sum += u16::from_be_bytes([d[2], d[3]]) as u32;
    sum += 17u32; // zero byte + protocol
    sum += seg.len() as u32; // UDP length (again, in the pseudo-header)
    sum += checksum::sum16(seg);
    checksum::finalize(sum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_checksum_nonzero() {
        let seg = [0x30, 0x39, 0x00, 0x35, 0x00, 0x0a, 0x00, 0x00, 0x41, 0x42];
        let c = udp_checksum(
            Ipv4Addr::new(192, 168, 0, 1),
            Ipv4Addr::new(192, 168, 0, 2),
            &seg,
        );
        assert_ne!(c, 0);
    }
}
