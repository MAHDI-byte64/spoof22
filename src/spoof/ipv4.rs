//! IPv4 header construction (with a forged source) and strict, bounds-checked
//! parsing of received packets.
//!
//! The parser is treated as hostile-input code: it never trusts the length or
//! IHL fields, clamps everything to the actual buffer, and returns
//! [`Error::decode`] on any inconsistency instead of indexing out of range.

use std::net::Ipv4Addr;

use crate::error::{Error, Result};
use crate::spoof::checksum;

/// Minimum IPv4 header length (no options).
pub const IPV4_MIN_HEADER: usize = 20;

/// Don't-Fragment bit position in the flags/fragment-offset word.
pub const DF_BIT: u16 = 0x4000;

/// Parameters for building one outgoing raw IPv4 packet.
pub struct Ipv4Build<'a> {
    /// Forged source address.
    pub src: Ipv4Addr,
    /// Real destination (the peer's real address).
    pub dst: Ipv4Addr,
    /// IP protocol number.
    pub protocol: u8,
    /// Time-to-live.
    pub ttl: u8,
    /// Full TOS/DSCP byte.
    pub tos: u8,
    /// Identification field (IP-ID). DF is always cleared to avoid PMTU holes.
    pub id: u16,
    /// L4 payload.
    pub payload: &'a [u8],
}

/// Build a complete IPv4 packet (header + payload) into a fresh `Vec`.
///
/// The DF bit is cleared (fragmentation permitted) per the MTU strategy; the
/// header checksum is computed here (the kernel would also fill it under
/// `IP_HDRINCL`, but we keep full control and determinism).
pub fn build(p: &Ipv4Build<'_>) -> Vec<u8> {
    let total_len = (IPV4_MIN_HEADER + p.payload.len()) as u16;
    let mut buf = Vec::with_capacity(total_len as usize);

    buf.push(0x45); // version 4, IHL 5
    buf.push(p.tos);
    buf.extend_from_slice(&total_len.to_be_bytes());
    buf.extend_from_slice(&p.id.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes()); // flags=0 (DF cleared) + frag offset 0
    buf.push(p.ttl);
    buf.push(p.protocol);
    buf.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    buf.extend_from_slice(&p.src.octets());
    buf.extend_from_slice(&p.dst.octets());

    // Checksum covers the 20-byte header only.
    let csum = checksum::checksum(&buf[..IPV4_MIN_HEADER]);
    buf[10..12].copy_from_slice(&csum.to_be_bytes());

    buf.extend_from_slice(p.payload);
    buf
}

/// A validated view into a received IPv4 packet.
#[derive(Debug, Clone, Copy)]
pub struct Ipv4View<'a> {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub protocol: u8,
    pub ttl: u8,
    pub tos: u8,
    pub id: u16,
    /// Header length in bytes (IHL * 4).
    pub header_len: usize,
    /// The L4 payload (bounded to the real buffer, length field clamped).
    pub payload: &'a [u8],
}

/// Strictly parse an IPv4 packet. Rejects anything malformed.
pub fn parse(buf: &[u8]) -> Result<Ipv4View<'_>> {
    if buf.len() < IPV4_MIN_HEADER {
        return Err(Error::decode("ipv4: shorter than minimum header"));
    }
    let version = buf[0] >> 4;
    if version != 4 {
        return Err(Error::decode("ipv4: not version 4"));
    }
    let ihl = (buf[0] & 0x0F) as usize;
    if ihl < 5 {
        return Err(Error::decode("ipv4: IHL < 5"));
    }
    let header_len = ihl * 4;
    if header_len > buf.len() {
        return Err(Error::decode("ipv4: header length exceeds buffer"));
    }
    let tos = buf[1];
    let total_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let id = u16::from_be_bytes([buf[4], buf[5]]);
    let ttl = buf[8];
    let protocol = buf[9];
    let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    let dst = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);

    // Never trust total_len: clamp the payload to what we actually received.
    let claimed_end = total_len.clamp(header_len, buf.len());
    let payload = &buf[header_len..claimed_end];

    Ok(Ipv4View {
        src,
        dst,
        protocol,
        ttl,
        tos,
        id,
        header_len,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_and_parse_roundtrip() {
        let payload = b"hello";
        let pkt = build(&Ipv4Build {
            src: Ipv4Addr::new(1, 2, 3, 4),
            dst: Ipv4Addr::new(5, 6, 7, 8),
            protocol: 17,
            ttl: 64,
            tos: 0x28,
            id: 0xABCD,
            payload,
        });
        let v = parse(&pkt).unwrap();
        assert_eq!(v.src, Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(v.dst, Ipv4Addr::new(5, 6, 7, 8));
        assert_eq!(v.protocol, 17);
        assert_eq!(v.ttl, 64);
        assert_eq!(v.tos, 0x28);
        assert_eq!(v.id, 0xABCD);
        assert_eq!(v.payload, payload);
        // Header checksum must verify to zero over the header.
        assert_eq!(checksum::checksum(&pkt[..IPV4_MIN_HEADER]), 0);
    }

    #[test]
    fn rejects_truncated() {
        assert!(parse(&[0x45, 0, 0]).is_err());
    }

    #[test]
    fn clamps_lying_total_length() {
        let mut pkt = build(&Ipv4Build {
            src: Ipv4Addr::LOCALHOST,
            dst: Ipv4Addr::LOCALHOST,
            protocol: 1,
            ttl: 1,
            tos: 0,
            id: 1,
            payload: b"ab",
        });
        // Lie: claim total length 60000.
        pkt[2..4].copy_from_slice(&60000u16.to_be_bytes());
        let v = parse(&pkt).unwrap();
        assert_eq!(v.payload.len(), 2); // clamped to real buffer
    }
}
