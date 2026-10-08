//! Internet checksum (RFC 1071) for IPv4 / ICMP headers.
//!
//! A straightforward 16-bit ones-complement sum. Written as a tight loop so
//! that `-C target-cpu=native` can auto-vectorize it (AVX2/AVX-512/NEON); the
//! scalar form here is correct on every target and is the fallback.

/// Compute the ones-complement 16-bit checksum over `data`.
///
/// Returns the folded value in host order (not yet negated); use
/// [`finalize`] to produce the on-wire checksum.
#[inline]
pub fn sum16(data: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    sum
}

/// Fold a 32-bit accumulator into 16 bits and take the ones-complement.
#[inline]
pub fn finalize(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Full internet checksum of a buffer.
#[inline]
pub fn checksum(data: &[u8]) -> u16 {
    finalize(sum16(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_ipv4_header_checksum() {
        // RFC 1071 / classic worked example header (checksum field zeroed).
        let hdr: [u8; 20] = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        let c = checksum(&hdr);
        assert_eq!(c, 0xb861);
    }

    #[test]
    fn odd_length() {
        let data = [0x11, 0x22, 0x33];
        let _ = checksum(&data); // must not panic
    }
}
