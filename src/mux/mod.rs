//! Multiplexing: batch several inner packets into one wire frame.
//!
//! A batch body is a sequence of length-prefixed packets:
//!
//! ```text
//!   [ len:u16 | packet bytes ] [ len:u16 | packet bytes ] ...
//! ```
//!
//! The sender accumulates packets in a [`BatchAccumulator`] until it reaches
//! `multiplex_max_payload` or a flush deadline (`multiplex_flush_ms`, driven by
//! the session), then seals the whole batch as one `Data` frame with the
//! [`crate::wire::flags::MUX_BATCH`] flag set. The receiver splits it with
//! [`decode_batch`]. Multiplexing applies only to the datagram transports.

use crate::error::{Error, Result};

/// Per-packet length prefix width.
const LEN_PREFIX: usize = 2;

/// Accumulates inner packets into a length-prefixed batch buffer.
pub struct BatchAccumulator {
    buf: Vec<u8>,
    count: usize,
    max_payload: usize,
}

impl BatchAccumulator {
    /// Create an accumulator that flushes at `max_payload` encoded bytes.
    pub fn new(max_payload: usize) -> BatchAccumulator {
        BatchAccumulator {
            buf: Vec::with_capacity(max_payload.min(64 * 1024)),
            count: 0,
            max_payload,
        }
    }

    /// Number of packets currently buffered.
    pub fn len(&self) -> usize {
        self.count
    }

    /// True if no packets are buffered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Encoded size so far.
    pub fn encoded_len(&self) -> usize {
        self.buf.len()
    }

    /// Would appending `pkt_len` bytes exceed the flush threshold?
    pub fn would_overflow(&self, pkt_len: usize) -> bool {
        !self.is_empty() && self.buf.len() + LEN_PREFIX + pkt_len > self.max_payload
    }

    /// Append a packet. Packets longer than `u16::MAX` are rejected.
    pub fn push(&mut self, pkt: &[u8]) -> Result<()> {
        if pkt.len() > u16::MAX as usize {
            return Err(Error::decode("mux: packet too large to batch"));
        }
        self.buf
            .extend_from_slice(&(pkt.len() as u16).to_be_bytes());
        self.buf.extend_from_slice(pkt);
        self.count += 1;
        Ok(())
    }

    /// Take the encoded batch, resetting the accumulator. Returns `None` if empty.
    pub fn take(&mut self) -> Option<Vec<u8>> {
        if self.is_empty() {
            return None;
        }
        self.count = 0;
        Some(std::mem::take(&mut self.buf))
    }
}

/// Encode a set of packets into a single batch buffer.
pub fn encode_batch(packets: &[&[u8]]) -> Result<Vec<u8>> {
    let mut acc = BatchAccumulator::new(usize::MAX);
    for p in packets {
        acc.push(p)?;
    }
    Ok(acc.take().unwrap_or_default())
}

/// Strictly decode a batch body into its constituent packets. Never trusts the
/// length prefixes; every slice is bounds-checked.
pub fn decode_batch(body: &[u8]) -> Result<Vec<&[u8]>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < body.len() {
        if pos + LEN_PREFIX > body.len() {
            return Err(Error::decode("mux: truncated length prefix"));
        }
        let len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
        pos += LEN_PREFIX;
        let end = pos
            .checked_add(len)
            .ok_or_else(|| Error::decode("mux: length overflow"))?;
        if end > body.len() {
            return Err(Error::decode("mux: packet exceeds batch bounds"));
        }
        out.push(&body[pos..end]);
        pos = end;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_roundtrip() {
        let a = vec![1u8, 2, 3];
        let b = vec![9u8; 100];
        let c = vec![];
        let enc = encode_batch(&[&a, &b, &c]).unwrap();
        let dec = decode_batch(&enc).unwrap();
        assert_eq!(dec.len(), 3);
        assert_eq!(dec[0], &a[..]);
        assert_eq!(dec[1], &b[..]);
        assert_eq!(dec[2], &c[..]);
    }

    #[test]
    fn accumulator_overflow() {
        let mut acc = BatchAccumulator::new(16);
        assert!(!acc.would_overflow(10)); // empty never overflows
        acc.push(&[0u8; 10]).unwrap();
        assert!(acc.would_overflow(10)); // 2+10 + 2+10 > 16
        let batch = acc.take().unwrap();
        assert_eq!(decode_batch(&batch).unwrap().len(), 1);
        assert!(acc.take().is_none());
    }

    #[test]
    fn rejects_truncated() {
        assert!(decode_batch(&[0x00]).is_err()); // half a length prefix
        assert!(decode_batch(&[0x00, 0x05, 0x01]).is_err()); // claims 5, has 1
    }
}
