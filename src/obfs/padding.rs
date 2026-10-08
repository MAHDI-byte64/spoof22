//! Low-level length obfuscation: random padding and pad-to-fixed-size.
//!
//! Padding is applied to the plaintext payload *before* sealing, so it changes
//! the on-wire ciphertext length and defeats naive length fingerprinting. The
//! padded layout is:
//!
//! ```text
//!   [ payload ][ random pad (k bytes) ][ k : u16 big-endian ]
//! ```
//!
//! The [`crate::wire::flags::PADDED`] flag tells the receiver to strip it. Only
//! padded frames are unpadded, so a zero-pad frame is never misread.

use rand::Rng;

/// Trailing pad-length field width.
const PAD_LEN_FIELD: usize = 2;

/// Padding policy derived from config.
#[derive(Debug, Clone, Copy)]
pub struct PadPolicy {
    /// Minimum random pad bytes (0 disables random padding).
    pub min: usize,
    /// Maximum random pad bytes.
    pub max: usize,
    /// Pad the whole padded payload up to this fixed size (0 disables).
    pub pad_to: usize,
}

impl PadPolicy {
    /// True if any padding is active.
    pub fn active(&self) -> bool {
        self.max > 0 || self.pad_to > 0
    }

    /// Produce the padded payload. Returns `None` if no padding was applied.
    pub fn apply(&self, payload: &[u8]) -> Option<Vec<u8>> {
        if !self.active() {
            return None;
        }
        let mut rng = rand::thread_rng();
        let mut k = if self.max > 0 {
            rng.gen_range(self.min.max(1)..=self.max)
        } else {
            0
        };

        // Pad-to-fixed-size: grow k so the final length (payload+pad+field)
        // reaches `pad_to`, if that is larger.
        if self.pad_to > 0 {
            let target = self.pad_to.saturating_sub(payload.len() + PAD_LEN_FIELD);
            if target > k {
                k = target;
            }
        }
        if k > u16::MAX as usize {
            k = u16::MAX as usize;
        }

        let mut out = Vec::with_capacity(payload.len() + k + PAD_LEN_FIELD);
        out.extend_from_slice(payload);
        let start = out.len();
        out.resize(start + k, 0);
        rng.fill(&mut out[start..]);
        out.extend_from_slice(&(k as u16).to_be_bytes());
        Some(out)
    }
}

/// Strip padding from a decrypted, PADDED-flagged payload. Returns the original
/// payload slice, or `None` if the trailer is malformed (caller drops).
pub fn strip(buf: &[u8]) -> Option<&[u8]> {
    if buf.len() < PAD_LEN_FIELD {
        return None;
    }
    let k = u16::from_be_bytes([buf[buf.len() - 2], buf[buf.len() - 1]]) as usize;
    let total_trailer = k + PAD_LEN_FIELD;
    if total_trailer > buf.len() {
        return None;
    }
    Some(&buf[..buf.len() - total_trailer])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_random() {
        let p = PadPolicy {
            min: 1,
            max: 32,
            pad_to: 0,
        };
        let payload = b"the quick brown fox";
        let padded = p.apply(payload).unwrap();
        assert!(padded.len() > payload.len());
        assert_eq!(strip(&padded).unwrap(), payload);
    }

    #[test]
    fn pad_to_fixed_size() {
        let p = PadPolicy {
            min: 0,
            max: 0,
            pad_to: 256,
        };
        let payload = vec![7u8; 40];
        let padded = p.apply(&payload).unwrap();
        assert_eq!(padded.len(), 256);
        assert_eq!(strip(&padded).unwrap(), &payload[..]);
    }

    #[test]
    fn disabled_returns_none() {
        let p = PadPolicy {
            min: 0,
            max: 0,
            pad_to: 0,
        };
        assert!(p.apply(b"x").is_none());
    }

    #[test]
    fn malformed_trailer_rejected() {
        assert!(strip(&[0x00]).is_none());
        assert!(strip(&[0xFF, 0xFF]).is_none()); // claims 65535 pad in 2 bytes
    }
}
