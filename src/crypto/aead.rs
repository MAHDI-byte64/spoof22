//! Per-frame authenticated encryption.
//!
//! Two AEAD constructions are supported, selected by config / auto-tune:
//! ChaCha20-Poly1305 (default, constant-time everywhere) and AES-256-GCM
//! (preferred when the CPU has AES-NI). Both use a 96-bit nonce built from a
//! strictly monotonic 64-bit counter.
//!
//! ## Nonce discipline
//!
//! Each *direction* of a session has its own key (derived separately in
//! [`super::keyschedule`]), so the per-direction counter alone guarantees the
//! nonce never repeats under a key. The counter is carried in the authenticated
//! wire header and verified by the anti-replay window on receive. If the
//! counter ever reached `u64::MAX` the sealer fails closed
//! ([`Error::Crypto`]) — but the rekey policy forces a new key long before
//! that is remotely possible.

use aes_gcm::Aes256Gcm;
use chacha20poly1305::aead::inout::InOutBuf;
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use zeroize::Zeroize;

use crate::config::AeadKind;
use crate::error::{Error, Result};

/// Poly1305 / GCM tag length in bytes.
pub const TAG_LEN: usize = 16;
/// AEAD key length in bytes (256-bit).
pub const KEY_LEN: usize = 32;
/// Nonce length in bytes (96-bit).
pub const NONCE_LEN: usize = 12;

/// A keyed AEAD ready to seal/open frames in one direction.
pub enum DataCipher {
    Chacha(Box<ChaCha20Poly1305>),
    Aes(Box<Aes256Gcm>),
}

impl DataCipher {
    /// Create a cipher from a 32-byte key. The key is cloned into the cipher
    /// state and the caller's copy should be zeroized by its owner.
    pub fn new(kind: AeadKind, key: &[u8; KEY_LEN]) -> Self {
        match kind {
            AeadKind::Chacha20Poly1305 => {
                DataCipher::Chacha(Box::new(ChaCha20Poly1305::new(key.into())))
            }
            AeadKind::Aes256Gcm => DataCipher::Aes(Box::new(Aes256Gcm::new(key.into()))),
        }
    }

    /// Build the 96-bit nonce from the direction counter: 4 zero bytes followed
    /// by the big-endian counter. Distinct counters ⇒ distinct nonces.
    #[inline]
    fn nonce(counter: u64) -> [u8; NONCE_LEN] {
        let mut n = [0u8; NONCE_LEN];
        n[4..].copy_from_slice(&counter.to_be_bytes());
        n
    }

    /// Seal `buf` in place: encrypt the plaintext and append the 16-byte tag.
    /// `aad` (the authenticated wire header) is authenticated but not encrypted.
    #[inline]
    pub fn seal(&self, counter: u64, aad: &[u8], buf: &mut Vec<u8>) -> Result<()> {
        if counter == u64::MAX {
            return Err(Error::crypto("nonce counter exhausted; rekey required"));
        }
        let nonce = Self::nonce(counter);
        let mut tag = [0u8; TAG_LEN];
        match self {
            DataCipher::Chacha(c) => {
                let t = c
                    .encrypt_inout_detached(
                        (&nonce).into(),
                        aad,
                        InOutBuf::from(buf.as_mut_slice()),
                    )
                    .map_err(|_| Error::crypto("chacha seal failed"))?;
                tag.copy_from_slice(t.as_slice());
            }
            DataCipher::Aes(c) => {
                let t = c
                    .encrypt_inout_detached(
                        (&nonce).into(),
                        aad,
                        InOutBuf::from(buf.as_mut_slice()),
                    )
                    .map_err(|_| Error::crypto("aes seal failed"))?;
                tag.copy_from_slice(t.as_slice());
            }
        };
        buf.extend_from_slice(&tag);
        Ok(())
    }

    /// Open `buf` in place: verify+decrypt, leaving plaintext in `buf` (tag
    /// stripped). Any failure is a droppable crypto error.
    #[inline]
    pub fn open(&self, counter: u64, aad: &[u8], buf: &mut Vec<u8>) -> Result<()> {
        if buf.len() < TAG_LEN {
            return Err(Error::crypto("frame shorter than AEAD tag"));
        }
        let nonce = Self::nonce(counter);
        let tag_start = buf.len() - TAG_LEN;
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&buf[tag_start..]);
        buf.truncate(tag_start);
        let res = match self {
            DataCipher::Chacha(c) => c.decrypt_inout_detached(
                (&nonce).into(),
                aad,
                InOutBuf::from(buf.as_mut_slice()),
                (&tag).into(),
            ),
            DataCipher::Aes(c) => c.decrypt_inout_detached(
                (&nonce).into(),
                aad,
                InOutBuf::from(buf.as_mut_slice()),
                (&tag).into(),
            ),
        };
        tag.zeroize();
        res.map_err(|_| Error::crypto("AEAD open/verify failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_chacha() {
        let key = [7u8; KEY_LEN];
        let c = DataCipher::new(AeadKind::Chacha20Poly1305, &key);
        let aad = b"header";
        let mut buf = b"hello world".to_vec();
        c.seal(1, aad, &mut buf).unwrap();
        assert_eq!(buf.len(), 11 + TAG_LEN);
        c.open(1, aad, &mut buf).unwrap();
        assert_eq!(&buf, b"hello world");
    }

    #[test]
    fn roundtrip_aes() {
        let key = [9u8; KEY_LEN];
        let c = DataCipher::new(AeadKind::Aes256Gcm, &key);
        let aad = b"h";
        let mut buf = vec![1, 2, 3, 4, 5];
        c.seal(42, aad, &mut buf).unwrap();
        c.open(42, aad, &mut buf).unwrap();
        assert_eq!(buf, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn wrong_counter_fails() {
        let key = [1u8; KEY_LEN];
        let c = DataCipher::new(AeadKind::Chacha20Poly1305, &key);
        let mut buf = b"data".to_vec();
        c.seal(1, b"", &mut buf).unwrap();
        assert!(c.open(2, b"", &mut buf).is_err());
    }

    #[test]
    fn tampered_aad_fails() {
        let key = [2u8; KEY_LEN];
        let c = DataCipher::new(AeadKind::Aes256Gcm, &key);
        let mut buf = b"data".to_vec();
        c.seal(1, b"aad1", &mut buf).unwrap();
        assert!(c.open(1, b"aad2", &mut buf).is_err());
    }
}
