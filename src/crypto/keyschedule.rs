//! Hybrid key schedule.
//!
//! The data-plane keys are derived with HKDF-SHA256 from material that is
//! secret under *either* primitive:
//!
//! ```text
//!   salt = Noise handshake hash  (public transcript binding)
//!   ikm  = seed_i || seed_r || kem_ss?
//!   key_c2s = HKDF-Expand(ikm, "freespoof v1 c2s")
//!   key_s2c = HKDF-Expand(ikm, "freespoof v1 s2c")
//!   session_id = HKDF-Expand(ikm, "freespoof v1 sid")
//! ```
//!
//! * `seed_i` / `seed_r` are 32 random bytes each, contributed by the two
//!   peers and transported **inside the Noise-encrypted handshake payloads**,
//!   so recovering them requires breaking the classical Noise handshake.
//! * `kem_ss` is the ML-KEM shared secret; recovering it requires breaking
//!   ML-KEM. The ciphertext/encapsulation key travel inside the same encrypted
//!   payloads but decapsulation needs the ephemeral ML-KEM secret, which never
//!   leaves the initiator.
//!
//! An attacker therefore needs to break **both** X25519 and ML-KEM to recover
//! the session keys — the hybrid property. When `pq_hybrid` is off, security
//! rests on the Noise handshake alone, which is still sound.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::aead::KEY_LEN;
use crate::error::{Error, Result};

/// Length in bytes of each contributed handshake seed.
pub const SEED_LEN: usize = 32;

/// The derived directional keys for one session. Zeroized on drop.
#[derive(ZeroizeOnDrop)]
pub struct DirectionalKeys {
    /// Client→server data key.
    pub c2s: [u8; KEY_LEN],
    /// Server→client data key.
    pub s2c: [u8; KEY_LEN],
    /// Session identifier (used for migration keying and logs). Not secret.
    #[zeroize(skip)]
    pub session_id: u64,
}

impl std::fmt::Debug for DirectionalKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key bytes.
        f.debug_struct("DirectionalKeys")
            .field("session_id", &format_args!("{:#018x}", self.session_id))
            .finish_non_exhaustive()
    }
}

/// Derive the directional keys from the handshake outputs.
pub fn derive(
    handshake_hash: &[u8],
    seed_i: &[u8; SEED_LEN],
    seed_r: &[u8; SEED_LEN],
    kem_ss: Option<&[u8; 32]>,
) -> Result<DirectionalKeys> {
    let mut ikm = Vec::with_capacity(SEED_LEN * 2 + 32);
    ikm.extend_from_slice(seed_i);
    ikm.extend_from_slice(seed_r);
    if let Some(k) = kem_ss {
        ikm.extend_from_slice(k);
    }

    let hk = Hkdf::<Sha256>::new(Some(handshake_hash), &ikm);
    ikm.zeroize();

    let mut c2s = [0u8; KEY_LEN];
    let mut s2c = [0u8; KEY_LEN];
    let mut sid = [0u8; 8];

    hk.expand(b"freespoof v1 c2s", &mut c2s)
        .map_err(|_| Error::crypto("hkdf expand c2s failed"))?;
    hk.expand(b"freespoof v1 s2c", &mut s2c)
        .map_err(|_| Error::crypto("hkdf expand s2c failed"))?;
    hk.expand(b"freespoof v1 sid", &mut sid)
        .map_err(|_| Error::crypto("hkdf expand sid failed"))?;

    Ok(DirectionalKeys {
        c2s,
        s2c,
        session_id: u64::from_be_bytes(sid),
    })
}

/// Derive a 32-byte Noise PSK from an operator passphrase or base64 key.
///
/// WireGuard-style: whatever the operator supplies (a passphrase or a 32-byte
/// base64 key) is hashed to exactly 32 bytes and mixed into the handshake via
/// the `psk2` modifier.
pub fn derive_psk(pre_shared_key: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"freespoof psk salt v1"), pre_shared_key.as_bytes());
    let mut psk = [0u8; 32];
    // Infallible for 32-byte output.
    let _ = hk.expand(b"freespoof v1 psk", &mut psk);
    psk
}

/// Lightweight symmetric ratchet used by the optional in-place rekey path
/// (the primary rekey mechanism is a fresh handshake, which also refreshes the
/// ephemeral ML-KEM material). `old` is consumed-by-value conceptually; the
/// caller zeroizes it.
pub fn ratchet(old: &[u8; KEY_LEN]) -> Result<[u8; KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(Some(b"freespoof ratchet v1"), old);
    let mut next = [0u8; KEY_LEN];
    hk.expand(b"freespoof v1 next", &mut next)
        .map_err(|_| Error::crypto("hkdf ratchet failed"))?;
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_agree() {
        let h = [0xABu8; 32];
        let si = [1u8; SEED_LEN];
        let sr = [2u8; SEED_LEN];
        let kem = [3u8; 32];
        let a = derive(&h, &si, &sr, Some(&kem)).unwrap();
        let b = derive(&h, &si, &sr, Some(&kem)).unwrap();
        assert_eq!(a.c2s, b.c2s);
        assert_eq!(a.s2c, b.s2c);
        assert_eq!(a.session_id, b.session_id);
        assert_ne!(a.c2s, a.s2c);
    }

    #[test]
    fn kem_changes_keys() {
        let h = [0u8; 32];
        let si = [1u8; SEED_LEN];
        let sr = [2u8; SEED_LEN];
        let without = derive(&h, &si, &sr, None).unwrap();
        let with = derive(&h, &si, &sr, Some(&[9u8; 32])).unwrap();
        assert_ne!(without.c2s, with.c2s);
    }
}
