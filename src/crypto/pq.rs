//! Post-quantum ML-KEM (FIPS 203) wrapper for the hybrid handshake.
//!
//! The initiator generates an **ephemeral** ML-KEM keypair per handshake and
//! sends the encapsulation key inside the (Noise-encrypted) first message. The
//! responder encapsulates to it, derives a shared secret, and returns the
//! ciphertext inside the (Noise-encrypted) second message. The initiator
//! decapsulates with its ephemeral secret key, which never leaves the process.
//!
//! Because the keypair is ephemeral, the PQ layer provides forward secrecy as
//! well as quantum resistance. The shared secret is mixed into the data-plane
//! key schedule (see [`super::keyschedule`]).

use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem1024, MlKem512, MlKem768};
use zeroize::Zeroizing;

use crate::config::PqLevel;
use crate::error::{Error, Result};

/// Ephemeral ML-KEM decapsulation key held by the initiator between the two
/// handshake messages. Boxed because the 1024 key is multiple KiB. The
/// underlying `ml-kem` key type zeroizes its secret on drop.
pub enum PqDecapKey {
    K512(Box<<MlKem512 as KemCore>::DecapsulationKey>),
    K768(Box<<MlKem768 as KemCore>::DecapsulationKey>),
    K1024(Box<<MlKem1024 as KemCore>::DecapsulationKey>),
}

/// A 32-byte ML-KEM shared secret, zeroized on drop.
pub type PqSharedSecret = Zeroizing<[u8; 32]>;

/// Serialized ML-KEM sizes `(encapsulation_key_len, ciphertext_len)` for a
/// level — used by the MTU accounting and config diagnostics.
pub fn sizes(level: PqLevel) -> (usize, usize) {
    match level {
        PqLevel::MlKem512 => (800, 768),
        PqLevel::MlKem768 => (1184, 1088),
        PqLevel::MlKem1024 => (1568, 1568),
    }
}

/// Initiator step 1: generate an ephemeral keypair. Returns the decapsulation
/// key handle (kept for step 2) and the serialized encapsulation key to send.
pub fn generate(level: PqLevel) -> (PqDecapKey, Vec<u8>) {
    let mut rng = rand::thread_rng();
    match level {
        PqLevel::MlKem512 => {
            let (dk, ek) = MlKem512::generate(&mut rng);
            (PqDecapKey::K512(Box::new(dk)), ek.as_bytes().to_vec())
        }
        PqLevel::MlKem768 => {
            let (dk, ek) = MlKem768::generate(&mut rng);
            (PqDecapKey::K768(Box::new(dk)), ek.as_bytes().to_vec())
        }
        PqLevel::MlKem1024 => {
            let (dk, ek) = MlKem1024::generate(&mut rng);
            (PqDecapKey::K1024(Box::new(dk)), ek.as_bytes().to_vec())
        }
    }
}

/// Responder step: encapsulate to the peer's encapsulation key. Returns the
/// serialized ciphertext to send and the shared secret.
pub fn encapsulate(level: PqLevel, ek_bytes: &[u8]) -> Result<(Vec<u8>, PqSharedSecret)> {
    match level {
        PqLevel::MlKem512 => encap::<MlKem512>(ek_bytes),
        PqLevel::MlKem768 => encap::<MlKem768>(ek_bytes),
        PqLevel::MlKem1024 => encap::<MlKem1024>(ek_bytes),
    }
}

fn encap<K: KemCore>(ek_bytes: &[u8]) -> Result<(Vec<u8>, PqSharedSecret)> {
    let mut rng = rand::thread_rng();
    let enc = Encoded::<K::EncapsulationKey>::try_from(ek_bytes)
        .map_err(|_| Error::handshake("ML-KEM encapsulation key has wrong length"))?;
    let ek = K::EncapsulationKey::from_bytes(&enc);
    let (ct, ss) = ek
        .encapsulate(&mut rng)
        .map_err(|_| Error::handshake("ML-KEM encapsulate failed"))?;
    // ML-KEM shared secrets are always 32 bytes; copy via slice so the generic
    // code doesn't need to prove `SharedKeySize == U32` at the type level.
    let ssb = ss.as_slice();
    if ssb.len() != 32 {
        return Err(Error::handshake("unexpected ML-KEM shared-secret size"));
    }
    let mut ss_arr = [0u8; 32];
    ss_arr.copy_from_slice(ssb);
    Ok((ct.to_vec(), Zeroizing::new(ss_arr)))
}

/// Initiator step 2: decapsulate the responder's ciphertext to recover the
/// shared secret.
pub fn decapsulate(dk: &PqDecapKey, ct_bytes: &[u8]) -> Result<PqSharedSecret> {
    let ss: [u8; 32] = match dk {
        PqDecapKey::K512(k) => {
            let ct = Ciphertext::<MlKem512>::try_from(ct_bytes)
                .map_err(|_| Error::handshake("ML-KEM ciphertext has wrong length"))?;
            k.decapsulate(&ct)
                .map_err(|_| Error::handshake("ML-KEM decapsulate failed"))?
                .into()
        }
        PqDecapKey::K768(k) => {
            let ct = Ciphertext::<MlKem768>::try_from(ct_bytes)
                .map_err(|_| Error::handshake("ML-KEM ciphertext has wrong length"))?;
            k.decapsulate(&ct)
                .map_err(|_| Error::handshake("ML-KEM decapsulate failed"))?
                .into()
        }
        PqDecapKey::K1024(k) => {
            let ct = Ciphertext::<MlKem1024>::try_from(ct_bytes)
                .map_err(|_| Error::handshake("ML-KEM ciphertext has wrong length"))?;
            k.decapsulate(&ct)
                .map_err(|_| Error::handshake("ML-KEM decapsulate failed"))?
                .into()
        }
    };
    Ok(Zeroizing::new(ss))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_kem_agrees_all_levels() {
        for level in [PqLevel::MlKem512, PqLevel::MlKem768, PqLevel::MlKem1024] {
            let (dk, ek) = generate(level);
            let (ct, ss_r) = encapsulate(level, &ek).unwrap();
            let ss_i = decapsulate(&dk, &ct).unwrap();
            assert_eq!(*ss_i, *ss_r);
            let (ek_len, ct_len) = sizes(level);
            assert_eq!(ek.len(), ek_len);
            assert_eq!(ct.len(), ct_len);
        }
    }

    #[test]
    fn bad_ciphertext_length_errors() {
        let (dk, _ek) = generate(PqLevel::MlKem768);
        assert!(decapsulate(&dk, &[0u8; 10]).is_err());
    }
}
