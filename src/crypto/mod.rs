//! Cryptography: handshake, AEAD, anti-replay, rekey, key management.
//!
//! All primitives come from vetted crates (`snow`, `ml-kem`, RustCrypto
//! `chacha20poly1305`/`aes-gcm`, `hkdf`/`sha2`, `subtle`, `zeroize`). Nothing
//! cryptographic is hand-rolled.

pub mod aead;
pub mod handshake;
pub mod keyschedule;
pub mod pq;
pub mod replay;

use base64::Engine as _;
use zeroize::Zeroizing;

use crate::config::{AeadKind, Config, Role};
use crate::error::{Error, Result};

pub use aead::{DataCipher, KEY_LEN, NONCE_LEN, TAG_LEN};
pub use handshake::{HandshakeParams, HandshakeResult, Initiator, Responder};
pub use replay::ReplayWindow;

/// A freshly generated Noise static keypair, base64-encoded for config files.
pub struct StaticKeypair {
    /// base64 X25519 private key.
    pub private_b64: String,
    /// base64 X25519 public key.
    pub public_b64: String,
}

/// Generate a new Noise static (X25519) keypair for an endpoint.
pub fn generate_static_keypair() -> Result<StaticKeypair> {
    let params: snow::params::NoiseParams = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
        .parse()
        .map_err(|e| Error::handshake(format!("noise params: {e}")))?;
    let kp = snow::Builder::new(params)
        .generate_keypair()
        .map_err(|e| Error::handshake(format!("keygen: {e}")))?;
    let b64 = base64::engine::general_purpose::STANDARD;
    Ok(StaticKeypair {
        private_b64: b64.encode(kp.private),
        public_b64: b64.encode(kp.public),
    })
}

/// Decode a base64 32-byte key from config.
pub fn decode_key_b64(s: &str, what: &str) -> Result<[u8; 32]> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| Error::config(format!("{what}: invalid base64: {e}")))?;
    if raw.len() != 32 {
        return Err(Error::config(format!("{what}: must be 32 bytes")));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// Decode a hex 32-byte key (used for `allowed_peers`).
pub fn decode_key_hex(s: &str, what: &str) -> Result<[u8; 32]> {
    let raw =
        hex::decode(s.trim()).map_err(|e| Error::config(format!("{what}: invalid hex: {e}")))?;
    if raw.len() != 32 {
        return Err(Error::config(format!("{what}: must be 32 bytes")));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// Build [`HandshakeParams`] from a validated [`Config`] for this side.
pub fn handshake_params(cfg: &Config) -> Result<HandshakeParams> {
    let local_private = Zeroizing::new(decode_key_b64(
        &cfg.crypto.static_private_key,
        "static_private_key",
    )?);
    let peer_public = decode_key_b64(&cfg.crypto.peer_public_key, "peer_public_key")?;

    let psk = if cfg.crypto.pre_shared_key.trim().is_empty() {
        None
    } else {
        Some(keyschedule::derive_psk(&cfg.crypto.pre_shared_key))
    };

    // allowed_peers are hex X25519 public keys.
    let mut allowed_peers = Vec::with_capacity(cfg.spoof.allowed_peers.len());
    for p in &cfg.spoof.allowed_peers {
        allowed_peers.push(decode_key_hex(p, "allowed_peers")?);
    }

    Ok(HandshakeParams {
        local_private: *local_private,
        peer_public,
        psk,
        pq_hybrid: cfg.crypto.pq_hybrid,
        pq_level: cfg.crypto.pq_level,
        aead: cfg.crypto.aead,
        local_version: crate::PROTOCOL_VERSION,
        allowed_peers,
    })
}

/// The data-plane cipher state established for one session.
///
/// `tx` encrypts outbound frames; `rx` decrypts inbound ones. The directional
/// keys are assigned by role so both sides agree: the client sends on the
/// client→server key and receives on the server→client key, and vice versa.
pub struct SessionCrypto {
    /// Outbound AEAD.
    pub tx: DataCipher,
    /// Inbound AEAD.
    pub rx: DataCipher,
    /// Session identifier (non-secret; used in framing + migration).
    pub session_id: u64,
    /// Which AEAD construction is in use.
    pub aead: AeadKind,
    /// Whether the post-quantum hybrid was active for this session.
    pub pq_active: bool,
}

impl SessionCrypto {
    /// Wire up the directional ciphers from a completed handshake for `role`.
    pub fn from_handshake(role: Role, result: &HandshakeResult) -> Self {
        let (tx_key, rx_key) = match role {
            Role::Client => (&result.keys.c2s, &result.keys.s2c),
            Role::Server => (&result.keys.s2c, &result.keys.c2s),
        };
        SessionCrypto {
            tx: DataCipher::new(result.aead, tx_key),
            rx: DataCipher::new(result.aead, rx_key),
            session_id: result.keys.session_id,
            aead: result.aead,
            pq_active: result.pq_active,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_roundtrips_base64() {
        let kp = generate_static_keypair().unwrap();
        let priv_ = decode_key_b64(&kp.private_b64, "priv").unwrap();
        let pub_ = decode_key_b64(&kp.public_b64, "pub").unwrap();
        assert_eq!(priv_.len(), 32);
        assert_eq!(pub_.len(), 32);
    }
}
