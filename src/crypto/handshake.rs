//! Mutually-authenticated handshake: Noise_IK (X25519) + optional ML-KEM hybrid.
//!
//! * **Authentication & classical FS** come from Noise_IK (both static keys are
//!   authenticated; the ephemeral DH gives forward secrecy). An optional
//!   operator PSK is mixed via the `IKpsk2` modifier (WireGuard-style).
//! * **Post-quantum FS** comes from an ephemeral ML-KEM exchange whose
//!   encapsulation key / ciphertext ride inside the Noise-encrypted payloads.
//! * Both peers contribute a 32-byte seed inside those same encrypted payloads;
//!   the data-plane keys are derived from the seeds ⊕ KEM secret (see
//!   [`super::keyschedule`]).
//! * The protocol version is carried in the payloads and compared explicitly,
//!   so a mismatch yields a clean [`Error::VersionMismatch`] rather than an
//!   opaque MAC failure.
//!
//! The handshake is transport-agnostic: it produces/consumes opaque byte
//! messages that the session layer ships over whatever transport is active.

use subtle::ConstantTimeEq;

use crate::config::{AeadKind, PqLevel};
use crate::crypto::keyschedule::{self, DirectionalKeys, SEED_LEN};
use crate::crypto::pq::{self, PqDecapKey};
use crate::error::{Error, Result};

/// Stable prologue bound into the Noise transcript (protocol-major scoped).
const PROLOGUE: &[u8] = b"freespoof-noise-prologue-v1";

/// Flag bit: initiator offers the ML-KEM hybrid.
const FLAG_PQ: u8 = 0b0000_0001;

/// Scratch buffer size for Noise read/write (payload + overhead, fits ML-KEM-1024).
const NOISE_BUF: usize = 4096;

/// Inputs shared by both handshake roles.
#[derive(Clone)]
pub struct HandshakeParams {
    /// Our Noise static private key (X25519).
    pub local_private: [u8; 32],
    /// The peer's Noise static public key (required by IK; also the fallback
    /// authorization identity when `allowed_peers` is empty).
    pub peer_public: [u8; 32],
    /// Optional 32-byte PSK (already derived from the operator secret).
    pub psk: Option<[u8; 32]>,
    /// Whether this side is willing to run the ML-KEM hybrid.
    pub pq_hybrid: bool,
    /// ML-KEM parameter set to use when the hybrid is active.
    pub pq_level: PqLevel,
    /// Per-frame AEAD this side wants to use (carried for the peer's info).
    pub aead: AeadKind,
    /// This side's wire protocol version.
    pub local_version: u8,
    /// Responder authorization set (X25519 public keys). Empty = only accept
    /// the single configured `peer_public`.
    pub allowed_peers: Vec<[u8; 32]>,
}

/// The negotiated outcome of a completed handshake.
pub struct HandshakeResult {
    /// Derived directional data-plane keys (zeroized on drop).
    pub keys: DirectionalKeys,
    /// The peer's authenticated static public key.
    pub peer_static: [u8; 32],
    /// Negotiated wire protocol version (== local after a successful check).
    pub negotiated_version: u8,
    /// Whether the ML-KEM hybrid was actually used.
    pub pq_active: bool,
    /// Per-frame AEAD to use on the data plane.
    pub aead: AeadKind,
}

/// Build a `snow` builder/params for the chosen pattern.
fn noise_params(psk: bool) -> Result<snow::params::NoiseParams> {
    let s = if psk {
        "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
    } else {
        "Noise_IK_25519_ChaChaPoly_BLAKE2s"
    };
    s.parse()
        .map_err(|e| Error::handshake(format!("invalid noise params: {e}")))
}

/// Constant-time 32-byte equality.
fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).into()
}

// ---------------------------------------------------------------------------
// Payload encoding (inside the Noise-encrypted messages)
// ---------------------------------------------------------------------------

/// msg1 payload: `magic(4) | version(1) | flags(1) | pq_level(1) | seed_i(32) | ek_len(2) | ek`
fn encode_msg1(
    version: u8,
    pq: bool,
    level: PqLevel,
    seed_i: &[u8; SEED_LEN],
    ek: &[u8],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + 3 + SEED_LEN + 2 + ek.len());
    v.extend_from_slice(&crate::HANDSHAKE_MAGIC);
    v.push(version);
    v.push(if pq { FLAG_PQ } else { 0 });
    v.push(pq_level_code(level));
    v.extend_from_slice(seed_i);
    v.extend_from_slice(&(ek.len() as u16).to_be_bytes());
    v.extend_from_slice(ek);
    v
}

struct Msg1 {
    version: u8,
    pq: bool,
    level: PqLevel,
    seed_i: [u8; SEED_LEN],
    ek: Vec<u8>,
}

/// Strict, bounds-checked decode of the msg1 payload.
fn decode_msg1(buf: &[u8]) -> Result<Msg1> {
    let mut r = Reader::new(buf);
    let magic = r.take(4)?;
    if magic != crate::HANDSHAKE_MAGIC {
        return Err(Error::handshake("handshake magic mismatch"));
    }
    let version = r.u8()?;
    let flags = r.u8()?;
    let level = pq_level_from_code(r.u8()?)?;
    let mut seed_i = [0u8; SEED_LEN];
    seed_i.copy_from_slice(r.take(SEED_LEN)?);
    let ek_len = r.u16()? as usize;
    let ek = r.take(ek_len)?.to_vec();
    Ok(Msg1 {
        version,
        pq: flags & FLAG_PQ != 0,
        level,
        seed_i,
        ek,
    })
}

/// msg2 payload: `version(1) | seed_r(32) | ct_len(2) | ct`
fn encode_msg2(version: u8, seed_r: &[u8; SEED_LEN], ct: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + SEED_LEN + 2 + ct.len());
    v.push(version);
    v.extend_from_slice(seed_r);
    v.extend_from_slice(&(ct.len() as u16).to_be_bytes());
    v.extend_from_slice(ct);
    v
}

struct Msg2 {
    version: u8,
    seed_r: [u8; SEED_LEN],
    ct: Vec<u8>,
}

fn decode_msg2(buf: &[u8]) -> Result<Msg2> {
    let mut r = Reader::new(buf);
    let version = r.u8()?;
    let mut seed_r = [0u8; SEED_LEN];
    seed_r.copy_from_slice(r.take(SEED_LEN)?);
    let ct_len = r.u16()? as usize;
    let ct = r.take(ct_len)?.to_vec();
    Ok(Msg2 {
        version,
        seed_r,
        ct,
    })
}

fn pq_level_code(l: PqLevel) -> u8 {
    match l {
        PqLevel::MlKem512 => 1,
        PqLevel::MlKem768 => 2,
        PqLevel::MlKem1024 => 3,
    }
}
fn pq_level_from_code(c: u8) -> Result<PqLevel> {
    match c {
        1 => Ok(PqLevel::MlKem512),
        2 => Ok(PqLevel::MlKem768),
        3 => Ok(PqLevel::MlKem1024),
        other => Err(Error::handshake(format!(
            "unknown ML-KEM level code {other}"
        ))),
    }
}

/// Minimal bounds-checked byte reader — the handshake's untrusted-input parser.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| Error::handshake("length overflow"))?;
        if end > self.buf.len() {
            return Err(Error::handshake("handshake payload truncated"));
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
}

// ---------------------------------------------------------------------------
// Initiator (client)
// ---------------------------------------------------------------------------

/// Initiator-side handshake driver.
pub struct Initiator {
    state: snow::HandshakeState,
    params: HandshakeParams,
    seed_i: [u8; SEED_LEN],
    dk: Option<PqDecapKey>,
    pq_offered: bool,
}

impl Initiator {
    /// Start the handshake, returning the first message to send.
    pub fn start(params: HandshakeParams) -> Result<(Initiator, Vec<u8>)> {
        let mut builder = snow::Builder::new(noise_params(params.psk.is_some())?)
            .local_private_key(&params.local_private)
            .map_err(|e| Error::handshake(format!("set local key: {e}")))?
            .remote_public_key(&params.peer_public)
            .map_err(|e| Error::handshake(format!("set remote key: {e}")))?
            .prologue(PROLOGUE)
            .map_err(|e| Error::handshake(format!("set prologue: {e}")))?;
        if let Some(psk) = &params.psk {
            builder = builder
                .psk(2, psk)
                .map_err(|e| Error::handshake(format!("set psk: {e}")))?;
        }
        let mut state = builder
            .build_initiator()
            .map_err(|e| Error::handshake(format!("build init: {e}")))?;

        // Contribute a seed and (optionally) an ephemeral ML-KEM keypair.
        let mut seed_i = [0u8; SEED_LEN];
        getrandom::getrandom(&mut seed_i).map_err(|e| Error::handshake(format!("rng: {e}")))?;
        let (dk, ek) = if params.pq_hybrid {
            let (dk, ek) = pq::generate(params.pq_level);
            (Some(dk), ek)
        } else {
            (None, Vec::new())
        };

        let pq_offered = params.pq_hybrid;
        let payload = encode_msg1(
            params.local_version,
            params.pq_hybrid,
            params.pq_level,
            &seed_i,
            &ek,
        );
        let mut out = vec![0u8; NOISE_BUF + payload.len()];
        let n = state
            .write_message(&payload, &mut out)
            .map_err(|e| Error::handshake(format!("write msg1: {e}")))?;
        out.truncate(n);

        Ok((
            Initiator {
                state,
                params,
                seed_i,
                dk,
                pq_offered,
            },
            out,
        ))
    }

    /// Finish the handshake given the responder's reply.
    pub fn finish(mut self, msg2: &[u8]) -> Result<HandshakeResult> {
        let mut out = vec![0u8; NOISE_BUF.max(msg2.len())];
        let n = self
            .state
            .read_message(msg2, &mut out)
            .map_err(|e| Error::handshake(format!("read msg2: {e}")))?;
        out.truncate(n);
        let m2 = decode_msg2(&out)?;

        if m2.version != self.params.local_version {
            return Err(Error::VersionMismatch {
                local: self.params.local_version,
                peer: m2.version,
            });
        }

        // Recover the PQ shared secret, if the hybrid was offered & answered.
        let pq_active = self.pq_offered && !m2.ct.is_empty();
        let kem_ss = if pq_active {
            let dk = self
                .dk
                .as_ref()
                .ok_or_else(|| Error::handshake("missing ML-KEM key"))?;
            Some(pq::decapsulate(dk, &m2.ct)?)
        } else {
            None
        };

        if !self.state.is_handshake_finished() {
            return Err(Error::handshake("initiator handshake did not complete"));
        }
        let h = self.state.get_handshake_hash().to_vec();
        let peer_static = remote_static(&self.state)?;
        // IK pins the responder's static to the configured key.
        if !ct_eq(&peer_static, &self.params.peer_public) {
            return Err(Error::handshake("responder static key mismatch"));
        }

        let keys = keyschedule::derive(&h, &self.seed_i, &m2.seed_r, kem_ss.as_deref())?;

        Ok(HandshakeResult {
            keys,
            peer_static,
            negotiated_version: m2.version,
            pq_active,
            aead: self.params.aead,
        })
    }
}

// ---------------------------------------------------------------------------
// Responder (server)
// ---------------------------------------------------------------------------

/// Responder-side handshake driver.
pub struct Responder {
    state: snow::HandshakeState,
    params: HandshakeParams,
}

impl Responder {
    /// Create a responder state (call before the first message arrives).
    pub fn start(params: HandshakeParams) -> Result<Responder> {
        let mut builder = snow::Builder::new(noise_params(params.psk.is_some())?)
            .local_private_key(&params.local_private)
            .map_err(|e| Error::handshake(format!("set local key: {e}")))?
            .prologue(PROLOGUE)
            .map_err(|e| Error::handshake(format!("set prologue: {e}")))?;
        if let Some(psk) = &params.psk {
            builder = builder
                .psk(2, psk)
                .map_err(|e| Error::handshake(format!("set psk: {e}")))?;
        }
        let state = builder
            .build_responder()
            .map_err(|e| Error::handshake(format!("build resp: {e}")))?;
        Ok(Responder { state, params })
    }

    /// Process the initiator's first message and produce the reply + result.
    pub fn respond(mut self, msg1: &[u8]) -> Result<(Vec<u8>, HandshakeResult)> {
        let mut out = vec![0u8; NOISE_BUF.max(msg1.len())];
        let n = self
            .state
            .read_message(msg1, &mut out)
            .map_err(|e| Error::handshake(format!("read msg1: {e}")))?;
        out.truncate(n);
        let m1 = decode_msg1(&out)?;

        if m1.version != self.params.local_version {
            return Err(Error::VersionMismatch {
                local: self.params.local_version,
                peer: m1.version,
            });
        }

        // Authorize the peer by its authenticated static key (NEVER by the
        // forged source address). Fail-closed: unknown peers are rejected so
        // the caller can drop silently or divert to the decoy.
        let peer_static = remote_static(&self.state)?;
        if !self.authorized(&peer_static) {
            return Err(Error::Unauthenticated);
        }

        // PQ is active only if the initiator offered it AND we're willing.
        let pq_active = m1.pq && self.params.pq_hybrid && !m1.ek.is_empty();
        let (ct, kem_ss) = if pq_active {
            let (ct, ss) = pq::encapsulate(m1.level, &m1.ek)?;
            (ct, Some(ss))
        } else {
            (Vec::new(), None)
        };

        let mut seed_r = [0u8; SEED_LEN];
        getrandom::getrandom(&mut seed_r).map_err(|e| Error::handshake(format!("rng: {e}")))?;

        let payload = encode_msg2(self.params.local_version, &seed_r, &ct);
        let mut msg2 = vec![0u8; NOISE_BUF + payload.len()];
        let n = self
            .state
            .write_message(&payload, &mut msg2)
            .map_err(|e| Error::handshake(format!("write msg2: {e}")))?;
        msg2.truncate(n);

        if !self.state.is_handshake_finished() {
            return Err(Error::handshake("responder handshake did not complete"));
        }
        let h = self.state.get_handshake_hash().to_vec();

        let keys = keyschedule::derive(&h, &m1.seed_i, &seed_r, kem_ss.as_deref())?;

        let result = HandshakeResult {
            keys,
            peer_static,
            negotiated_version: m1.version,
            pq_active,
            aead: self.params.aead,
        };
        Ok((msg2, result))
    }

    /// Is this peer static key authorized?
    fn authorized(&self, peer_static: &[u8; 32]) -> bool {
        if self.params.allowed_peers.is_empty() {
            ct_eq(peer_static, &self.params.peer_public)
        } else {
            self.params
                .allowed_peers
                .iter()
                .any(|p| ct_eq(p, peer_static))
        }
    }
}

/// Extract the peer's static public key from a snow state as a fixed array.
fn remote_static(state: &snow::HandshakeState) -> Result<[u8; 32]> {
    let rs = state
        .get_remote_static()
        .ok_or_else(|| Error::handshake("no remote static key"))?;
    if rs.len() != 32 {
        return Err(Error::handshake("remote static key wrong length"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(rs);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> ([u8; 32], [u8; 32]) {
        let kp = snow::Builder::new(noise_params(false).unwrap().clone())
            .generate_keypair()
            .unwrap();
        let mut priv_ = [0u8; 32];
        let mut pub_ = [0u8; 32];
        priv_.copy_from_slice(&kp.private);
        pub_.copy_from_slice(&kp.public);
        (priv_, pub_)
    }

    fn run(pq: bool, psk: Option<[u8; 32]>) {
        let (c_priv, c_pub) = keypair();
        let (s_priv, s_pub) = keypair();

        let cp = HandshakeParams {
            local_private: c_priv,
            peer_public: s_pub,
            psk,
            pq_hybrid: pq,
            pq_level: PqLevel::MlKem768,
            aead: AeadKind::Chacha20Poly1305,
            local_version: 1,
            allowed_peers: vec![],
        };
        let sp = HandshakeParams {
            local_private: s_priv,
            peer_public: c_pub, // responder authorizes against client pub
            psk,
            pq_hybrid: pq,
            pq_level: PqLevel::MlKem768,
            aead: AeadKind::Chacha20Poly1305,
            local_version: 1,
            allowed_peers: vec![],
        };

        let (initiator, msg1) = Initiator::start(cp).unwrap();
        let responder = Responder::start(sp).unwrap();
        let (msg2, server_res) = responder.respond(&msg1).unwrap();
        let client_res = initiator.finish(&msg2).unwrap();

        // Both sides derive identical directional keys and session id.
        assert_eq!(client_res.keys.c2s, server_res.keys.c2s);
        assert_eq!(client_res.keys.s2c, server_res.keys.s2c);
        assert_eq!(client_res.keys.session_id, server_res.keys.session_id);
        assert_eq!(client_res.pq_active, pq);
        assert_eq!(server_res.pq_active, pq);
        assert_eq!(client_res.peer_static, s_pub);
        assert_eq!(server_res.peer_static, c_pub);
    }

    #[test]
    fn classical_handshake() {
        run(false, None);
    }

    #[test]
    fn hybrid_handshake() {
        run(true, None);
    }

    #[test]
    fn hybrid_with_psk() {
        run(true, Some([42u8; 32]));
    }

    #[test]
    fn unauthorized_peer_rejected() {
        let (c_priv, c_pub) = keypair();
        let (s_priv, s_pub) = keypair();
        let (_e_priv, e_pub) = keypair(); // some other key the server authorizes

        let cp = HandshakeParams {
            local_private: c_priv,
            peer_public: s_pub,
            psk: None,
            pq_hybrid: false,
            pq_level: PqLevel::MlKem768,
            aead: AeadKind::Chacha20Poly1305,
            local_version: 1,
            allowed_peers: vec![],
        };
        // Server only authorizes e_pub, not the client's c_pub.
        let sp = HandshakeParams {
            local_private: s_priv,
            peer_public: c_pub,
            psk: None,
            pq_hybrid: false,
            pq_level: PqLevel::MlKem768,
            aead: AeadKind::Chacha20Poly1305,
            local_version: 1,
            allowed_peers: vec![e_pub],
        };
        let _ = c_pub;
        let (initiator, msg1) = Initiator::start(cp).unwrap();
        let responder = Responder::start(sp).unwrap();
        let err = responder.respond(&msg1).err().unwrap();
        assert!(matches!(err, Error::Unauthenticated));
        drop(initiator);
    }

    #[test]
    fn version_mismatch_detected() {
        let (c_priv, _c_pub) = keypair();
        let (s_priv, s_pub) = keypair();
        let (_x, c_pub) = keypair();
        let cp = HandshakeParams {
            local_private: c_priv,
            peer_public: s_pub,
            psk: None,
            pq_hybrid: false,
            pq_level: PqLevel::MlKem768,
            aead: AeadKind::Chacha20Poly1305,
            local_version: 1,
            allowed_peers: vec![],
        };
        let sp = HandshakeParams {
            local_private: s_priv,
            peer_public: c_pub,
            psk: None,
            pq_hybrid: false,
            pq_level: PqLevel::MlKem768,
            aead: AeadKind::Chacha20Poly1305,
            local_version: 2, // different
            allowed_peers: vec![],
        };
        let (initiator, msg1) = Initiator::start(cp).unwrap();
        let responder = Responder::start(sp).unwrap();
        // Responder sees client v1 vs its v2.
        let err = responder.respond(&msg1).err().unwrap();
        assert!(matches!(err, Error::VersionMismatch { .. }));
        drop(initiator);
    }
}
