//! uTLS-style TLS 1.3 ClientHello builder for the synthetic TCP transport.
//!
//! JA3/JA4 fingerprinting hashes the ClientHello's version, cipher-suite list,
//! extension list, supported groups and EC point formats. `rustls` does not let
//! us control that ordering, so for the raw-socket TCP transport — where we own
//! every byte — we hand-craft a ClientHello whose fields match a real browser,
//! yielding a browser JA3 instead of a tell-tale library fingerprint. GREASE
//! values are included (JA3 ignores them) in the Chrome profile.
//!
//! The client emits this as its first TCP segment; the peer skips a leading
//! ClientHello-looking record (see the `tcp` transport). This is camouflage,
//! not a real TLS session — the tunnel's security is the inner Noise handshake.

use crate::config::TlsFingerprint;

const GREASE: u16 = 0x0a0a;

/// A tiny big-endian TLS writer with length-prefixed block helpers.
struct W(Vec<u8>);
impl W {
    fn new() -> W {
        W(Vec::with_capacity(512))
    }
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn bytes(&mut self, b: &[u8]) {
        self.0.extend_from_slice(b);
    }
    /// Write a block whose length is a `n`-byte big-endian prefix.
    fn block(&mut self, nlen: usize, f: impl FnOnce(&mut W)) {
        let mut inner = W::new();
        f(&mut inner);
        let len = inner.0.len();
        match nlen {
            1 => self.u8(len as u8),
            2 => self.u16(len as u16),
            3 => {
                self.u8((len >> 16) as u8);
                self.u16((len & 0xFFFF) as u16);
            }
            _ => unreachable!(),
        }
        self.0.extend_from_slice(&inner.0);
    }
}

/// Cipher-suite list for a profile (GREASE first for Chrome).
fn ciphers(profile: TlsFingerprint) -> Vec<u16> {
    match profile {
        TlsFingerprint::Firefox => vec![
            0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ],
        // Chrome / Safari / default.
        _ => vec![
            GREASE, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
            0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ],
    }
}

/// Build a complete TLS record (handshake / ClientHello) for the profile+SNI.
pub fn client_hello(profile: TlsFingerprint, sni: &str) -> Vec<u8> {
    let chrome = !matches!(profile, TlsFingerprint::Firefox);

    let mut body = W::new();
    body.u16(0x0303); // legacy_version TLS 1.2
    let mut rnd = [0u8; 32];
    let _ = getrandom::getrandom(&mut rnd);
    body.bytes(&rnd); // random

    let mut sid = [0u8; 32];
    let _ = getrandom::getrandom(&mut sid);
    body.block(1, |w| w.bytes(&sid)); // legacy_session_id (32 bytes)

    // cipher_suites
    let cs = ciphers(profile);
    body.block(2, |w| {
        for c in &cs {
            w.u16(*c);
        }
    });

    body.block(1, |w| w.u8(0)); // compression_methods: null

    // extensions
    body.block(2, |w| {
        if chrome {
            ext_grease(w);
        }
        ext_sni(w, sni);
        ext_empty(w, 23); // extended_master_secret
        ext_renegotiation_info(w);
        ext_supported_groups(w, chrome);
        ext_ec_point_formats(w);
        ext_session_ticket(w);
        ext_alpn(w);
        ext_empty(w, 5); // status_request (simplified)
        ext_sig_algs(w);
        ext_key_share(w, chrome);
        ext_psk_modes(w);
        ext_supported_versions(w, chrome);
        if chrome {
            ext_grease(w);
        }
    });

    // Handshake header (ClientHello = 1) + record header (0x16, TLS 1.0).
    let mut hs = W::new();
    hs.u8(1);
    hs.block(3, |w| w.bytes(&body.0));

    let mut rec = W::new();
    rec.u8(0x16);
    rec.u16(0x0301);
    rec.block(2, |w| w.bytes(&hs.0));
    rec.0
}

/// Does `buf` begin with a TLS handshake ClientHello record? Used by the peer
/// to skip the camouflage first flight.
pub fn looks_like_client_hello(buf: &[u8]) -> bool {
    // record type 0x16, version 0x03 0x0x, then handshake type 0x01 at [5].
    buf.len() >= 6 && buf[0] == 0x16 && buf[1] == 0x03 && buf[5] == 0x01
}

fn ext_grease(w: &mut W) {
    w.u16(GREASE);
    w.block(2, |_| {});
}
fn ext_empty(w: &mut W, id: u16) {
    w.u16(id);
    w.block(2, |_| {});
}
fn ext_sni(w: &mut W, sni: &str) {
    w.u16(0); // server_name
    w.block(2, |w| {
        w.block(2, |w| {
            w.u8(0); // host_name
            w.block(2, |w| w.bytes(sni.as_bytes()));
        });
    });
}
fn ext_renegotiation_info(w: &mut W) {
    w.u16(65281);
    w.block(2, |w| w.u8(0));
}
fn ext_supported_groups(w: &mut W, chrome: bool) {
    w.u16(10);
    w.block(2, |w| {
        w.block(2, |w| {
            if chrome {
                w.u16(GREASE);
            }
            w.u16(0x001d); // x25519
            w.u16(0x0017); // secp256r1
            w.u16(0x0018); // secp384r1
        });
    });
}
fn ext_ec_point_formats(w: &mut W) {
    w.u16(11);
    w.block(2, |w| w.block(1, |w| w.u8(0))); // uncompressed
}
fn ext_session_ticket(w: &mut W) {
    ext_empty(w, 35);
}
fn ext_alpn(w: &mut W) {
    w.u16(16);
    w.block(2, |w| {
        w.block(2, |w| {
            w.block(1, |w| w.bytes(b"h2"));
            w.block(1, |w| w.bytes(b"http/1.1"));
        });
    });
}
fn ext_sig_algs(w: &mut W) {
    w.u16(13);
    w.block(2, |w| {
        w.block(2, |w| {
            for a in [
                0x0403u16, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ] {
                w.u16(a);
            }
        });
    });
}
fn ext_key_share(w: &mut W, chrome: bool) {
    w.u16(51);
    w.block(2, |w| {
        w.block(2, |w| {
            if chrome {
                w.u16(GREASE);
                w.block(2, |w| w.u8(0));
            }
            w.u16(0x001d); // x25519
            let mut kx = [0u8; 32];
            let _ = getrandom::getrandom(&mut kx);
            w.block(2, |w| w.bytes(&kx));
        });
    });
}
fn ext_psk_modes(w: &mut W) {
    w.u16(45);
    w.block(2, |w| w.block(1, |w| w.u8(1))); // psk_dhe_ke
}
fn ext_supported_versions(w: &mut W, chrome: bool) {
    w.u16(43);
    w.block(2, |w| {
        w.block(1, |w| {
            if chrome {
                w.u16(GREASE);
            }
            w.u16(0x0304); // TLS 1.3
            w.u16(0x0303); // TLS 1.2
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_formed_record() {
        for p in [TlsFingerprint::Chrome, TlsFingerprint::Firefox] {
            let ch = client_hello(p, "example.com");
            assert!(looks_like_client_hello(&ch));
            // Record length field matches the body.
            let rec_len = u16::from_be_bytes([ch[3], ch[4]]) as usize;
            assert_eq!(rec_len, ch.len() - 5);
            // Handshake length field matches too.
            let hs_len = ((ch[6] as usize) << 16) | ((ch[7] as usize) << 8) | ch[8] as usize;
            assert_eq!(hs_len, ch.len() - 9);
        }
    }

    #[test]
    fn contains_sni() {
        let ch = client_hello(TlsFingerprint::Chrome, "secret.example");
        assert!(ch.windows(14).any(|w| w == b"secret.example"));
    }
}
