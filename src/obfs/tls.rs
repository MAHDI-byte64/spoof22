//! TLS fingerprint mimicry (uTLS-style) and ECH plumbing for tcp/quic.
//!
//! Goal: make the ClientHello of the TCP/QUIC transports resemble a real
//! browser so JA3/JA4 fingerprinting does not single it out, and hide the real
//! SNI with Encrypted Client Hello where available.
//!
//! ## What is implemented
//!
//! * Browser-like **ALPN** sets per profile (Chrome/Firefox/Safari).
//! * **SNI** selection (a benign, popular name) fed into the QUIC/TLS config.
//!
//! ## Honest limitation / extension point
//!
//! Matching a browser's JA3/JA4 *exactly* requires controlling the
//! ClientHello's cipher-suite order, extension order, supported-groups and
//! GREASE values. `rustls` deliberately does not expose that ordering, so a
//! byte-exact browser fingerprint is **not** achievable through rustls alone.
//! The clean extension point is to swap the QUIC/TCP TLS stack for one that
//! allows ClientHello shaping (e.g. a BoringSSL/`boring`-based client, or a
//! hand-rolled ClientHello encoder) and drive it from [`TlsProfile`]. This is
//! called out in the README rather than shipped as a broken stub. The default
//! build still avoids the most obvious tell by presenting a browser ALPN and a
//! realistic SNI rather than rustls defaults.

use crate::config::{ObfsConfig, TlsFingerprint};

/// A resolved TLS mimicry profile.
#[derive(Debug, Clone)]
pub struct TlsProfile {
    pub fingerprint: TlsFingerprint,
    pub sni: String,
    pub ech: bool,
}

impl TlsProfile {
    /// Build from the obfs config.
    pub fn from_config(obfs: &ObfsConfig) -> TlsProfile {
        TlsProfile {
            fingerprint: obfs.tls_fingerprint,
            sni: obfs.sni.clone(),
            ech: obfs.ech,
        }
    }

    /// Browser-like ALPN protocol list for this fingerprint.
    pub fn alpn(&self) -> Vec<Vec<u8>> {
        match self.fingerprint {
            // Chrome/Safari and Firefox all offer h2 + http/1.1 on TCP TLS and
            // h3 on QUIC; the QUIC transport prepends h3 itself.
            TlsFingerprint::Chrome | TlsFingerprint::Safari | TlsFingerprint::Firefox => {
                vec![b"h2".to_vec(), b"http/1.1".to_vec()]
            }
            TlsFingerprint::Native => vec![b"h2".to_vec()],
        }
    }

    /// True if ECH was requested (the SNI should then be concealed). Whether it
    /// is actually negotiated depends on the TLS stack's ECH support.
    pub fn ech_requested(&self) -> bool {
        self.ech
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_sets() {
        let o = ObfsConfig {
            tls_fingerprint: TlsFingerprint::Chrome,
            ..Default::default()
        };
        let p = TlsProfile::from_config(&o);
        assert!(p.alpn().contains(&b"h2".to_vec()));
    }
}
