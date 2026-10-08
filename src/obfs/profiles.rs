//! Pluggable traffic-mimicry profiles.
//!
//! A profile shapes the *length distribution* of frames toward a target
//! traffic type (HTTP/2, HTTP/3, DoH, WebSocket, video), beyond mere random
//! padding, and supplies a realistic header template for the TCP transport.
//! New profiles are easy to add: extend [`sample_target_len`] and
//! [`header_template`].

use rand::Rng;

use crate::config::MimicryProfile;

/// Sample a plausible on-wire length for the profile. The obfuscation layer
/// pads the frame *up to* this length (never truncates). `None` means the
/// profile imposes no length target.
pub fn sample_target_len(profile: MimicryProfile) -> Option<usize> {
    let mut rng = rand::thread_rng();
    let len = match profile {
        MimicryProfile::None => return None,
        // HTTP/2 over TLS: many small framed records, some larger data frames.
        MimicryProfile::Http2 => {
            if rng.gen_bool(0.7) {
                rng.gen_range(40..=300)
            } else {
                rng.gen_range(800..=1400)
            }
        }
        // HTTP/3 / QUIC-ish: tends toward near-MTU datagrams.
        MimicryProfile::Http3 => rng.gen_range(1100..=1400),
        // DoH: small request/response bodies.
        MimicryProfile::Doh => rng.gen_range(80..=512),
        // WebSocket: small, bursty frames.
        MimicryProfile::WebSocket => rng.gen_range(20..=200),
        // Video streaming: large, consistent segments.
        MimicryProfile::VideoStream => rng.gen_range(1200..=1460),
    };
    Some(len)
}

/// A realistic header/preamble template for the given profile, prepended by
/// the TCP transport's mimicry to make the first bytes look conventional.
/// Returns an empty slice for profiles that do not define one.
pub fn header_template(profile: MimicryProfile) -> &'static [u8] {
    match profile {
        // HTTP/2 connection preface.
        MimicryProfile::Http2 => b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
        // A WebSocket upgrade line fragment.
        MimicryProfile::WebSocket => b"GET /chat HTTP/1.1\r\nUpgrade: websocket\r\n",
        // DoH POST line fragment.
        MimicryProfile::Doh => {
            b"POST /dns-query HTTP/1.1\r\nContent-Type: application/dns-message\r\n"
        }
        _ => b"",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_has_no_target() {
        assert!(sample_target_len(MimicryProfile::None).is_none());
    }

    #[test]
    fn profiles_have_targets() {
        for p in [
            MimicryProfile::Http2,
            MimicryProfile::Http3,
            MimicryProfile::Doh,
            MimicryProfile::WebSocket,
            MimicryProfile::VideoStream,
        ] {
            let l = sample_target_len(p).unwrap();
            assert!((20..=1460).contains(&l));
        }
    }
}
