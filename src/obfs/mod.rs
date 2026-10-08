//! Obfuscation & censorship resistance.
//!
//! * [`padding`] — random padding + pad-to-fixed-size (length obfuscation)
//! * [`shaping`] — inter-packet timing jitter + constant-rate pacing
//! * [`profiles`] — pluggable length-distribution mimicry ("looks like …")
//! * [`tls`] — TLS fingerprint / ECH profile for tcp/quic
//! * [`decoy`] — active-probing reverse proxy to a real HTTPS site
//!
//! TTL jitter and DSCP marking are applied at the raw-IPv4 layer (see
//! [`crate::transport::raw_core`]); padding / jitter / cover traffic / length
//! mimicry are applied in the session data plane via [`Obfs`].

pub mod decoy;
pub mod padding;
pub mod profiles;
pub mod shaping;
pub mod tls;

pub use padding::PadPolicy;

use crate::config::{Config, MimicryProfile};

/// Data-plane obfuscation settings resolved from config.
#[derive(Debug, Clone, Copy)]
pub struct Obfs {
    /// Random / fixed-size padding policy.
    pub pad: PadPolicy,
    /// Inter-packet timing jitter upper bound (ms).
    pub timing_jitter_ms: u64,
    /// Cover/chaff traffic rate (packets/sec, 0 = off).
    pub cover_pps: u64,
    /// Constant-rate shaping (packets/sec, 0 = off).
    pub constant_rate_pps: u64,
    /// Length-distribution mimicry profile.
    pub profile: MimicryProfile,
}

impl Obfs {
    /// Resolve from config.
    pub fn from_config(cfg: &Config) -> Obfs {
        Obfs {
            pad: PadPolicy {
                min: cfg.obfs.packet_padding,
                max: cfg.obfs.packet_padding_max.max(cfg.obfs.packet_padding),
                pad_to: cfg.obfs.pad_to_size,
            },
            timing_jitter_ms: cfg.obfs.timing_jitter_ms,
            cover_pps: cfg.obfs.cover_traffic_pps,
            constant_rate_pps: cfg.obfs.constant_rate_pps,
            profile: cfg.obfs.mimicry_profile,
        }
    }

    /// Whether the padding stage does anything (random, fixed, or profile).
    pub fn pads(&self) -> bool {
        self.pad.active() || self.profile != MimicryProfile::None
    }

    /// Compute the effective pad policy for one frame, folding in a sampled
    /// profile target length (as a dynamic pad-to, accounting for `overhead`
    /// bytes added by framing + AEAD).
    pub fn frame_pad(&self, overhead: usize) -> PadPolicy {
        let mut pad = self.pad;
        if let Some(target) = profiles::sample_target_len(self.profile) {
            let plaintext_target = target.saturating_sub(overhead);
            pad.pad_to = pad.pad_to.max(plaintext_target);
        }
        pad
    }
}
