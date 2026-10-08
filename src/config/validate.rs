//! Configuration validation with precise, actionable error messages.
//!
//! Two classes of rules are enforced:
//!
//! 1. **Local structural rules** — a single side's file must be internally
//!    consistent (keys present, ports in range, mtu sane, spoof×transport
//!    legality, shuffle×QUIC exclusivity, FEC group sizing, …). These are
//!    fully checkable here and fail the load.
//!
//! 2. **Cross-side agreement rules** — fields that MUST match (or be mirrored)
//!    between the two sides: `uplink/downlink/data_port/icmp_id/psk/aead/obfs`
//!    settings must agree, and `tun_ip`/`tun_peer_ip` must be swapped. A single
//!    file cannot see the peer's file, so the parts that are locally checkable
//!    (e.g. tun_ip != tun_peer_ip, both inside the /30) are enforced here; the
//!    rest are negotiated/verified during the handshake (parameter hash) and
//!    documented in `docs/CONFIG_REFERENCE.fa.md`.

use std::net::Ipv4Addr;

use crate::config::{Config, TransportKind};
use crate::error::{Error, Result};

/// Validate a fully-normalized [`Config`].
pub fn validate(cfg: &Config) -> Result<()> {
    validate_logging(cfg)?;
    validate_spoof(cfg)?;
    validate_transport(cfg)?;
    validate_crypto(cfg)?;
    validate_tun(cfg)?;
    validate_obfs(cfg)?;
    validate_mux_fec(cfg)?;
    validate_perf(cfg)?;
    validate_quic_interactions(cfg)?;
    Ok(())
}

fn validate_logging(cfg: &Config) -> Result<()> {
    match cfg.log_level.as_str() {
        "trace" | "debug" | "info" | "warn" | "error" => Ok(()),
        other => Err(Error::validation(format!(
            "log_level must be one of trace|debug|info|warn|error, got '{other}'"
        ))),
    }
}

fn validate_spoof(cfg: &Config) -> Result<()> {
    let s = &cfg.spoof;
    if s.real_ip == Ipv4Addr::UNSPECIFIED {
        return Err(Error::validation(
            "spoof.real_ip must be set to this host's real NIC address",
        ));
    }
    if s.peer_real_ip == Ipv4Addr::UNSPECIFIED {
        return Err(Error::validation(
            "spoof.peer_real_ip must be set to the peer's real address",
        ));
    }
    if s.real_ip == s.peer_real_ip {
        return Err(Error::validation(
            "spoof.real_ip and spoof.peer_real_ip must differ",
        ));
    }
    // In spoof mode the forged source must not accidentally equal the real one
    // unless no_spoof is set (then normalize() already forced them equal).
    if !s.no_spoof {
        if s.spoofed_ip == Ipv4Addr::UNSPECIFIED {
            return Err(Error::validation(
                "spoof.spoofed_ip must be set (or set spoof.no_spoof = true)",
            ));
        }
        if s.peer_spoofed_ip == Ipv4Addr::UNSPECIFIED {
            return Err(Error::validation(
                "spoof.peer_spoofed_ip must be set (or set spoof.no_spoof = true)",
            ));
        }
    }
    // Validate any hex peer keys in allowed_peers decode to 32 bytes.
    for (i, p) in s.allowed_peers.iter().enumerate() {
        let raw = hex::decode(p.trim())
            .map_err(|e| Error::validation(format!("allowed_peers[{i}] not valid hex: {e}")))?;
        if raw.len() != 32 {
            return Err(Error::validation(format!(
                "allowed_peers[{i}] must be a 32-byte X25519 public key (hex)"
            )));
        }
    }
    Ok(())
}

fn validate_transport(cfg: &Config) -> Result<()> {
    let t = &cfg.transport;
    if t.interface.trim().is_empty() {
        return Err(Error::validation(
            "transport.interface (physical NIC) must be set",
        ));
    }
    if t.data_port == 0 {
        return Err(Error::validation("transport.data_port must be non-zero"));
    }
    if t.shuffle_data_port {
        if t.shuffle_port_min == 0 || t.shuffle_port_max == 0 {
            return Err(Error::validation(
                "shuffle_port_min/max must be non-zero when shuffling",
            ));
        }
        if t.shuffle_port_min >= t.shuffle_port_max {
            return Err(Error::validation(
                "shuffle_port_min must be < shuffle_port_max",
            ));
        }
        // shuffle is UDP/TCP only and mutually exclusive with QUIC.
        if cfg.uses_quic() {
            return Err(Error::validation(
                "shuffle_data_port is mutually exclusive with the QUIC transport",
            ));
        }
        if !matches!(t.uplink_protocol, TransportKind::Udp | TransportKind::Tcp)
            || !matches!(t.downlink_protocol, TransportKind::Udp | TransportKind::Tcp)
        {
            return Err(Error::validation(
                "shuffle_data_port requires udp or tcp on both directions",
            ));
        }
    }
    // Endpoint hopping needs at least two endpoints to hop between.
    if t.endpoint_hop_interval_secs > 0 && t.server_endpoints.len() < 2 {
        return Err(Error::validation(
            "endpoint_hop_interval_secs > 0 requires at least two transport.server_endpoints",
        ));
    }
    Ok(())
}

fn validate_crypto(cfg: &Config) -> Result<()> {
    let c = &cfg.crypto;
    // Static private key is required to run (the manager generates one).
    if c.static_private_key.trim().is_empty() {
        return Err(Error::validation(
            "crypto.static_private_key is empty — generate one with `freespoof genkey`",
        ));
    }
    decode_b64_key(&c.static_private_key, "crypto.static_private_key")?;

    // Noise_IK requires knowing the peer's static public key up front.
    if c.peer_public_key.trim().is_empty() {
        return Err(Error::validation(
            "crypto.peer_public_key is required for the Noise_IK handshake",
        ));
    }
    decode_b64_key(&c.peer_public_key, "crypto.peer_public_key")?;

    if c.rekey_secs > 0 && c.rekey_secs < 10 {
        return Err(Error::validation("crypto.rekey_secs must be 0 or >= 10"));
    }
    if c.replay_window < 64 {
        return Err(Error::validation("crypto.replay_window must be >= 64"));
    }
    if c.replay_window % 64 != 0 {
        return Err(Error::validation(
            "crypto.replay_window must be a multiple of 64",
        ));
    }
    Ok(())
}

fn validate_tun(cfg: &Config) -> Result<()> {
    let t = &cfg.tun;
    if t.tun_name.is_empty() || t.tun_name.len() > 15 {
        return Err(Error::validation("tun.tun_name must be 1..=15 characters"));
    }
    if t.tun_ip == t.tun_peer_ip {
        return Err(Error::validation(
            "tun.tun_ip and tun.tun_peer_ip must differ (and be swapped on the two sides)",
        ));
    }
    // Both TUN addresses must live in the same subnet defined by the netmask.
    let mask = u32::from(t.tun_netmask);
    if (u32::from(t.tun_ip) & mask) != (u32::from(t.tun_peer_ip) & mask) {
        return Err(Error::validation(
            "tun.tun_ip and tun.tun_peer_ip must be in the same subnet (point-to-point /30)",
        ));
    }
    if t.tun_mtu < 576 {
        return Err(Error::validation("tun.tun_mtu must be >= 576"));
    }
    if cfg.tun.routing_mode == crate::config::RoutingMode::Split
        && t.split_cidrs.is_empty()
        && t.split_ports.is_empty()
    {
        return Err(Error::validation(
            "routing_mode = split requires at least one split_cidrs or split_ports entry",
        ));
    }
    Ok(())
}

fn validate_obfs(cfg: &Config) -> Result<()> {
    let o = &cfg.obfs;
    if o.packet_padding_max > 0 && o.packet_padding > o.packet_padding_max {
        return Err(Error::validation(
            "obfs.packet_padding must be <= obfs.packet_padding_max",
        ));
    }
    for ttl in &o.ttl_jitter {
        if *ttl == 0 {
            return Err(Error::validation("obfs.ttl_jitter values must be non-zero"));
        }
    }
    if o.pad_to_size > 0 && o.pad_to_size < 64 {
        return Err(Error::validation("obfs.pad_to_size must be 0 or >= 64"));
    }
    if o.decoy_enabled && o.decoy_target.trim().is_empty() {
        return Err(Error::validation(
            "obfs.decoy_target must be set when decoy_enabled = true",
        ));
    }
    Ok(())
}

fn validate_mux_fec(cfg: &Config) -> Result<()> {
    if cfg.fec.enable_fec {
        if cfg.fec.fec_group_size < 2 {
            return Err(Error::validation("fec.fec_group_size must be >= 2"));
        }
        if cfg.fec.fec_parity_shards == 0 {
            return Err(Error::validation("fec.fec_parity_shards must be >= 1"));
        }
        if cfg.fec.fec_group_size + cfg.fec.fec_parity_shards > 255 {
            return Err(Error::validation(
                "fec data+parity shards must be <= 255 (Reed-Solomon GF(2^8) limit)",
            ));
        }
        // Mux/FEC only apply to datagram transports.
        if !cfg.transport.uplink_protocol.supports_mux_fec()
            && !cfg.transport.downlink_protocol.supports_mux_fec()
        {
            return Err(Error::validation(
                "FEC is only supported on udp/icmp/proto58/ipip transports (not tcp/quic)",
            ));
        }
    }
    if cfg.mux.enable_multiplex && cfg.mux.multiplex_max_payload < 256 {
        return Err(Error::validation(
            "mux.multiplex_max_payload must be >= 256",
        ));
    }
    Ok(())
}

fn validate_perf(cfg: &Config) -> Result<()> {
    let p = &cfg.perf;
    if !p.auto_tune && p.tunnel_count == 0 {
        return Err(Error::validation(
            "perf.tunnel_count must be >= 1 when auto_tune = false",
        ));
    }
    if p.mtu < 576 || p.mtu > 9000 {
        return Err(Error::validation("perf.mtu must be in 576..=9000"));
    }
    if p.channel_capacity == 0 || p.io_channel_capacity == 0 {
        return Err(Error::validation(
            "perf channel capacities must be non-zero",
        ));
    }
    Ok(())
}

/// Enforce the spoofing × transport legality rule: real QUIC (kernel UDP +
/// path validation + TLS tied to the 4-tuple) effectively requires real
/// addresses, so a QUIC transport MUST run with `no_spoof = true`. Any config
/// that combines QUIC with active spoofing is rejected with a clear message.
fn validate_quic_interactions(cfg: &Config) -> Result<()> {
    if cfg.uses_quic() && !cfg.spoof.no_spoof {
        return Err(Error::validation(
            "QUIC cannot be combined with IP spoofing: set spoof.no_spoof = true for QUIC \
             transports (QUIC relies on TLS/ECH mimicry instead of source forging)",
        ));
    }
    Ok(())
}

/// Decode and length-check a base64 32-byte key.
fn decode_b64_key(s: &str, field: &str) -> Result<[u8; 32]> {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| Error::validation(format!("{field} is not valid base64: {e}")))?;
    if raw.len() != 32 {
        return Err(Error::validation(format!(
            "{field} must decode to 32 bytes (X25519 key)"
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}
