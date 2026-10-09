//! Integration tests.
//!
//! * `pairing_roundtrip` runs everywhere: it generates a server config, derives
//!   a client config with the pairing helper, and checks the cross-side
//!   agreement (swapped addresses, pinned keys, matching transport/port).
//! * `netns_end_to_end` drives a real two-namespace tunnel via
//!   `tests/netns_e2e.sh`; it needs root + CAP_NET_ADMIN and is `#[ignore]` by
//!   default (run with `sudo -E cargo test --test integration -- --ignored`).

use std::io::Write;

use freespoof::config::{Config, Role};

fn write_temp(name: &str, contents: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "freespoof-test-{}-{}.toml",
        std::process::id(),
        name
    ));
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(contents.as_bytes()).unwrap();
    path
}

fn server_config_toml() -> String {
    let server = freespoof::crypto::generate_static_keypair().unwrap();
    let client = freespoof::crypto::generate_static_keypair().unwrap();
    format!(
        r#"
role = "server"
log_level = "info"

[spoof]
real_ip = "203.0.113.10"
peer_real_ip = "198.51.100.20"
no_spoof = true

[transport]
interface = "eth0"
uplink_protocol = "udp"
downlink_protocol = "udp"
data_port = 51820

[crypto]
static_private_key = "{}"
static_public_key = "{}"
peer_public_key = "{}"

[tun]
tun_ip = "10.66.0.1"
tun_peer_ip = "10.66.0.2"
"#,
        server.private_b64, server.public_b64, client.public_b64
    )
}

#[test]
fn pairing_roundtrip() {
    let server_path = write_temp("server", &server_config_toml());
    let server = Config::load(&server_path).unwrap();

    let pairing = freespoof::app::generate_client_config(&server_path).unwrap();
    // The share link is a freespoof:// URL.
    assert!(pairing.share_link.starts_with("freespoof://"));
    assert_eq!(pairing.client_public_hex.len(), 64); // 32 bytes hex

    // The generated client config must itself load + validate.
    let client = Config::from_toml_str(&pairing.client_toml).unwrap();
    assert_eq!(client.role, Role::Client);

    // Cross-side agreement: addresses mirrored, transport + port identical.
    assert_eq!(client.spoof.real_ip, server.spoof.peer_real_ip);
    assert_eq!(client.spoof.peer_real_ip, server.spoof.real_ip);
    assert_eq!(client.tun.tun_ip, server.tun.tun_peer_ip);
    assert_eq!(client.tun.tun_peer_ip, server.tun.tun_ip);
    assert_eq!(client.transport.data_port, server.transport.data_port);
    assert_eq!(
        client.transport.uplink_protocol,
        server.transport.uplink_protocol
    );
    // The client pins the server's static public key.
    assert_eq!(
        client.crypto.peer_public_key,
        server.crypto.static_public_key
    );

    let _ = std::fs::remove_file(&server_path);
}

#[test]
fn quic_rejects_spoofing() {
    // A QUIC transport with spoofing enabled must be rejected by validation.
    let server = freespoof::crypto::generate_static_keypair().unwrap();
    let client = freespoof::crypto::generate_static_keypair().unwrap();
    let toml = format!(
        r#"
role = "client"
[spoof]
real_ip = "203.0.113.10"
peer_real_ip = "198.51.100.20"
spoofed_ip = "192.0.2.50"
peer_spoofed_ip = "192.0.2.60"
no_spoof = false
[transport]
interface = "eth0"
uplink_protocol = "quic"
downlink_protocol = "quic"
data_port = 443
[crypto]
static_private_key = "{}"
peer_public_key = "{}"
[tun]
tun_ip = "10.66.0.2"
tun_peer_ip = "10.66.0.1"
"#,
        server.private_b64, client.public_b64
    );
    let err = Config::from_toml_str(&toml).unwrap_err();
    assert!(format!("{err}").contains("QUIC"));
}

#[test]
#[ignore = "requires root + CAP_NET_ADMIN; run with --ignored"]
fn netns_end_to_end() {
    let status = std::process::Command::new("bash")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/netns_e2e.sh"))
        .status()
        .expect("spawn netns_e2e.sh");
    assert!(status.success(), "netns end-to-end test failed");
}
