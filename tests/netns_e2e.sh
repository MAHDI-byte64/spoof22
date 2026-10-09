#!/usr/bin/env bash
# End-to-end tunnel test across two Linux network namespaces.
#
# Builds the release binary, wires a veth pair between namespaces `fs_srv` and
# `fs_cli`, runs a freespoof server and client, and pings the peer across the
# tunnel's TUN device. Requires root (CAP_NET_ADMIN / netns).
#
#   sudo bash tests/netns_e2e.sh
#
# Exit 0 on success. Everything is torn down on exit.
set -euo pipefail

SRV_NS=fs_srv
CLI_NS=fs_cli
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/target/release/freespoof"
WORK="$(mktemp -d)"

log()  { printf '\033[36m[netns-e2e]\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[netns-e2e] FAIL:\033[0m %s\n' "$*"; exit 1; }

cleanup() {
  ip netns pids "$SRV_NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
  ip netns pids "$CLI_NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
  ip netns del "$SRV_NS" 2>/dev/null || true
  ip netns del "$CLI_NS" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

[ "$(id -u)" -eq 0 ] || fail "must run as root"

log "building release binary"
( cd "$ROOT" && cargo build --release --quiet )

log "creating namespaces + veth pair"
ip netns add "$SRV_NS"
ip netns add "$CLI_NS"
ip link add veth-s netns "$SRV_NS" type veth peer name veth-c netns "$CLI_NS"
ip netns exec "$SRV_NS" ip addr add 10.0.0.1/24 dev veth-s
ip netns exec "$CLI_NS" ip addr add 10.0.0.2/24 dev veth-c
ip netns exec "$SRV_NS" ip link set veth-s up
ip netns exec "$CLI_NS" ip link set veth-c up
ip netns exec "$SRV_NS" ip link set lo up
ip netns exec "$CLI_NS" ip link set lo up

log "generating keypairs"
SRV_KEYS="$("$BIN" genkey)"
CLI_KEYS="$("$BIN" genkey)"
srv_priv=$(echo "$SRV_KEYS" | awk -F'"' '/static_private_key/{print $2}')
srv_pub=$(echo "$SRV_KEYS"  | awk -F'"' '/static_public_key/{print $2}')
cli_priv=$(echo "$CLI_KEYS" | awk -F'"' '/static_private_key/{print $2}')
cli_pub=$(echo "$CLI_KEYS"  | awk -F'"' '/static_public_key/{print $2}')

common_crypto() { cat <<EOF
[crypto]
static_private_key = "$1"
static_public_key = "$2"
peer_public_key = "$3"
pq_hybrid = true
EOF
}

cat > "$WORK/server.toml" <<EOF
role = "server"
log_level = "info"
[spoof]
real_ip = "10.0.0.1"
peer_real_ip = "10.0.0.2"
no_spoof = true
[transport]
interface = "veth-s"
uplink_protocol = "udp"
downlink_protocol = "udp"
data_port = 51820
$(common_crypto "$srv_priv" "$srv_pub" "$cli_pub")
[tun]
tun_name = "fs0"
tun_ip = "10.66.0.1"
tun_peer_ip = "10.66.0.2"
kill_switch = false
[reliability]
keepalive_secs = 5
dead_peer_timeout_secs = 30
EOF

cat > "$WORK/client.toml" <<EOF
role = "client"
log_level = "info"
[spoof]
real_ip = "10.0.0.2"
peer_real_ip = "10.0.0.1"
no_spoof = true
[transport]
interface = "veth-c"
uplink_protocol = "udp"
downlink_protocol = "udp"
data_port = 51820
$(common_crypto "$cli_priv" "$cli_pub" "$srv_pub")
[tun]
tun_name = "fs0"
tun_ip = "10.66.0.2"
tun_peer_ip = "10.66.0.1"
kill_switch = false
[reliability]
keepalive_secs = 5
dead_peer_timeout_secs = 30
EOF

log "starting server"
ip netns exec "$SRV_NS" "$BIN" --config "$WORK/server.toml" >"$WORK/srv.log" 2>&1 &
sleep 1
log "starting client"
ip netns exec "$CLI_NS" "$BIN" --config "$WORK/client.toml" >"$WORK/cli.log" 2>&1 &

log "waiting for tunnel to come up"
for _ in $(seq 1 20); do
  if ip netns exec "$CLI_NS" ping -c1 -W1 10.66.0.1 >/dev/null 2>&1; then
    log "PASS: pinged server TUN address across the tunnel"
    exit 0
  fi
  sleep 1
done

echo "--- server log ---"; cat "$WORK/srv.log" || true
echo "--- client log ---"; cat "$WORK/cli.log" || true
fail "tunnel did not come up / ping failed"
