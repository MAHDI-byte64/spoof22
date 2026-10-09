#!/usr/bin/env bash
#
# freespoof-manager.sh — مدیرِ تعاملیِ نصب، پیکربندی و سرویسِ freespoof
#
# یک ابزارِ منوییِ فارسی برای:
#   - نصبِ راهنمایی‌شده (بیلد از سورس یا باینریِ آماده، تولیدِ کانفیگِ سرور و کلاینت،
#     ساختِ کاربرِ غیرمجاز، setcap، نصبِ یونیتِ systemd)
#   - پیکربندی/به‌روزرسانیِ یک instance
#   - مدیریتِ سرویس (start/stop/restart/enable/disable/remove) به ازای هر instance
#   - داشبوردِ وضعیت و آمارِ زنده (ctl)
#   - فهرستِ instanceها و لاگ‌ها (journalctl)
#   - تولیدِ گواهیِ self-signed برای ترنسپورتِ QUIC
#   - حذفِ کامل (uninstall)
#
# متنِ رابطِ کاربری فارسی است؛ نامِ فرمان‌ها/فلگ‌ها/کلیدهای TOML انگلیسی می‌مانند.

set -euo pipefail

# ---------------------------------------------------------------------------
# ثابت‌ها و مسیرهای استاندارد استقرار
# ---------------------------------------------------------------------------
BIN_DIR="/usr/local/bin"
BIN_PATH="${BIN_DIR}/freespoof"
CONFIG_DIR="/etc/freespoof"
WORK_DIR="/opt/freespoof"
RUN_DIR="/run"
DEFAULT_SOCKET="/run/freespoof.sock"
UNIT_NAME="freespoof@.service"
UNIT_DST="/etc/systemd/system/${UNIT_NAME}"
SVC_USER="freespoof"
SVC_GROUP="freespoof"
QUIC_CERT="${CONFIG_DIR}/quic-cert.pem"
QUIC_KEY="${CONFIG_DIR}/quic-key.pem"

# دایرکتوریِ ریشه‌ی مخزن (برای بیلد و کپیِ یونیت)، نسبت به محلِ همین اسکریپت.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "${SCRIPT_DIR}")"

# ---------------------------------------------------------------------------
# رنگ‌ها و چاپگرها
# ---------------------------------------------------------------------------
if [[ -t 1 ]]; then
  C_RESET=$'\e[0m'; C_BOLD=$'\e[1m'
  C_RED=$'\e[31m'; C_GREEN=$'\e[32m'; C_YELLOW=$'\e[33m'
  C_BLUE=$'\e[34m'; C_CYAN=$'\e[36m'
else
  C_RESET=""; C_BOLD=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_CYAN=""
fi

info()  { printf '%s[i]%s %s\n' "$C_BLUE"   "$C_RESET" "$*"; }
ok()    { printf '%s[✓]%s %s\n' "$C_GREEN"  "$C_RESET" "$*"; }
warn()  { printf '%s[!]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
err()   { printf '%s[✗]%s %s\n' "$C_RED"    "$C_RESET" "$*" >&2; }
title() { printf '\n%s%s== %s ==%s\n' "$C_BOLD" "$C_CYAN" "$*" "$C_RESET"; }

die() { err "$*"; exit 1; }

# ---------------------------------------------------------------------------
# کمک‌تابع‌های ورودی
# ---------------------------------------------------------------------------

# ask VAR "پیام" "پیش‌فرض"
ask() {
  local __var=$1 __msg=$2 __def=${3:-} __in=""
  if [[ -n "$__def" ]]; then
    read -r -p "$(printf '%s%s%s [%s]: ' "$C_BOLD" "$__msg" "$C_RESET" "$__def")" __in || true
    __in=${__in:-$__def}
  else
    read -r -p "$(printf '%s%s%s: ' "$C_BOLD" "$__msg" "$C_RESET")" __in || true
  fi
  printf -v "$__var" '%s' "$__in"
}

# confirm "پیام"  → کدِ خروجیِ 0 یعنی «بله»
confirm() {
  local __msg=$1 __in=""
  read -r -p "$(printf '%s%s%s [y/N]: ' "$C_BOLD" "$__msg" "$C_RESET")" __in || true
  [[ "${__in,,}" == "y" || "${__in,,}" == "yes" ]]
}

pause() {
  local __x=""
  read -r -p "$(printf '%sبرای ادامه Enter را بزنید...%s' "$C_CYAN" "$C_RESET")" __x || true
}

require_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    die "این اسکریپت باید با دسترسیِ root اجرا شود (از sudo استفاده کنید)."
  fi
}

have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# کمک‌تابع‌های عمومیِ instance / سوکت
# ---------------------------------------------------------------------------

# آرایه‌ی نام instanceها را در متغیرِ سراسریِ INSTANCES می‌ریزد.
list_instance_names() {
  INSTANCES=()
  local f base
  shopt -s nullglob
  for f in "${CONFIG_DIR}"/*.toml; do
    base="$(basename "$f" .toml)"
    # فایل‌های کمکیِ کلاینت (‎*-client.toml‎) را به‌عنوان instanceِ سرویس نشان نمی‌دهیم.
    case "$base" in
      *-client) continue ;;
    esac
    INSTANCES+=("$base")
  done
  shopt -u nullglob
}

# مسیرِ سوکتِ کنترلِ یک instance را از کانفیگش می‌خواند (پیش‌فرض /run/freespoof.sock).
instance_socket() {
  local name=$1 s=""
  s="$(sed -n 's/^[[:space:]]*control_socket[[:space:]]*=[[:space:]]*"\(.*\)".*/\1/p' \
        "${CONFIG_DIR}/${name}.toml" 2>/dev/null | head -n1)"
  printf '%s' "${s:-$DEFAULT_SOCKET}"
}

# یک instance را از فهرست انتخاب می‌کند؛ نتیجه در متغیرِ سراسریِ SELECTED.
select_instance() {
  SELECTED=""
  list_instance_names
  if [[ ${#INSTANCES[@]} -eq 0 ]]; then
    warn "هیچ instanceای در ${CONFIG_DIR} یافت نشد. ابتدا «نصبِ راهنمایی‌شده» را اجرا کنید."
    return 1
  fi
  echo "instanceهای موجود:"
  local i
  for i in "${!INSTANCES[@]}"; do
    printf '  %s%d%s) %s\n' "$C_BOLD" "$((i + 1))" "$C_RESET" "${INSTANCES[$i]}"
  done
  local choice=""
  ask choice "شماره‌ی instance را انتخاب کنید"
  if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#INSTANCES[@]} )); then
    SELECTED="${INSTANCES[$((choice - 1))]}"
    return 0
  fi
  err "انتخابِ نامعتبر."
  return 1
}

# انتخابِ ترنسپورت؛ نتیجه در متغیرِ سراسریِ TRANSPORT.
select_transport() {
  echo "ترنسپورت‌های موجود:"
  echo "  1) udp       (پیش‌فرض، سریع، قابلِ جعلِ منبع)"
  echo "  2) icmp      (شبیهِ ping)"
  echo "  3) proto58   (بدونِ هدرِ L4)"
  echo "  4) tcp       (شبیهِ HTTP/HTTPS، fake-TLS اختیاری)"
  echo "  5) quic      (TLS 1.3 واقعی — جعلِ IP غیرمجاز است، no_spoof اجباری)"
  echo "  6) ipip      (IP-in-IP)"
  echo "  7) gre       (شبیهِ GRE VPN)"
  local c=""
  ask c "انتخابِ ترنسپورت" "1"
  case "$c" in
    1|udp)     TRANSPORT="udp" ;;
    2|icmp)    TRANSPORT="icmp" ;;
    3|proto58) TRANSPORT="proto58" ;;
    4|tcp)     TRANSPORT="tcp" ;;
    5|quic)    TRANSPORT="quic" ;;
    6|ipip)    TRANSPORT="ipip" ;;
    7|gre)     TRANSPORT="gre" ;;
    *) warn "ناشناخته؛ udp انتخاب شد."; TRANSPORT="udp" ;;
  esac
}

# base64 → hex (برای allowed_peers). ورودیِ base64 استاندارد.
b64_to_hex() {
  printf '%s' "$1" | base64 -d 2>/dev/null | od -An -v -tx1 | tr -d ' \n'
}

# ---------------------------------------------------------------------------
# نصبِ باینری: بیلد از سورس یا باینریِ آماده
# ---------------------------------------------------------------------------
install_binary() {
  title "نصبِ باینریِ freespoof"
  echo "روشِ تهیه‌ی باینری:"
  echo "  1) بیلد از سورس با cargo (${REPO_ROOT})"
  echo "  2) استفاده از یک باینریِ از پیش ساخته‌شده"
  echo "  3) رد شدن (باینری قبلاً در ${BIN_PATH} نصب شده است)"
  local m=""
  ask m "انتخاب" "1"
  case "$m" in
    1) build_from_source ;;
    2) use_prebuilt ;;
    3)
      if [[ -x "$BIN_PATH" ]]; then
        ok "از باینریِ موجود استفاده می‌شود: ${BIN_PATH}"
      else
        die "باینری در ${BIN_PATH} یافت نشد."
      fi
      ;;
    *) die "انتخابِ نامعتبر." ;;
  esac
}

build_from_source() {
  have cargo || die "cargo یافت نشد. Rust (stable) را نصب کنید یا باینریِ آماده را به‌کار ببرید."
  [[ -f "${REPO_ROOT}/Cargo.toml" ]] || die "Cargo.toml در ${REPO_ROOT} یافت نشد."
  local native=""
  if confirm "بیلد با RUSTFLAGS=\"-C target-cpu=native\" برای AVX2/AVX-512/NEON؟"; then
    native="yes"
  fi
  info "در حالِ بیلد (cargo build --release) ... ممکن است چند دقیقه طول بکشد."
  if [[ -n "$native" ]]; then
    ( cd "$REPO_ROOT" && RUSTFLAGS="-C target-cpu=native" cargo build --release )
  else
    ( cd "$REPO_ROOT" && cargo build --release )
  fi
  local rel="${REPO_ROOT}/target/release"
  [[ -x "${rel}/freespoof" ]] || die "باینریِ ساخته‌شده در ${rel}/freespoof یافت نشد."
  install -D -m 0755 "${rel}/freespoof" "$BIN_PATH"
  # باینری‌های نقش‌قفل‌شده (در صورتِ وجود) هم نصب می‌شوند.
  [[ -x "${rel}/freespoof-client" ]] && install -D -m 0755 "${rel}/freespoof-client" "${BIN_DIR}/freespoof-client"
  [[ -x "${rel}/freespoof-server" ]] && install -D -m 0755 "${rel}/freespoof-server" "${BIN_DIR}/freespoof-server"
  ok "باینری‌ها در ${BIN_DIR} نصب شدند."
}

use_prebuilt() {
  local p=""
  ask p "مسیرِ باینریِ freespoof (فایل یا دایرکتوریِ حاویِ آن)"
  [[ -n "$p" ]] || die "مسیر خالی است."
  if [[ -d "$p" ]]; then
    p="${p%/}/freespoof"
  fi
  [[ -f "$p" ]] || die "باینری در ${p} یافت نشد."
  install -D -m 0755 "$p" "$BIN_PATH"
  # اگر باینری‌های نقش‌قفل‌شده کنارش بودند، آن‌ها هم نصب می‌شوند.
  local d; d="$(dirname "$p")"
  [[ -f "${d}/freespoof-client" ]] && install -D -m 0755 "${d}/freespoof-client" "${BIN_DIR}/freespoof-client"
  [[ -f "${d}/freespoof-server" ]] && install -D -m 0755 "${d}/freespoof-server" "${BIN_DIR}/freespoof-server"
  ok "باینری در ${BIN_PATH} نصب شد."
}

apply_setcap() {
  if ! have setcap; then
    warn "setcap یافت نشد (بسته‌ی libcap را نصب کنید). سرویس به‌جای آن باید با root اجرا شود یا AmbientCapabilities در systemd کار کند."
    return 0
  fi
  local b
  for b in "$BIN_PATH" "${BIN_DIR}/freespoof-client" "${BIN_DIR}/freespoof-server"; do
    [[ -x "$b" ]] || continue
    setcap cap_net_raw,cap_net_admin+ep "$b" \
      && ok "setcap روی ${b} اعمال شد (cap_net_raw,cap_net_admin+ep)." \
      || warn "setcap روی ${b} ناموفق بود."
  done
}

# ---------------------------------------------------------------------------
# کاربر، دایرکتوری‌ها، یونیتِ systemd
# ---------------------------------------------------------------------------
ensure_user() {
  if id "$SVC_USER" >/dev/null 2>&1; then
    ok "کاربرِ سیستمیِ ${SVC_USER} از قبل وجود دارد."
    return 0
  fi
  local nologin="/usr/sbin/nologin"
  [[ -x "$nologin" ]] || nologin="/sbin/nologin"
  [[ -x "$nologin" ]] || nologin="/bin/false"
  if have useradd; then
    useradd --system --no-create-home --home-dir "$WORK_DIR" --shell "$nologin" "$SVC_USER"
  elif have adduser; then
    adduser --system --no-create-home --home "$WORK_DIR" --shell "$nologin" "$SVC_USER" >/dev/null
  else
    die "نه useradd و نه adduser موجود نیست؛ کاربرِ ${SVC_USER} را دستی بسازید."
  fi
  ok "کاربرِ سیستمیِ غیرمجازِ ${SVC_USER} ساخته شد."
}

ensure_dirs() {
  install -d -m 0755 -o "$SVC_USER" -g "$SVC_GROUP" "$WORK_DIR" 2>/dev/null \
    || install -d -m 0755 "$WORK_DIR"
  # کانفیگ‌ها شاملِ کلیدِ خصوصی‌اند → دایرکتوری 0750 و فایل‌ها 0640، خواندنی برای گروهِ سرویس.
  install -d -m 0750 "$CONFIG_DIR"
  chgrp "$SVC_GROUP" "$CONFIG_DIR" 2>/dev/null || true
}

install_unit() {
  if [[ -f "${REPO_ROOT}/systemd/${UNIT_NAME}" ]]; then
    install -D -m 0644 "${REPO_ROOT}/systemd/${UNIT_NAME}" "$UNIT_DST"
    info "یونیت از ${REPO_ROOT}/systemd/${UNIT_NAME} کپی شد."
  else
    write_embedded_unit
    info "یونیتِ تعبیه‌شده در ${UNIT_DST} نوشته شد."
  fi
  if have systemctl; then
    systemctl daemon-reload
    ok "systemd daemon-reload انجام شد."
  else
    warn "systemctl یافت نشد؛ یونیت نصب شد اما قابلِ مدیریت با systemd نیست."
  fi
}

write_embedded_unit() {
  cat > "$UNIT_DST" <<'UNIT'
# قالبِ یونیتِ systemd برای freespoof — هر instance یک فایلِ کانفیگِ جداگانه دارد.
# نامِ instance (%i) برابرِ basename فایلِ کانفیگ است.
[Unit]
Description=freespoof tunnel instance %i (تونل ضدسانسورِ دوطرفه با جعلِ IP)
Documentation=file:///opt/freespoof/README.md
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=freespoof
Group=freespoof
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=false
WorkingDirectory=/opt/freespoof
ExecStart=/usr/local/bin/freespoof --config /etc/freespoof/%i.toml
ExecReload=/bin/kill -HUP $MAINPID
KillSignal=SIGTERM
TimeoutStopSec=15
Restart=on-failure
RestartSec=3
StartLimitIntervalSec=60
StartLimitBurst=5
ProtectSystem=strict
ReadWritePaths=/etc/freespoof /run
ProtectHome=true
PrivateTmp=true
RestrictSUIDSGID=true
LockPersonality=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
UNIT
}

# ---------------------------------------------------------------------------
# تولیدِ کانفیگ
# ---------------------------------------------------------------------------

# خواندنِ یک مقدارِ کلیدِ ساده‌ی TOML از یک فایل.
toml_get() {
  sed -n "s/^[[:space:]]*$2[[:space:]]*=[[:space:]]*\"\(.*\)\".*/\1/p" "$1" 2>/dev/null | head -n1
}

generate_server_config() {
  local instance=$1
  local server_cfg="${CONFIG_DIR}/${instance}.toml"
  local client_cfg="${CONFIG_DIR}/${instance}-client.toml"

  title "پارامترهای تونل (سمتِ سرور)"
  local IFACE REAL_IP PEER_REAL_IP DATA_PORT
  ask IFACE "نامِ اینترفیسِ فیزیکیِ NIC" "eth0"
  ask REAL_IP "IP واقعیِ این سرور"
  ask PEER_REAL_IP "IP واقعیِ کلاینت (طرفِ مقابل)"
  select_transport
  local dp_def="51820"
  [[ "$TRANSPORT" == "icmp" || "$TRANSPORT" == "proto58" || "$TRANSPORT" == "ipip" || "$TRANSPORT" == "gre" ]] && dp_def="51820"
  ask DATA_PORT "پورتِ داده (data_port)" "$dp_def"

  [[ -n "$REAL_IP" && -n "$PEER_REAL_IP" ]] || die "IP واقعیِ سرور و کلاینت الزامی است."
  [[ "$REAL_IP" != "$PEER_REAL_IP" ]] || die "IP واقعیِ سرور و کلاینت باید متفاوت باشند."

  # جعلِ IP — برای QUIC اجباراً خاموش.
  local NO_SPOOF="false" SPOOFED_IP PEER_SPOOFED_IP
  if [[ "$TRANSPORT" == "quic" ]]; then
    warn "ترنسپورتِ quic با جعلِ IP ناسازگار است؛ no_spoof = true تنظیم می‌شود."
    NO_SPOOF="true"
    SPOOFED_IP="$REAL_IP"; PEER_SPOOFED_IP="$PEER_REAL_IP"
  elif confirm "جعلِ IP فعال باشد؟ (برای مخفی‌کردنِ منبعِ واقعی)"; then
    NO_SPOOF="false"
    ask SPOOFED_IP "منبعِ جعلیِ این سرور (spoofed_ip)" "192.0.2.1"
    ask PEER_SPOOFED_IP "منبعِ جعلیِ موردانتظار از کلاینت (peer_spoofed_ip)" "192.0.2.2"
  else
    NO_SPOOF="true"
    SPOOFED_IP="$REAL_IP"; PEER_SPOOFED_IP="$PEER_REAL_IP"
  fi

  # کلیدها.
  info "در حالِ تولیدِ جفت‌کلیدِ استاتیکِ Noise سرور (freespoof genkey) ..."
  local genout PRIV PUB
  genout="$("$BIN_PATH" genkey)" || die "اجرای genkey ناموفق بود."
  PRIV="$(printf '%s\n' "$genout" | sed -n 's/^static_private_key[[:space:]]*=[[:space:]]*"\(.*\)".*/\1/p' | head -n1)"
  PUB="$(printf '%s\n'  "$genout" | sed -n 's/^static_public_key[[:space:]]*=[[:space:]]*"\(.*\)".*/\1/p'  | head -n1)"
  [[ -n "$PRIV" && -n "$PUB" ]] || die "تجزیه‌ی خروجیِ genkey ناموفق بود."

  local CTRL_SOCK="/run/freespoof-${instance}.sock"
  local METRICS_ADDR="127.0.0.1:9095" HEALTH_ADDR="127.0.0.1:9096"

  info "در حالِ نوشتنِ کانفیگِ سرور: ${server_cfg}"
  {
    echo "# کانفیگِ سرورِ freespoof — instance: ${instance}"
    echo "# ساخته‌شده توسطِ freespoof-manager.sh"
    echo "role = \"server\""
    echo "log_level = \"info\""
    echo ""
    echo "[spoof]"
    echo "real_ip = \"${REAL_IP}\""
    echo "peer_real_ip = \"${PEER_REAL_IP}\""
    echo "spoofed_ip = \"${SPOOFED_IP}\""
    echo "peer_spoofed_ip = \"${PEER_SPOOFED_IP}\""
    echo "no_spoof = ${NO_SPOOF}"
    echo "allowed_peers = []"
    echo ""
    echo "[transport]"
    echo "interface = \"${IFACE}\""
    echo "uplink_protocol = \"${TRANSPORT}\""
    echo "downlink_protocol = \"${TRANSPORT}\""
    echo "data_port = ${DATA_PORT}"
    echo ""
    echo "[crypto]"
    echo "static_private_key = \"${PRIV}\""
    echo "static_public_key = \"${PUB}\""
    # مقدارِ موقت (placeholder) تا اعتبارسنجیِ pair رد نشود؛ پس از pair با کلیدِ واقعیِ کلاینت جایگزین می‌شود.
    echo "peer_public_key = \"${PUB}\""
    echo "pre_shared_key = \"\""
    echo "pq_hybrid = true"
    echo ""
    echo "[tun]"
    echo "tun_name = \"freespoof0\""
    echo "tun_ip = \"10.66.0.1\""
    echo "tun_peer_ip = \"10.66.0.2\""
    echo "tun_mtu = 1380"
    echo "kill_switch = true"
    echo ""
    echo "[observability]"
    echo "metrics_addr = \"${METRICS_ADDR}\""
    echo "health_addr = \"${HEALTH_ADDR}\""
    echo "control_socket = \"${CTRL_SOCK}\""
    echo ""
    echo "[hardening]"
    # درون‌ریزیِ privilege در خودِ فرایند لازم نیست؛ systemd با User= و AmbientCapabilities این کار را می‌کند.
    echo "run_as_user = \"\""
    if [[ "$TRANSPORT" == "quic" ]]; then
      echo ""
      echo "[quic]"
      echo "cert_path = \"${QUIC_CERT}\""
      echo "key_path = \"${QUIC_KEY}\""
      echo "server_name = \"www.cloudflare.com\""
    fi
  } > "$server_cfg"
  chmod 0640 "$server_cfg"
  chgrp "$SVC_GROUP" "$server_cfg" 2>/dev/null || true

  # ساختِ کانفیگِ کلاینت با pair (آینه‌سازیِ آدرس‌ها، کلیدِ تازه‌ی کلاینت، پین‌کردنِ کلیدِ سرور).
  info "در حالِ ساختِ کانفیگِ کلاینت با freespoof pair ..."
  local pairout=""
  if ! pairout="$("$BIN_PATH" pair --server-config "$server_cfg" --client-out "$client_cfg" 2>&1)"; then
    err "اجرای pair ناموفق بود:"
    printf '%s\n' "$pairout" >&2
    die "تولیدِ کانفیگِ کلاینت متوقف شد."
  fi
  chmod 0640 "$client_cfg" 2>/dev/null || true
  chgrp "$SVC_GROUP" "$client_cfg" 2>/dev/null || true

  # کلیدِ عمومیِ کلاینت را از کانفیگِ کلاینت استخراج و در peer_public_key سرور می‌گذاریم.
  local CLIENT_PUB_B64 CLIENT_PUB_HEX SHARE_LINK
  CLIENT_PUB_B64="$(toml_get "$client_cfg" static_public_key)"
  SHARE_LINK="$(printf '%s\n' "$pairout" | grep -oE 'freespoof://[A-Za-z0-9_-]+' | head -n1)"
  CLIENT_PUB_HEX="$(printf '%s\n' "$pairout" | grep -oiE '^[0-9a-fA-F]{64}$' | head -n1)"
  [[ -z "$CLIENT_PUB_HEX" && -n "$CLIENT_PUB_B64" ]] && CLIENT_PUB_HEX="$(b64_to_hex "$CLIENT_PUB_B64")"

  if [[ -n "$CLIENT_PUB_B64" ]]; then
    sed -i "s|^peer_public_key[[:space:]]*=.*|peer_public_key = \"${CLIENT_PUB_B64}\"|" "$server_cfg"
    ok "کلیدِ عمومیِ کلاینت در peer_public_key سرور تنظیم شد."
  else
    warn "استخراجِ کلیدِ عمومیِ کلاینت ناموفق بود؛ peer_public_key را دستی در ${server_cfg} تنظیم کنید."
  fi
  if [[ -n "$CLIENT_PUB_HEX" ]]; then
    sed -i "s|^allowed_peers[[:space:]]*=.*|allowed_peers = [\"${CLIENT_PUB_HEX}\"]|" "$server_cfg"
  fi

  ok "کانفیگِ سرور: ${server_cfg}"
  ok "کانفیگِ کلاینت: ${client_cfg}  (این فایل را به ماشینِ کلاینت منتقل کنید)"
  if [[ -n "$SHARE_LINK" ]]; then
    echo ""
    echo "${C_BOLD}لینکِ اشتراک (این را به کلاینت بدهید):${C_RESET}"
    echo "${SHARE_LINK}"
  fi

  if [[ "$TRANSPORT" == "quic" ]]; then
    echo ""
    if confirm "ترنسپورتِ quic انتخاب شد؛ همین حالا گواهیِ self-signed بسازیم؟"; then
      generate_quic_cert "www.cloudflare.com"
    else
      info "اگر گواهی نسازید، خودِ freespoof یک گواهیِ موقت (ephemeral) هنگامِ اجرا تولید می‌کند."
    fi
  fi
}

generate_client_config_interactive() {
  local instance=$1
  local client_cfg="${CONFIG_DIR}/${instance}.toml"
  title "راه‌اندازیِ کلاینت از لینک/فایلِ pairing"
  echo "کانفیگِ کلاینت روی ${C_BOLD}سرور${C_RESET} با دستورِ pair ساخته می‌شود."
  echo "یا لینکِ اشتراکِ freespoof:// را وارد کنید، یا مسیرِ یک فایلِ client.toml را بدهید."
  local src=""
  ask src "لینکِ freespoof:// یا مسیرِ فایلِ client.toml"
  [[ -n "$src" ]] || die "ورودی خالی است."

  if [[ "$src" == freespoof://* ]]; then
    local b64="${src#freespoof://}"
    # URL-safe → استاندارد، سپس padding.
    b64="$(printf '%s' "$b64" | tr '_-' '/+')"
    local pad=$(( (4 - ${#b64} % 4) % 4 ))
    local i; for ((i=0; i<pad; i++)); do b64="${b64}="; done
    if ! printf '%s' "$b64" | base64 -d > "$client_cfg" 2>/dev/null; then
      die "رمزگشاییِ لینکِ freespoof:// ناموفق بود."
    fi
    ok "کانفیگ از لینکِ اشتراک رمزگشایی و در ${client_cfg} نوشته شد."
  elif [[ -f "$src" ]]; then
    install -m 0640 "$src" "$client_cfg"
    ok "کانفیگ از ${src} در ${client_cfg} کپی شد."
  else
    die "نه لینکِ معتبر و نه فایلِ موجود."
  fi
  chmod 0640 "$client_cfg"
  chgrp "$SVC_GROUP" "$client_cfg" 2>/dev/null || true

  # به‌روزرسانیِ مسیرِ سوکتِ کنترل تا با instance سازگار باشد و با سایرین تداخل نکند.
  if grep -q '^[[:space:]]*control_socket' "$client_cfg"; then
    sed -i "s|^[[:space:]]*control_socket[[:space:]]*=.*|control_socket = \"/run/freespoof-${instance}.sock\"|" "$client_cfg"
  fi
}

# ---------------------------------------------------------------------------
# گواهیِ QUIC
# ---------------------------------------------------------------------------
generate_quic_cert() {
  local cn="${1:-}"
  if ! have openssl; then
    warn "openssl یافت نشد؛ خودِ freespoof هنگامِ اجرا یک گواهیِ موقت می‌سازد."
    return 0
  fi
  [[ -n "$cn" ]] || ask cn "نامِ دامنه برای گواهی (CN / SNI)" "www.cloudflare.com"
  install -d -m 0750 "$CONFIG_DIR"
  info "در حالِ ساختِ گواهیِ self-signed برای ${cn} ..."
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$QUIC_KEY" -out "$QUIC_CERT" \
    -days 825 -subj "/CN=${cn}" \
    -addext "subjectAltName=DNS:${cn}" >/dev/null 2>&1 \
    || die "ساختِ گواهی با openssl ناموفق بود."
  chmod 0640 "$QUIC_KEY" "$QUIC_CERT"
  chgrp "$SVC_GROUP" "$QUIC_KEY" "$QUIC_CERT" 2>/dev/null || true
  ok "گواهی: ${QUIC_CERT}"
  ok "کلید:  ${QUIC_KEY}"
}

# ---------------------------------------------------------------------------
# نصبِ راهنمایی‌شده (گزینه‌ی ۱)
# ---------------------------------------------------------------------------
guided_setup() {
  title "نصب و راه‌اندازیِ راهنمایی‌شده"
  install_binary
  ensure_user
  ensure_dirs
  apply_setcap

  local role=""
  echo "این میزبان کدام نقش را دارد؟"
  echo "  1) server (کانفیگِ سرور + کانفیگِ کلاینت تولید می‌شود)"
  echo "  2) client (از لینک/فایلِ pairing که روی سرور ساخته شده استفاده می‌شود)"
  ask role "انتخاب" "1"

  local instance=""
  case "$role" in
    1|server)
      ask instance "نامِ instance (basename کانفیگ)" "server"
      [[ -n "$instance" ]] || die "نامِ instance الزامی است."
      if [[ -f "${CONFIG_DIR}/${instance}.toml" ]] && ! confirm "کانفیگِ ${instance} وجود دارد؛ بازنویسی شود؟"; then
        die "لغو شد."
      fi
      generate_server_config "$instance"
      ;;
    2|client)
      ask instance "نامِ instance (basename کانفیگ)" "client"
      [[ -n "$instance" ]] || die "نامِ instance الزامی است."
      if [[ -f "${CONFIG_DIR}/${instance}.toml" ]] && ! confirm "کانفیگِ ${instance} وجود دارد؛ بازنویسی شود؟"; then
        die "لغو شد."
      fi
      generate_client_config_interactive "$instance"
      ;;
    *) die "انتخابِ نامعتبر." ;;
  esac

  install_unit

  echo ""
  if confirm "سرویسِ freespoof@${instance} همین حالا enable و start شود؟"; then
    systemctl enable --now "freespoof@${instance}"
    ok "سرویسِ freespoof@${instance} فعال و اجرا شد."
    sleep 1
    systemctl --no-pager --full status "freespoof@${instance}" | head -n 12 || true
  else
    info "بعداً می‌توانید اجرا کنید:  systemctl enable --now freespoof@${instance}"
  fi
}

# ---------------------------------------------------------------------------
# پیکربندی/به‌روزرسانی (گزینه‌ی ۲)
# ---------------------------------------------------------------------------
configure_update() {
  title "پیکربندی/به‌روزرسانیِ یک instance"
  select_instance || { pause; return; }
  local cfg="${CONFIG_DIR}/${SELECTED}.toml"
  echo "اقدام:"
  echo "  1) ویرایشِ کانفیگ در ویرایشگر"
  echo "  2) بازتولیدِ کانفیگِ کلاینت از این سرور (pair)"
  echo "  3) تغییرِ ترنسپورتِ زنده (ctl switch-transport)"
  local a=""
  ask a "انتخاب" "1"
  case "$a" in
    1)
      local ed="${EDITOR:-}"
      [[ -z "$ed" ]] && { have nano && ed="nano" || ed="vi"; }
      "$ed" "$cfg"
      if confirm "سرویسِ freespoof@${SELECTED} برای اعمالِ تغییرات restart شود؟"; then
        systemctl restart "freespoof@${SELECTED}" && ok "restart شد." || err "restart ناموفق."
      else
        info "می‌توانید فقط کانفیگ را دوباره بخوانید:  systemctl reload freespoof@${SELECTED}"
      fi
      ;;
    2)
      local out="${CONFIG_DIR}/${SELECTED}-client.toml"
      local pairout=""
      if pairout="$("$BIN_PATH" pair --server-config "$cfg" --client-out "$out" 2>&1)"; then
        chmod 0640 "$out" 2>/dev/null || true
        chgrp "$SVC_GROUP" "$out" 2>/dev/null || true
        ok "کانفیگِ کلاینت در ${out} ساخته شد."
        local link; link="$(printf '%s\n' "$pairout" | grep -oE 'freespoof://[A-Za-z0-9_-]+' | head -n1)"
        [[ -n "$link" ]] && { echo "لینکِ اشتراک:"; echo "$link"; }
        echo ""
        warn "کلیدِ عمومیِ کلاینت را (در صورتِ تغییر) در peer_public_key / allowed_peers سرور به‌روز کنید."
        printf '%s\n' "$pairout" | grep -oiE '^[0-9a-fA-F]{64}$' | head -n1
      else
        err "pair ناموفق:"; printf '%s\n' "$pairout" >&2
      fi
      ;;
    3)
      local sock kind
      sock="$(instance_socket "$SELECTED")"
      ask kind "ترنسپورتِ جدید (udp|icmp|proto58|tcp|quic|ipip|gre)"
      "$BIN_PATH" ctl --socket "$sock" switch-transport "$kind" || err "ناموفق (آیا سرویس در حالِ اجراست؟)"
      ;;
    *) warn "نامعتبر." ;;
  esac
  pause
}

# ---------------------------------------------------------------------------
# مدیریتِ سرویس (گزینه‌ی ۳)
# ---------------------------------------------------------------------------
manage_service() {
  title "مدیریتِ سرویسِ یک instance"
  select_instance || { pause; return; }
  local name="$SELECTED" svc="freespoof@${SELECTED}"
  echo "اقدام روی ${C_BOLD}${svc}${C_RESET}:"
  echo "  1) start"
  echo "  2) stop"
  echo "  3) restart"
  echo "  4) reload (SIGHUP → بازخوانیِ کانفیگ)"
  echo "  5) enable (اجرا هنگامِ بوت)"
  echo "  6) disable"
  echo "  7) remove (توقف، disable و حذفِ کانفیگ)"
  local a=""
  ask a "انتخاب"
  case "$a" in
    1) systemctl start "$svc"   && ok "start شد." ;;
    2) systemctl stop "$svc"    && ok "stop شد." ;;
    3) systemctl restart "$svc" && ok "restart شد." ;;
    4) systemctl reload "$svc"  && ok "reload (SIGHUP) ارسال شد." ;;
    5) systemctl enable "$svc"  && ok "enable شد." ;;
    6) systemctl disable "$svc" && ok "disable شد." ;;
    7)
      if confirm "مطمئنید؟ instanceِ ${name} کاملاً حذف می‌شود"; then
        systemctl disable --now "$svc" 2>/dev/null || true
        rm -f "${CONFIG_DIR}/${name}.toml" "${CONFIG_DIR}/${name}-client.toml"
        ok "instanceِ ${name} حذف شد."
      fi
      ;;
    *) warn "نامعتبر." ;;
  esac
  pause
}

# ---------------------------------------------------------------------------
# داشبوردِ وضعیت (گزینه‌ی ۴)
# ---------------------------------------------------------------------------
status_dashboard() {
  title "داشبوردِ وضعیت"
  select_instance || { pause; return; }
  local svc="freespoof@${SELECTED}" sock
  sock="$(instance_socket "$SELECTED")"

  echo "${C_BOLD}-- systemctl status --${C_RESET}"
  systemctl --no-pager --full status "$svc" 2>/dev/null | head -n 16 || warn "سرویس یافت نشد."

  echo ""
  echo "${C_BOLD}-- ctl status (${sock}) --${C_RESET}"
  "$BIN_PATH" ctl --socket "$sock" status 2>/dev/null \
    || warn "سوکتِ کنترل در دسترس نیست (آیا سرویس در حالِ اجراست؟)."

  echo ""
  echo "${C_BOLD}-- ctl stats (گزیده‌ی متریک‌ها) --${C_RESET}"
  "$BIN_PATH" ctl --socket "$sock" stats 2>/dev/null \
    | grep -E '^freespoof_' | head -n 25 \
    || warn "آماری در دسترس نیست."
  pause
}

# ---------------------------------------------------------------------------
# فهرستِ instanceها (گزینه‌ی ۵)
# ---------------------------------------------------------------------------
list_instances() {
  title "فهرستِ instanceها"
  list_instance_names
  if [[ ${#INSTANCES[@]} -eq 0 ]]; then
    warn "هیچ instanceای یافت نشد."
    pause; return
  fi
  printf '%-16s %-10s %-10s %s\n' "INSTANCE" "ENABLED" "ACTIVE" "CONTROL-SOCKET"
  local n en ac
  for n in "${INSTANCES[@]}"; do
    en="$(systemctl is-enabled "freespoof@${n}" 2>/dev/null || echo "-")"
    ac="$(systemctl is-active  "freespoof@${n}" 2>/dev/null || echo "-")"
    printf '%-16s %-10s %-10s %s\n' "$n" "$en" "$ac" "$(instance_socket "$n")"
  done
  pause
}

# ---------------------------------------------------------------------------
# لاگ‌ها (گزینه‌ی ۶)
# ---------------------------------------------------------------------------
show_logs() {
  title "لاگ‌ها (journalctl)"
  select_instance || { pause; return; }
  local svc="freespoof@${SELECTED}"
  if confirm "به‌صورتِ زنده دنبال شود (follow, -f)؟ برای خروج Ctrl+C"; then
    journalctl -u "$svc" -f --no-pager || true
  else
    journalctl -u "$svc" --no-pager -n 120 || true
    pause
  fi
}

# ---------------------------------------------------------------------------
# گواهیِ QUIC (گزینه‌ی ۷)
# ---------------------------------------------------------------------------
quic_cert_menu() {
  title "تولیدِ گواهیِ self-signed برای QUIC"
  ensure_dirs
  generate_quic_cert ""
  info "در کانفیگِ مربوطه مطمئن شوید [quic].cert_path=${QUIC_CERT} و key_path=${QUIC_KEY} باشد."
  pause
}

# ---------------------------------------------------------------------------
# حذفِ کامل (گزینه‌ی ۸)
# ---------------------------------------------------------------------------
uninstall_all() {
  title "حذفِ کاملِ freespoof"
  warn "این کار همه‌ی سرویس‌ها را متوقف و باینری/یونیت را حذف می‌کند."
  confirm "ادامه می‌دهید؟" || { info "لغو شد."; pause; return; }

  list_instance_names
  local n
  for n in "${INSTANCES[@]:-}"; do
    [[ -z "$n" ]] && continue
    systemctl disable --now "freespoof@${n}" 2>/dev/null || true
    ok "freespoof@${n} متوقف و disable شد."
  done

  rm -f "$UNIT_DST"
  have systemctl && systemctl daemon-reload || true
  rm -f "$BIN_PATH" "${BIN_DIR}/freespoof-client" "${BIN_DIR}/freespoof-server"
  ok "باینری‌ها و یونیت حذف شدند."

  if confirm "کانفیگ‌ها و گواهی‌ها در ${CONFIG_DIR} هم حذف شوند؟ (شاملِ کلیدهای خصوصی)"; then
    rm -rf "$CONFIG_DIR"
    ok "${CONFIG_DIR} حذف شد."
  fi
  if confirm "کاربرِ سیستمیِ ${SVC_USER} و دایرکتوریِ ${WORK_DIR} هم حذف شوند؟"; then
    have userdel && userdel "$SVC_USER" 2>/dev/null || true
    rm -rf "$WORK_DIR"
    ok "کاربر و ${WORK_DIR} حذف شدند."
  fi
  pause
}

# ---------------------------------------------------------------------------
# منوی اصلی
# ---------------------------------------------------------------------------
main_menu() {
  while true; do
    printf '\n%s%s╔══════════════════════════════════════════════╗%s\n' "$C_BOLD" "$C_CYAN" "$C_RESET"
    printf   '%s%s║   مدیرِ freespoof — تونل ضدسانسورِ دوطرفه     ║%s\n' "$C_BOLD" "$C_CYAN" "$C_RESET"
    printf   '%s%s╚══════════════════════════════════════════════╝%s\n' "$C_BOLD" "$C_CYAN" "$C_RESET"
    echo "  1) نصب و راه‌اندازیِ راهنمایی‌شده"
    echo "  2) پیکربندی/به‌روزرسانیِ یک instance"
    echo "  3) مدیریتِ سرویس (start/stop/restart/enable/disable/remove)"
    echo "  4) داشبوردِ وضعیت (systemctl + ctl stats)"
    echo "  5) فهرستِ instanceها"
    echo "  6) لاگ‌ها (journalctl) و دنبال‌کردنِ زنده"
    echo "  7) تولیدِ گواهیِ self-signed برای QUIC"
    echo "  8) حذفِ کامل (uninstall)"
    echo "  0) خروج"
    local c=""
    ask c "گزینه را انتخاب کنید"
    case "$c" in
      1) guided_setup ;;
      2) configure_update ;;
      3) manage_service ;;
      4) status_dashboard ;;
      5) list_instances ;;
      6) show_logs ;;
      7) quic_cert_menu ;;
      8) uninstall_all ;;
      0) info "خداحافظ."; exit 0 ;;
      *) warn "گزینه‌ی نامعتبر." ;;
    esac
  done
}

require_root
main_menu
