#!/usr/bin/env bash
#
# install.sh — نصب‌کننده‌ی یک‌خطیِ freespoof (bootstrapِ غیرتعاملی)
#
# استفاده (یک‌خطی):
#   curl -fsSL https://raw.githubusercontent.com/MAHDI-byte64/spoof22/main/scripts/install.sh | sudo bash
#
# این اسکریپت مرحله‌ی سیستمی و غیرتعاملی را انجام می‌دهد:
#   - نصبِ پیش‌نیازها (در صورت نیاز: git، کامپایلر، زنجیره‌ی Rust)
#   - کلونِ مخزن و بیلدِ release
#   - نصبِ باینری‌ها در /usr/local/bin و اعمالِ setcap
#   - ساختِ کاربرِ غیرمجاز و دایرکتوری‌ها، نصبِ یونیتِ systemd و قالب‌های کانفیگ
#   - نصبِ دستورِ `freespoof-manager` برای پیکربندی/سرویسِ تعاملی
#
# پیکربندی و راه‌اندازیِ سرویس تعاملی است؛ پس از نصب این را در یک ترمینالِ واقعی اجرا کنید:
#   sudo freespoof-manager
#
# متغیرهای محیطی (اختیاری):
#   FREESPOOF_REPO   پیش‌فرض: MAHDI-byte64/spoof22
#   FREESPOOF_REF    شاخه/تگ/کامیت برای کلون (پیش‌فرض: main)
#   FREESPOOF_PREFIX مسیرِ نصبِ باینری‌ها (پیش‌فرض: /usr/local/bin)
#   FREESPOOF_NATIVE اگر "1" باشد با RUSTFLAGS=-C target-cpu=native بیلد می‌شود (غیرقابل‌حمل)

set -euo pipefail

REPO="${FREESPOOF_REPO:-MAHDI-byte64/spoof22}"
REF="${FREESPOOF_REF:-main}"
PREFIX="${FREESPOOF_PREFIX:-/usr/local/bin}"
SRC_DIR="/opt/freespoof/src"
CONFIG_DIR="/etc/freespoof"
UNIT_DST="/etc/systemd/system/freespoof@.service"
SVC_USER="freespoof"
BINARIES=(freespoof freespoof-client freespoof-server)

# --- چاپگرها ---------------------------------------------------------------
if [[ -t 1 ]]; then
  C_RESET=$'\e[0m'; C_BOLD=$'\e[1m'; C_RED=$'\e[31m'; C_GREEN=$'\e[32m'
  C_YELLOW=$'\e[33m'; C_BLUE=$'\e[34m'; C_CYAN=$'\e[36m'
else
  C_RESET=""; C_BOLD=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_BLUE=""; C_CYAN=""
fi
info() { printf '%s[i]%s %s\n' "$C_BLUE" "$C_RESET" "$*"; }
ok()   { printf '%s[✓]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
die()  { printf '%s[x]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }
title() { printf '\n%s%s== %s ==%s\n' "$C_BOLD" "$C_CYAN" "$*" "$C_RESET"; }
have() { command -v "$1" >/dev/null 2>&1; }

# --- پیش‌نیازها -------------------------------------------------------------
require_linux() {
  [[ "$(uname -s)" == "Linux" ]] || die "freespoof فقط روی Linux اجرا می‌شود."
}

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    if have sudo; then
      warn "نیازمندِ root؛ با sudo دوباره اجرا می‌شود ..."
      exec sudo -E bash "$0" "$@"
    fi
    die "این اسکریپت را با root (یا sudo) اجرا کنید."
  fi
}

# نصبِ بسته‌ها با پکیج‌منیجرِ در دسترس (بهترین تلاش).
pkg_install() {
  local pkgs=("$@")
  if have apt-get; then
    DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}" || return 1
  elif have dnf; then
    dnf install -y "${pkgs[@]}" || return 1
  elif have yum; then
    yum install -y "${pkgs[@]}" || return 1
  elif have pacman; then
    pacman -Sy --noconfirm "${pkgs[@]}" || return 1
  elif have apk; then
    apk add --no-cache "${pkgs[@]}" || return 1
  elif have zypper; then
    zypper install -y "${pkgs[@]}" || return 1
  else
    return 1
  fi
}

ensure_tool() {
  # ensure_tool <command> <pkg...> — اگر فرمان نبود، بسته‌(ها) را نصب کن.
  local cmd=$1; shift
  if have "$cmd"; then return 0; fi
  info "نصبِ پیش‌نیاز: ${cmd} ..."
  pkg_install "$@" || warn "نصبِ خودکارِ ${cmd} ناموفق بود؛ ادامه می‌دهیم."
}

ensure_build_deps() {
  ensure_tool git git
  ensure_tool curl curl ca-certificates
  # کامپایلرِ C برای وابستگی‌هایی مثل ring لازم است.
  if ! have cc && ! have gcc; then
    info "نصبِ زنجیره‌ی کامپایلرِ C ..."
    pkg_install build-essential || pkg_install gcc make || \
      pkg_install base-devel || warn "نصبِ کامپایلرِ C ناموفق بود؛ بیلد ممکن است شکست بخورد."
  fi
}

ensure_cargo() {
  if have cargo; then return 0; fi
  # اگر قبلاً rustup نصب شده اما در PATH نیست:
  if [[ -x "$HOME/.cargo/bin/cargo" ]]; then
    export PATH="$HOME/.cargo/bin:$PATH"; return 0
  fi
  # تلاش برای نصب از پکیج‌منیجر، سپس fallback به rustup.
  if pkg_install cargo rustc 2>/dev/null && have cargo; then return 0; fi
  info "نصبِ زنجیره‌ی Rust از طریقِ rustup (غیرتعاملی) ..."
  curl -fsSL --proto '=https' --tlsv1.2 https://sh.rustup.rs | sh -s -- -y --profile minimal \
    || die "نصبِ rustup ناموفق بود؛ لطفاً Rust را دستی نصب کنید (https://rustup.rs)."
  export PATH="$HOME/.cargo/bin:$PATH"
  have cargo || die "cargo پس از نصب هم در دسترس نیست."
}

# --- واکشیِ سورس و بیلد -----------------------------------------------------
fetch_source() {
  mkdir -p "$(dirname "$SRC_DIR")"
  if [[ -d "$SRC_DIR/.git" ]]; then
    info "به‌روزرسانیِ سورسِ موجود در ${SRC_DIR} (ref=${REF}) ..."
    git -C "$SRC_DIR" fetch --depth 1 origin "$REF" \
      || die "fetch ناموفق بود (ref=${REF})."
    git -C "$SRC_DIR" checkout -q FETCH_HEAD
  else
    info "کلونِ ${REPO} (ref=${REF}) در ${SRC_DIR} ..."
    rm -rf "$SRC_DIR"
    git clone --depth 1 --branch "$REF" "https://github.com/${REPO}.git" "$SRC_DIR" 2>/dev/null \
      || git clone "https://github.com/${REPO}.git" "$SRC_DIR" \
      || die "کلونِ مخزن ناموفق بود."
    # اگر ref یک شاخه نبود (تگ/کامیت)، صریحاً checkout کن.
    git -C "$SRC_DIR" checkout -q "$REF" 2>/dev/null || true
  fi
}

build_release() {
  title "بیلدِ release"
  info "در حالِ کامپایل (ممکن است چند دقیقه طول بکشد) ..."
  if [[ "${FREESPOOF_NATIVE:-0}" == "1" ]]; then
    ( cd "$SRC_DIR" && RUSTFLAGS="-C target-cpu=native" cargo build --release )
  else
    ( cd "$SRC_DIR" && cargo build --release )
  fi
  ok "بیلد کامل شد."
}

# --- نصبِ فایل‌ها ------------------------------------------------------------
install_binaries() {
  title "نصبِ باینری‌ها در ${PREFIX}"
  install -d -m 0755 "$PREFIX"
  for b in "${BINARIES[@]}"; do
    install -m 0755 "$SRC_DIR/target/release/$b" "$PREFIX/$b"
    ok "${b} نصب شد."
  done
}

apply_setcap() {
  if have setcap; then
    if setcap cap_net_raw,cap_net_admin+ep "$PREFIX/freespoof" 2>/dev/null; then
      ok "setcap اعمال شد: cap_net_raw,cap_net_admin+ep"
    else
      warn "setcap ناموفق بود؛ سرویس باید با root اجرا شود یا از AmbientCapabilities استفاده کند."
    fi
  else
    ensure_tool setcap libcap2-bin || ensure_tool setcap libcap || true
    have setcap && setcap cap_net_raw,cap_net_admin+ep "$PREFIX/freespoof" 2>/dev/null \
      && ok "setcap اعمال شد." \
      || warn "setcap در دسترس نیست؛ از systemd AmbientCapabilities یا اجرا با root استفاده کنید."
  fi
}

ensure_user_and_dirs() {
  if ! id -u "$SVC_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER" 2>/dev/null \
      || useradd --system --no-create-home --shell /sbin/nologin "$SVC_USER" 2>/dev/null \
      || warn "ساختِ کاربرِ ${SVC_USER} ناموفق بود (شاید از قبل وجود دارد)."
  fi
  install -d -m 0750 "$CONFIG_DIR"
  install -d -m 0750 /opt/freespoof
  chown -R "$SVC_USER":"$SVC_USER" "$CONFIG_DIR" /opt/freespoof 2>/dev/null || true
  ok "کاربر و دایرکتوری‌ها آماده شدند."
}

install_unit() {
  if [[ -f "$SRC_DIR/systemd/freespoof@.service" ]]; then
    install -m 0644 "$SRC_DIR/systemd/freespoof@.service" "$UNIT_DST"
    have systemctl && systemctl daemon-reload 2>/dev/null || true
    ok "یونیتِ systemd نصب شد: ${UNIT_DST}"
  else
    warn "فایلِ یونیتِ systemd در سورس پیدا نشد؛ از منیجر برای نصبِ آن استفاده کنید."
  fi
}

install_templates() {
  for f in client.toml server.toml; do
    if [[ -f "$SRC_DIR/config/$f" && ! -f "$CONFIG_DIR/$f.example" ]]; then
      install -m 0640 "$SRC_DIR/config/$f" "$CONFIG_DIR/$f.example"
    fi
  done
  chown -R "$SVC_USER":"$SVC_USER" "$CONFIG_DIR" 2>/dev/null || true
  ok "قالب‌های کانفیگ در ${CONFIG_DIR}/*.example قرار گرفتند."
}

install_manager() {
  # یک wrapper که منیجرِ تعاملی را از سورسِ کلون‌شده اجرا می‌کند
  # (تا REPO_ROOT برای بیلد/یونیت درست باشد).
  cat > "$PREFIX/freespoof-manager" <<EOF
#!/usr/bin/env bash
exec bash "${SRC_DIR}/scripts/freespoof-manager.sh" "\$@"
EOF
  chmod 0755 "$PREFIX/freespoof-manager"
  ok "دستورِ freespoof-manager نصب شد."
}

print_next_steps() {
  title "نصب کامل شد 🎉"
  cat <<EOF
نسخه‌ی نصب‌شده:
  $("$PREFIX/freespoof" --version 2>/dev/null || echo "freespoof")

گام بعد — پیکربندی و راه‌اندازیِ تعاملی را در یک ترمینالِ واقعی اجرا کنید:

  ${C_BOLD}sudo freespoof-manager${C_RESET}

منیجر به شما کمک می‌کند کانفیگِ سرور/کلاینت بسازید، سرویسِ systemd را فعال و
آمارِ زنده را ببینید. قالب‌های نمونه در ${CONFIG_DIR}/*.example هستند.

اجرای مستقیم با یک کانفیگِ آماده:
  sudo ${PREFIX}/freespoof --config ${CONFIG_DIR}/<name>.toml
EOF
}

main() {
  require_linux
  require_root "$@"
  title "نصبِ freespoof  (repo=${REPO}  ref=${REF})"
  ensure_build_deps
  ensure_cargo
  fetch_source
  build_release
  install_binaries
  apply_setcap
  ensure_user_and_dirs
  install_unit
  install_templates
  install_manager
  print_next_steps
}

main "$@"
