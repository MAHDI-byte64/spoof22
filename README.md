<div dir="rtl">

# freespoof

**تونل ضدسانسور دوطرفه، مقاوم در برابر DPI، با جعل منبعِ IP — برای لینک نقطه‌به‌نقطه‌ی مجاز.**

`freespoof` یک تونل رمزنگاری‌شده‌ی نقطه‌به‌نقطه (point-to-point) است که برای عبور از
سانسورِ مبتنی بر DPI ساخته شده و روی مسیری کار می‌کند که **هر دو سرِ آن را خودِ اپراتور
کنترل می‌کند**. برخلاف ابزارهای متداول، `freespoof` منبعِ بسته‌های خام IPv4 را نیز **جعل**
می‌کند تا الگوی ترافیک را متنوع کند و در برابر محدودسازی بر پایه‌ی IP مبدأ مقاوم‌تر باشد.
این پروژه هم‌خانواده‌ی WireGuard و Xray/Reality و Trojan و Hysteria است، اما با یک لایه‌ی
اضافیِ جعلِ منبع در سطح IP خام.

> **هشدار کاربرد مجاز:** این ابزار فقط برای لینکی در نظر گرفته شده که **هر دو انتهای آن را
> خودتان در اختیار دارید** و قانوناً اجازه‌ی ارسالِ بسته با منبعِ جعلی روی آن مسیر را دارید
> (مثلاً دو سرورِ اجاره‌ایِ خودتان، یا دو میزبان روی شبکه‌ای که مالک آن هستید). هویتِ طرفِ
> مقابل **همیشه** به‌صورت رمزنگاری‌شده احراز می‌شود، نه با اعتماد به فیلدِ منبعِ جعلی.

---

## معرفی و مدل تهدید

`freespoof` فرض می‌کند یک ناظرِ شبکه‌ی میانی (middlebox / DPI) بین دو انتهای لینک نشسته و
می‌تواند:

- محتوای بسته‌ها را بازرسی کند و پروتکل‌های شناخته‌شده (VPN، TLS مشکوک، الگوهای رمزنگاری‌شده)
  را مسدود یا محدود کند؛
- بر اساس **IP مبدأ/مقصد** و **شماره‌ی پورت** محدودسازی و نرخ‌گیری (rate-limiting) اعمال کند؛
- با **پروبِ فعال (active probing)** به سمتِ سرور، هویتِ یک سرویسِ دورزننده‌ی سانسور را افشا کند؛
- بسته‌ها را **بازپخش (replay)** کند یا ترافیک را برای رمزگشاییِ آینده ذخیره کند
  (تهدیدِ «اکنون جمع کن، بعداً رمزگشایی کن» با کامپیوترِ کوانتومی).

`freespoof` در برابر همه‌ی این‌ها پاسخ دارد:

| تهدید | پاسخِ freespoof |
|-------|----------------|
| بازرسیِ محتوا (DPI) | لایه‌ی `obfs`: padding، شکل‌دهیِ زمانی، تقلیدِ طولِ بسته، اثرانگشتِ TLS، SNI/ECH، ترافیکِ پوششی |
| محدودسازی بر پایه‌ی IP مبدأ | جعلِ منبع با `spoofed_ip` و `spoofed_ip_pool` (چرخشِ منبع)، به‌علاوه‌ی endpoint/port hopping |
| پروبِ فعال | fail-closed (ترافیکِ احراز‌نشده بی‌صدا دور ریخته می‌شود) + decoyِ معکوس به یک سایتِ واقعیِ HTTPS |
| مسدودسازیِ یک ترنسپورت | ۷ ترنسپورتِ قابلِ‌تعویض + failover + transport racing + switch زنده |
| بازپخش | پنجره‌ی ضدبازپخش (anti-replay sliding window) |
| تهدیدِ کوانتومی | دست‌دادنِ هیبریدِ X25519 + ML-KEM (FIPS-203) |

مرزِ امنیتی **همیشه** دست‌دادنِ رمزنگاری‌شده‌ی Noise_IK است؛ جعلِ منبع صرفاً برای مقاومت در
برابرِ تحلیلِ ترافیک و محدودسازیِ IP است و هرگز به‌عنوانِ احرازِ هویت به‌کار نمی‌رود.

---

## ویژگی‌ها

### ترنسپورت‌ها (۷ عدد، قابلِ تفکیکِ uplink/downlink)

| ترنسپورت | پروتکلِ IP | توضیح | جعلِ منبع | mux/FEC |
|----------|-----------|-------|:---------:|:-------:|
| `udp`     | 17 | دیتاگرامِ خام UDP | بله | بله |
| `icmp`    | 1  | ICMP Echo، شبیهِ `ping` | بله | بله |
| `proto58` | 58 | بدونِ هدرِ L4، استتار به شکلِ IPv6-ND | بله | بله |
| `tcp`     | 6  | TCPِ مصنوعی (stack دستی)، با `fake_tls_header` اختیاری | بله | خیر |
| `quic`    | 17 | QUIC/TLS 1.3 واقعی (quinn/ring)، **جعل غیرممکن** | خیر | خیر |
| `ipip`    | 4  | IP-in-IP (RFC 2003) | بله | بله |
| `gre`     | 47 | GRE (RFC 2784)، شبیهِ یک VPNِ GREِ واقعی | بله | خیر |

- `uplink_protocol` و `downlink_protocol` می‌توانند **متفاوت** باشند (مثلاً uplink روی `icmp`
  و downlink روی `udp`).
- `transport_racing`: همه‌ی ترنسپورت‌ها هم‌زمان امتحان می‌شوند و سریع‌ترین نگه داشته می‌شود.
- `failover_order`: فهرستِ مرتبِ ترنسپورت‌هایی که هنگامِ مسدودشدن به آن‌ها سقوط می‌کنیم.
- `switch-transport <kind>`: تعویضِ ترنسپورتِ فعال به‌صورتِ زنده، بدون ری‌استارت.

> **نکته:** `quic` بر پایه‌ی پشته‌ی UDPِ کرنل با path validation و TLSِ گره‌خورده به
> ۴-تایی (4-tuple) است، پس **قابلِ جعل نیست**. اعتبارسنجی هر کانفیگی را که `quic` را با
> جعلِ منبع ترکیب کند رد می‌کند و شما را به تنظیمِ `spoof.no_spoof = true` هدایت می‌کند.
> همچنین `mux`/`fec` فقط روی ترنسپورت‌های دیتاگرامی (`udp`/`icmp`/`proto58`/`ipip`) اعمال
> می‌شوند، نه روی `tcp`/`quic` که خودشان معناشناسیِ جریان/قابل‌اعتماد دارند.

### رمزنگاری

- دست‌دادنِ **Noise_IK** روی X25519 (`Noise_IK_25519_ChaChaPoly_BLAKE2s`) با احرازِ هویتِ
  دوطرفه؛ کلیدِ عمومیِ طرفِ مقابل باید از پیش مشخص باشد (`peer_public_key`).
- لایه‌ی اختیاریِ **PSK** به سبکِ WireGuard (معادلِ IKpsk2) از طریقِ `pre_shared_key`.
- **هیبریدِ پساکوانتومی**: ترکیبِ واقعیِ X25519 + **ML-KEM** (FIPS-203، کریتِ `ml-kem`) با
  سطوحِ `ml_kem_512` / `ml_kem_768` / `ml_kem_1024`. شکستنِ نشست مستلزمِ شکستنِ **هم**
  X25519 و **هم** ML-KEM است.
- **AEAD** به‌ازای هر فریم: `chacha20_poly1305` (پیش‌فرض) یا `aes256_gcm`؛ با
  `aead_auto_hardware = true` در صورتِ وجودِ AES-NI به‌صورتِ خودکار AES-256-GCM انتخاب می‌شود.
- **ضدبازپخش**: پنجره‌ی لغزانِ `replay_window` (پیش‌فرض ۲۰۴۸ فریم؛ مضربِ ۶۴ و حداقل ۶۴).
- **Rekey**: بر پایه‌ی حجم (`rekey_bytes`، پیش‌فرض ۶۴ GiB) یا زمان (`rekey_secs`، پیش‌فرض ۳۶۰۰
  ثانیه)؛ و `rotate-key` برای وادارکردنِ یک دست‌دادنِ تازه به‌صورتِ دستی.
- کلیدها با `zeroize` از حافظه پاک می‌شوند؛ هیچ اولیه‌ی رمزنگاری‌ای دست‌ساز نیست (همه از
  کریت‌های بازبینی‌شده: `snow`، `ml-kem`، RustCrypto، `hkdf`/`sha2`، `subtle`).

### mux و FEC

- **mux** (`[mux]`): دسته‌کردنِ چند بسته‌ی داخلی در یک فریمِ خارجی برای کاهشِ سربار و پنهان‌کردنِ
  مرزِ بسته‌ها (`enable_multiplex`، `multiplex_flush_ms`، `multiplex_max_payload`).
- **FEC** (`[fec]`): تصحیحِ خطای رو به جلو با `xor` (یک‌پاریتی) یا `reed_solomon` (چندپاریتی،
  کریتِ `reed-solomon-erasure`)؛ با `fec_adaptive` میزانِ افزونگی با نرخِ تلفاتِ اندازه‌گیری‌شده
  تطبیق می‌یابد (`fec_group_size`، `fec_parity_shards`).

### مبهم‌سازی (obfs) — کامل

- **padding**: `packet_padding` / `packet_padding_max` (padding تصادفی) و `pad_to_size`
  (پدکردن تا یک اندازه‌ی ثابت).
- **mimicry**: `mimicry_profile` (توزیعِ طولِ بسته شبیهِ `http2`/`http3`/`doh`/`web_socket`/`video_stream`).
- **TTL/DSCP jitter**: `ttl_jitter` و `random_dscp` (انتخابِ تصادفیِ TTL و DSCP به‌ازای هر بسته،
  در لایه‌ی IP خام؛ باید روی هر دو طرف یکسان باشند).
- **timing jitter**: `timing_jitter_ms` (تأخیرِ تصادفیِ بین‌بسته‌ای) و `constant_rate_pps`
  (شکل‌دهیِ نرخِ ثابت).
- **cover / chaff**: `cover_traffic_pps` ترافیکِ پوششیِ ساختگی برای پنهان‌کردنِ الگوی مصرف تولید
  می‌کند (فریم‌های `Chaff` که در مقصد بی‌صدا دور ریخته می‌شوند).
- **fake-TLS**: `fake_tls_header` یک رکوردِ ۵-بایتیِ جعلیِ TLS Application-Data جلوی ترنسپورتِ
  `tcp` می‌گذارد.
- **اثرانگشتِ TLS / SNI / ECH**: `tls_fingerprint` (chrome/firefox/safari/native)، `sni`، و `ech`
  برای پنهان‌کردنِ SNIِ واقعی روی `tcp`/`quic`.
- **decoy ضدپروب**: `decoy_enabled` یک reverse-proxy بالا می‌آورد که ترافیکِ احراز‌نشده را به یک
  سایتِ واقعیِ HTTPS (`decoy_target`) می‌فرستد، تا پروب‌کننده یک وب‌سایتِ مشروع ببیند
  (سبکِ Reality/Trojan).

### کارایی و auto-tune

- تشخیصِ خودکارِ سخت‌افزار (تعداد هسته، RAM، سرعتِ NIC) و تنظیمِ worker threads، `tunnel_count`،
  ظرفیتِ کانال‌ها و mux بر پایه‌ی `perf_mode` (`throughput`/`latency`/`balanced`).
- چند تونلِ موازی (`tunnel_count`)، `cpu_pinning`، تخصیص‌دهنده‌ی `mimalloc`، و بیلدِ
  `target-cpu=native` برای AVX2/AVX-512/NEON.

### قابلیتِ اطمینان

- `auto_reconnect` با backoffِ نمایی (`reconnect_backoff_min_ms` تا `reconnect_backoff_max_ms`).
- `failover_order` و `transport_racing`.
- **endpoint/port hopping**: چرخشِ میان `server_endpoints` روی یک زمان‌بندیِ هماهنگ
  (`endpoint_hop_interval_secs`، نیازمندِ حداقل دو endpoint).
- **connection migration**: بقا در برابرِ تغییرِ IPِ کلاینت (Wi-Fi ↔ cellular)؛ سمتِ سرور فقط
  پس از دریافتِ یک فریمِ **احراز‌شده** از منبعِ جدید به آن مهاجرت می‌کند (`enable_migration`).
- **keepalive / dead-peer**: `keepalive_secs` و `dead_peer_timeout_secs`.

### رصد و کنترل

- اندپوینتِ Prometheus روی `observability.metrics_addr` (`/metrics`) و سلامتِ JSON روی
  `observability.health_addr` (`/health`).
- سوکتِ کنترلِ یونیکس روی `observability.control_socket` (پیش‌فرض `/run/freespoof.sock`) برای
  `freespoof ctl ...`.

### شبکه و امنیتِ میزبان

- دستگاهِ **TUN** (پیش‌فرض `freespoof0`)، مسیریابیِ full یا split، DNS push.
- **NAT/kill-switch**: تنظیمِ خودکارِ sysctl‌ها و قواعدِ nft/iptables؛ kill switch تا یک تونلِ
  قطع‌شده نشت نکند؛ همه‌چیز هنگامِ خروج (teardown) برگردانده می‌شود.
- **drop privileges**: افتِ امتیاز به کاربرِ غیرمجاز با حفظِ `CAP_NET_RAW` + `CAP_NET_ADMIN`.

---

## چطور کار می‌کند

هر بسته‌ی خروجیِ خام IPv4 یک **منبعِ جعلی** (`spoofed_ip`) دارد، اما **مقصدِ آن همیشه آدرسِ
واقعیِ طرفِ مقابل** (`peer_real_ip`) است تا پاسخ‌ها به طرفِ واقعی برسند و مسیریابی کار کند.
هویت نه از روی فیلدِ منبع، بلکه با دست‌دادنِ Noise_IK احراز می‌شود.

مسیرِ داده یک خط‌لوله‌ی کوچک است (padding بخشی از مرحله‌ی seal است چون قبل از رمزنگاری اعمال
می‌شود؛ timing jitter پس از FEC و TTL/DSCP در لایه‌ی IP خام اعمال می‌شوند):

</div>

```text
 egress  (TUN → wire)
 ┌─────┐   ┌───────────┐   ┌─────────────┐   ┌────────────┐   ┌────────────┐   ┌──────────────────────────┐
 │ TUN │─▶ │ mux batch │─▶ │ obfs: pad   │─▶ │ seal(AEAD) │─▶ │ FEC shards │─▶ │ obfs: jitter             │
 │ read│   │ (optional)│   │ (padding)   │   │ encrypt    │   │ + parity   │   │ transport (TTL/DSCP,     │─▶ wire
 └─────┘   └───────────┘   └─────────────┘   └────────────┘   │ (optional) │   │ spoofed src → peer real) │
                                                              └────────────┘   └──────────────────────────┘

 ingress (wire → TUN)
 ┌──────┐   ┌───────────────┐   ┌────────────┐   ┌──────────────┐   ┌─────────────┐   ┌─────┐
 │ wire │─▶ │ transport     │─▶ │ FEC        │─▶ │ open(AEAD)   │─▶ │ strip pad + │─▶ │ TUN │
 │      │   │ recv_from     │   │ reconstruct│   │ + anti-replay│   │ mux debatch │   │write│
 └──────┘   └───────────────┘   │ (optional) │   │ (fail-closed)│   └─────────────┘   └─────┘
                                └────────────┘   └──────────────┘
```

<div dir="rtl">

- در سمتِ **egress** یک تسکِ `tun_to_net` مالکِ شمارنده‌ی tx، انکودرِ FEC و انباشتگرِ mux است
  (بدونِ قفل در مسیرِ داغ). در سمتِ **ingress** تسکِ `net_to_tun` بازسازیِ FEC، رمزگشایی،
  ضدبازپخش و تحویل به TUN را انجام می‌دهد.
- فریم‌های احراز‌نشده/نامعتبر **بی‌صدا دور ریخته می‌شوند** (fail-closed): نه خطایی، نه RST‌ای،
  نه نشانه‌ای برای پروب‌کننده.
- سربارِ هر بسته (هدرِ IPv4 + هدرِ فریم + تگِ AEAD + سربارِ ترنسپورت + FEC) هنگامِ شروعِ نشست
  در لاگ محاسبه و چاپ می‌شود تا بتوانید `mtu` مؤثرِ داخلی را برآورد کنید.

---

## نصب

### نصبِ یک‌خطی (توصیه‌شده)

روی **هر طرف** (سرور و کلاینت) این یک خط را اجرا کنید. پیش‌نیازها را نصب، از سورس بیلد،
باینری‌ها را در `/usr/local/bin` نصب، `setcap` و کاربرِ غیرمجاز و دایرکتوری‌ها و یونیتِ
systemd را به‌صورتِ خودکار آماده می‌کند:

</div>

```bash
curl -fsSL https://raw.githubusercontent.com/MAHDI-byte64/spoof22/main/scripts/install.sh | sudo bash
```

<div dir="rtl">

تا پیش از ادغام در شاخه‌ی `main`، از همان شاخه‌ی توسعه نصب کنید:

</div>

```bash
curl -fsSL "https://raw.githubusercontent.com/MAHDI-byte64/spoof22/claude/affectionate-meitner-fsbvda/scripts/install.sh" \
  | sudo FREESPOOF_REF=claude/affectionate-meitner-fsbvda bash
```

<div dir="rtl">

سپس پیکربندی و راه‌اندازیِ سرویس را به‌صورتِ تعاملی انجام دهید (در یک ترمینالِ واقعی):

</div>

```bash
sudo freespoof-manager
```

<div dir="rtl">

### نصبِ دستی

نیازمندِ **Linux** و قابلیت‌های `CAP_NET_RAW` + `CAP_NET_ADMIN` (برای سوکتِ خام، TUN و
فایروال). دو راه دارید: یا با `root` اجرا کنید، یا با `setcap` این قابلیت‌ها را به باینری بدهید
و با کاربرِ عادی اجرا کنید:

</div>

```bash
sudo setcap cap_net_raw,cap_net_admin+ep /usr/local/bin/freespoof
```

<div dir="rtl">

چون بسته‌های ورودی منبعِ جعلی دارند، `rp_filter` باید روی اینترفیس خاموش باشد. `freespoof`
این sysctl‌ها را **خودش هنگامِ اجرا تنظیم و هنگامِ خروج بازمی‌گرداند** (`rp_filter=0` روی `all`
و اینترفیسِ فیزیکی، `ip_forward=1`، و در صورتِ استفاده از `icmp` نیز `icmp_echo_ignore_all=1`،
و برای `tcp` یک قاعده‌ی دراپِ RST روی `OUTPUT`). اگر خواستید دستی بررسی کنید:

</div>

```bash
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.ip_forward=1
```

<div dir="rtl">

مسیرهای استاندارد استقرار:

- باینری: `/usr/local/bin/freespoof`
- کانفیگ‌ها: `/etc/freespoof/<instance>.toml`
- دایرکتوریِ کار/نصب: `/opt/freespoof`
- سوکتِ کنترل: `/run/freespoof.sock`
- یونیتِ systemd: قالبِ `freespoof@.service` (نامِ instance برابرِ basename کانفیگ است، مثلاً
  `freespoof@server` فایلِ `/etc/freespoof/server.toml` را می‌خواند).

---

## ساخت دستی

نیازمندِ Rust پایدار (stable، حداقلِ مستندشده `1.75`). فایلِ `rust-toolchain.toml` کانالِ
stable را به‌همراهِ `rustfmt`/`clippy` و هدف‌های cross پین می‌کند.

</div>

```bash
# بیلدِ معمولی
cargo build --release

# بیلد با فعال‌سازیِ AVX2/AVX-512/NEON برای مسیرهای crypto/FEC/checksum
RUSTFLAGS="-C target-cpu=native" cargo build --release

# باینریِ استاتیکِ musl (برای کپی روی هر توزیعِ لینوکس بدونِ وابستگی)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl

# ARM64 (استاتیکِ musl یا پیوندِ gnu)
rustup target add aarch64-unknown-linux-musl aarch64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-musl
```

<div dir="rtl">

> دایرکتوریِ `.cargo/config.toml` به‌صورتِ پیش‌فرض برای هدف‌های نیتیوِ میزبان
> (`x86_64`/`aarch64` با `-linux-gnu`) پرچمِ `target-cpu=native` را روشن می‌کند؛ ماتریسِ
> cross-buildِ musl در CI دست‌نخورده می‌ماند.

سه باینری ساخته می‌شود:

- `freespoof` — باینریِ یکپارچه؛ نقش از روی `role` در کانفیگ یا سوییچِ `--role client|server`
  انتخاب می‌شود. زیرفرمان‌های مدیریتی (`genkey`، `pair`، `ctl`) را هم دارد.
- `freespoof-client` — نقشِ قفل‌شده روی `client`.
- `freespoof-server` — نقشِ قفل‌شده روی `server`.

هر سه `--config <path>` (پیش‌فرض `/etc/freespoof/config.toml`) و `--log-level` را می‌پذیرند.

---

## شروع سریع

### ۱) تولیدِ کلید روی **هر دو** طرف

روی سرور و کلاینت (هرکدام جداگانه) یک جفت‌کلیدِ استاتیکِ Noise بسازید:

</div>

```bash
freespoof genkey
# خروجی (base64):
#   static_private_key = "..."
#   static_public_key  = "..."
```

<div dir="rtl">

`static_private_key` را در بخشِ `[crypto]` **همان طرف** بگذارید، و `static_public_key` را به
`peer_public_key` **طرفِ مقابل** بدهید.

### ۲) یک کانفیگِ کوتاهِ سرور

</div>

```toml
role = "server"
log_level = "info"

[spoof]
real_ip = "203.0.113.10"        # IP واقعیِ این میزبان
peer_real_ip = "198.51.100.20"  # IP واقعیِ طرفِ مقابل (کلاینت)
spoofed_ip = "192.0.2.1"        # منبعِ جعلیِ ما
peer_spoofed_ip = "192.0.2.2"   # منبعِ جعلیِ موردانتظار از طرفِ مقابل

[transport]
interface = "eth0"
uplink_protocol = "udp"
downlink_protocol = "udp"
data_port = 51820

[crypto]
static_private_key = "<کلید خصوصیِ سرور از genkey>"
static_public_key  = "<کلید عمومیِ سرور از genkey>"
peer_public_key    = "<کلید عمومیِ کلاینت>"
pq_hybrid = true

[observability]
metrics_addr = "127.0.0.1:9095"
control_socket = "/run/freespoof.sock"
```

<div dir="rtl">

> همه‌ی فیلدها پیش‌فرض دارند؛ فایلِ کمینه هم بار می‌شود و اعتبارسنج خطاهای دقیق می‌دهد.
> اگر نمی‌خواهید جعل کنید، `no_spoof = true` را در `[spoof]` بگذارید (برای `quic` اجباری است).

### ۳) اجرا

</div>

```bash
# سرور
freespoof --config /etc/freespoof/server.toml
# یا با باینریِ قفل‌شده
freespoof-server --config /etc/freespoof/server.toml
```

<div dir="rtl">

### ۴) ساختِ کانفیگِ کلاینت با `pair`

به‌جای نوشتنِ دستیِ کانفیگِ کلاینت، از روی کانفیگِ سرور یک کانفیگِ کلاینت + یک لینکِ اشتراکِ
`freespoof://` بسازید:

</div>

```bash
freespoof pair --server-config /etc/freespoof/server.toml --client-out client.toml
# خروجی‌ها:
#   فایلِ client.toml (آدرس‌دهی آینه‌ای، کلیدِ تازه‌ی کلاینت، کلیدِ عمومیِ سرور پین‌شده)
#   یک لینکِ اشتراک:  freespoof://<base64>
#   کلیدِ عمومیِ کلاینت (hex) — آن را به peer_public_key یا spoof.allowed_peers سرور اضافه کنید
```

<div dir="rtl">

`pair` آدرس‌ها (real/peer و tun) را آینه می‌کند، فیلدهای توافقی (ترنسپورت، پورت، PSK، AEAD،
obfs) را کپی می‌کند، یک جفت‌کلیدِ تازه برای کلاینت می‌سازد و کلیدِ عمومیِ سرور را پین می‌کند.
فراموش نکنید کلیدِ عمومیِ **کلاینت** (که `pair` چاپ می‌کند) را به سمتِ سرور اضافه کنید.

---

## تنظیمِ کارایی

- **`perf.auto_tune = true`** (پیش‌فرض): سخت‌افزار تشخیص داده می‌شود و تعدادِ worker threads،
  `tunnel_count`، ظرفیتِ کانال‌ها و mux به‌صورتِ خودکار تنظیم می‌شوند.
- **`perf.perf_mode`**: سیاستِ auto-tune را تعیین می‌کند:
  - `throughput`: بیشترین موازی‌سازی (تا دو برابرِ هسته‌ها + تقویتِ NIC، سقفِ ۶۴ تونل)، mux روشن.
  - `latency`: worker محدود (حداکثر ۴)، تعدادِ تونلِ کمتر، mux خاموش برای کمینه‌کردنِ تأخیر.
  - `balanced` (پیش‌فرض): حدِ وسط.
- **`perf.tunnel_count`**: وقتی `auto_tune = false` باشد، این مقدار مستقیماً به‌کار می‌رود
  (وگرنه auto-tune آن را بازنویسی می‌کند).
- سایرِ اهرم‌ها: `cpu_pinning`، `runtime_worker_threads`، `channel_capacity`،
  `io_channel_capacity`، `mtu` (پیش‌فرضِ موتور ۱۳۸۰). برای توانِ عبوریِ بالا FEC/mux و بیلدِ
  `target-cpu=native` را در نظر بگیرید.

> در سرعتِ NICِ بالا auto-tune تونل‌های بیشتری اضافه می‌کند (۱G→+۱، ۲G→+۲، ۵G→+۳، ۱۰G→+۴).

---

## نکاتِ امنیتی

- **fail-closed:** هر ترافیکِ احراز‌نشده، نامعتبر، بازپخش‌شده یا با AEADِ شکست‌خورده بی‌صدا دور
  ریخته می‌شود؛ هیچ پاسخی که وجودِ تونل را لو بدهد تولید نمی‌شود. سمتِ سرور نرخِ دست‌دادن را
  به‌ازای هر IP مبدأ محدود می‌کند (`handshake_rate_limit`).
- **احرازِ هویتِ رمزنگاری‌شده، نه فیلدِ منبع:** هویتِ طرفِ مقابل فقط با Noise_IK (و در صورتِ
  فعال‌بودن ML-KEM) تأیید می‌شود. فیلدِ منبعِ جعلی هرگز مبنای اعتماد نیست.
- **محرمانگیِ پساکوانتومی:** با `pq_hybrid = true` نشست تنها در صورتی می‌شکند که **هم** X25519
  و **هم** ML-KEM بشکنند — در برابرِ «اکنون جمع کن، بعداً رمزگشایی کن» مقاوم.
- **zeroize:** کلیدهای خصوصی و موادِ حساس پس از استفاده از حافظه پاک می‌شوند.
- **drop privileges:** با تنظیمِ `hardening.run_as_user` فرایند پس از راه‌اندازی به کاربرِ
  غیرمجاز می‌افتد اما `CAP_NET_RAW`/`CAP_NET_ADMIN` را برای اتصالِ مجدد نگه می‌دارد.
- **کاربرِ مجاز:** `freespoof` را **فقط** روی لینکی به‌کار ببرید که **هر دو سرِ آن را خودتان
  کنترل می‌کنید** و اجازه‌ی قانونیِ ارسالِ بسته با منبعِ جعلی روی آن مسیر را دارید. این ابزار
  برای جعلِ هویت در شبکه‌های دیگران ساخته نشده است.

---

## نکاتِ عملیاتی

### کنترلِ زنده با `ctl`

به یک نمونه‌ی در حالِ اجرا از طریقِ سوکتِ کنترل فرمان بدهید:

</div>

```bash
freespoof ctl --socket /run/freespoof.sock status           # یک خط وضعیت (نقش/ترنسپورت/session id)
freespoof ctl --socket /run/freespoof.sock stats            # متنِ Prometheus از متریک‌های زنده
freespoof ctl --socket /run/freespoof.sock rotate-key       # وادارکردنِ rekey (دست‌دادنِ تازه)
freespoof ctl --socket /run/freespoof.sock switch-transport gre   # تعویضِ ترنسپورتِ فعال
freespoof ctl --socket /run/freespoof.sock reload           # بازخوانیِ کانفیگ در نشستِ بعدی
```

<div dir="rtl">

### سیگنال‌ها

- **SIGHUP**: درخواستِ reload (مانندِ `ctl reload`؛ در نشستِ بعدی اعمال می‌شود).
- **SIGTERM / SIGINT**: خاموشیِ تمیز — تونل تخلیه و فایروال/NAT/مسیریابی بازگردانده می‌شوند.

### لاگ‌ها

سطحِ لاگ با `log_level` یا `--log-level` تنظیم می‌شود (`trace|debug|info|warn|error`). با
`observability.json_logs = true` لاگِ ساختارمندِ JSON در کنارِ لاگِ خوانا تولید می‌شود.

### رصد

</div>

```bash
curl -s http://127.0.0.1:9095/metrics   # متریک‌های Prometheus (freespoof_tx_bytes_total, ...)
curl -s http://127.0.0.1:9096/health    # سلامتِ JSON
```

<div dir="rtl">

### systemd

یونیتِ قالبیِ `freespoof@.service` (در دایرکتوریِ `systemd/`) را نصب کنید؛ نامِ instance برابرِ
basename کانفیگ است:

</div>

```bash
sudo cp systemd/freespoof@.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now freespoof@server   # می‌خواند: /etc/freespoof/server.toml
sudo systemctl reload freespoof@server         # SIGHUP → بازخوانیِ کانفیگ
```

<div dir="rtl">

### Docker

تنظیماتِ Docker در دایرکتوریِ `deploy/` قرار دارد. برای کارِ سوکتِ خام، فایروال و TUN، کانتینر
به `--cap-add=NET_RAW --cap-add=NET_ADMIN` و دستگاهِ `/dev/net/tun` نیاز دارد. برای ترنسپورتِ
`quic`، هم اسکریپت‌های `deploy/` و هم اسکریپتِ مدیریت می‌توانند گواهیِ self-signed بسازند؛ اگر
مسیرهای `quic.cert_path`/`quic.key_path` وجود نداشته باشند، خودِ `freespoof` یک گواهیِ
self-signedِ موقت (ephemeral) هم تولید می‌کند.

---

## نقاطِ توسعه (صادقانه)

بخش‌هایی عمداً به‌عنوانِ «نقطه‌ی توسعه» باقی مانده‌اند — موجود و مستند، اما هنوز به‌طورِ کامل
سیم‌کشی نشده‌اند:

- **congestion با بازخوردِ STATS:** کنترل‌کننده‌های `aimd` و `bbr` (BBR-lite) پیاده‌سازی و
  تست‌شده‌اند و حلقه‌ی بازخوردِ زنده‌ی فریمِ STATS (گزارشِ تحویل/تلفات/RTT از گیرنده به فرستنده)
  به کنترل‌کننده و نرخِ pacing وصل است. `quic` کنترل‌کننده‌ی خودش را دارد و مستقل است.
- **I/Oِ پرشتاب:** مسیرِ ارسالِ دسته‌ایِ سوکتِ خام از `sendmmsg(2)` و مسیرِ دریافت از
  `recvmmsg(2)` استفاده می‌کند (هر دو با fallbackِ خودکار)، و `pin` کردنِ threadهای رانتایم روی
  CPU (آگاه به شمارشِ هسته) در `tune` انجام می‌شود. یک backendِ اختیاریِ `io_uring` پشتِ
  featureِ کارگو (`--features io_uring`) مسیرِ ارسالِ خام را از طریقِ ring می‌بَرَد؛ buildِ
  پیش‌فرض آن را نمی‌کِشد. توجه: `UDP_SEGMENT`/GSO برای سوکت‌های UDPِ متعلق به هسته است و با
  مسیرِ `IP_HDRINCL`ِ ما سازگار نیست؛ به‌جایش با `sendmmsg` دسته‌ای می‌کنیم.
- **اثرانگشتِ TLS (JA3):** روی ترانسپورتِ TCPِ خام که هر بایت را خودمان می‌سازیم، یک
  ClientHelloِ دست‌سازِ مرورگری (Chrome/Firefox، با GREASE، SNI، ALPN، key_share و …)
  به‌عنوانِ اولین سگمنت ارسال می‌شود تا JA3 به‌جای اثرانگشتِ کتابخانه مثلِ یک مرورگرِ واقعی
  دیده شود (`obfs.tls_fingerprint` + `obfs.fake_tls_header`). QUIC از rustls استفاده می‌کند و
  ترتیبِ اکستنشن‌ها در اختیارِ ما نیست.
- **sandbox (Landlock + seccomp):** `hardening.sandbox` یک sandboxِ سیستم‌فایلِ Landlock اعمال
  می‌کند و `hardening.seccomp` یک deny-listِ seccomp-bpf (ردِ فراخوان‌های خطرناک با `EPERM`).
  هر دو best-effort هستند: روی هسته‌ی فاقدِ قابلیت فقط log و رد می‌شوند و هرگز پروسه را نمی‌کشند.

---

## مجوز

`MIT` یا `Apache-2.0` به انتخابِ شما.

</div>
