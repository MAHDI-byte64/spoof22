# مرجع کامل پیکربندی freespoof

<div dir="rtl">

این سند مرجع رسمی و کامل همهٔ کلیدهای پیکربندی `freespoof` است. منبع حقیقت، فایل
`src/config/mod.rs` (شِمای کامل) و `src/config/validate.rs` (قوانین اعتبارسنجی) است و
هر مقدار پیش‌فرض در این سند مستقیماً از پیاده‌سازی‌های `Default` در همان فایل‌ها استخراج
شده است.

## قرارداد کلی

- پیکربندی یک فایل **TOML** است که بین کلاینت و سرور **مشترک** است؛ نقش (role) و
  آدرس‌ها تفاوت دو طرف را مشخص می‌کنند.
- همهٔ فیلدها `#[serde(default)]` دارند، پس یک فایل حداقلی هم بارگذاری می‌شود و مقادیر
  نبودن‌شان از پیش‌فرض‌های جدول‌های زیر پر می‌شود.
- **نام کلیدها (key) و مقادیر enum همیشه انگلیسی هستند** (طبق مشخصات پروژه)؛ فقط توضیحات
  انسانی فارسی است.
- پس از بارگذاری، تابع `normalize()` چند مقدار مشتق را تنظیم می‌کند (پایین‌تر توضیح داده
  شده) و سپس `validate()` اجرا می‌شود و خطاهای دقیق می‌دهد.
- فایل با سه بخش بی‌جدول در سطح بالا شروع می‌شود (`role`، `log_level`،
  `protocol_version`) و سپس جدول‌های `[spoof]`، `[transport]`، `[crypto]`، `[tun]`،
  `[obfs]`، `[mux]`، `[fec]`، `[perf]`، `[reliability]`، `[observability]`، `[quic]`،
  `[hardening]` می‌آید.

> ⚠️ **راهنمای نوع‌ها:** ستون «نوع» نوع TOML را نشان می‌دهد. `IPv4` یعنی یک رشتهٔ آدرس
> IPv4 مانند `"203.0.113.10"`. `IPv4:port` یک `ip:port` مانند `"203.0.113.10:51820"`
> است. «فهرست enum» یعنی مقدار باید دقیقاً یکی از کلیدواژه‌های مجاز فهرست‌شده باشد.

---

## کلیدهای سطح بالا (top-level)

| کلید | نوع | پیش‌فرض | توضیح |
|------|-----|---------|-------|
| `role` | enum: `client` \| `server` | `client` | طرفی که این پروسه در تونل است. با فلگ `--role` در خط فرمان قابل بازنویسی است؛ مقدار CLI بر فایل اولویت دارد. |
| `log_level` | enum: `trace` \| `debug` \| `info` \| `warn` \| `error` | `info` | سطح لاگ. با فلگ `--log-level` قابل بازنویسی است. مقادیر دیگر رد می‌شوند. |
| `protocol_version` | integer (u8) | `1` | نسخهٔ پروتکل روی سیم که این بیلد می‌فهمد و در handshake مذاکره می‌شود. در فایل صرفاً اطلاعاتی است؛ موتور آن را به `PROTOCOL_VERSION` همین بیلد (اکنون `1`) محدود می‌کند. |

---

## `[spoof]` — جعل IP و آدرس‌دهی

| کلید | نوع | پیش‌فرض | توضیح |
|------|-----|---------|-------|
| `real_ip` | IPv4 | `0.0.0.0` | آدرس واقعی این میزبان روی کارت شبکهٔ فیزیکی. **اجباری**؛ باید تنظیم شود. |
| `peer_real_ip` | IPv4 | `0.0.0.0` | آدرس واقعی طرف مقابل. بسته‌ها همیشه به اینجا فرستاده می‌شوند تا پاسخ‌ها به طرف واقعی برسند؛ هویت طرف به‌صورت رمزنگارانه تأیید می‌شود. **اجباری**. |
| `spoofed_ip` | IPv4 | `0.0.0.0` | آدرس **مبدأِ جعلی** که روی بسته‌های خام خروجی ما حک می‌شود. در حالت جعل اجباری است (مگر `no_spoof = true`). |
| `peer_spoofed_ip` | IPv4 | `0.0.0.0` | مبدأ جعلیِ طرف مقابل، یعنی چیزی که انتظار داریم *ببینیم* (هرگز مورد اعتماد نیست). در حالت جعل اجباری است. |
| `allowed_peers` | list\<string\> | `[]` (خالی) | کلیدهای عمومی استاتیک مجاز طرف‌ها به‌صورت **hex** (X25519، ۳۲ بایت). خالی = هر طرفی که handshake را با کلید پیکربندی‌شده بگذراند پذیرفته می‌شود. |
| `spoofed_ip_pool` | list\<IPv4\> | `[]` (خالی) | مجموعهٔ آدرس‌های مبدأ جعلی برای چرخش به‌ازای هر session، جهت متنوع‌کردن الگوی ترافیک و مقاومت در برابر محدودسازی نرخ به‌ازای مبدأ. خالی = فقط `spoofed_ip`. |
| `no_spoof` | boolean | `false` | وقتی `true` باشد جعل غیرفعال می‌شود: اعتبارسنج `spoofed_ip = real_ip` و `peer_spoofed_ip = peer_real_ip` را اجبار می‌کند و `spoofed_ip_pool` پاک می‌شود. برای ترنسپورت QUIC **اجباری** است. |

---

## `[transport]` — ترنسپورت‌های روی سیم و انتخاب نقطهٔ اتصال

| کلید | نوع | پیش‌فرض | توضیح |
|------|-----|---------|-------|
| `interface` | string | `"eth0"` | کارت شبکهٔ فیزیکی که سوکت خام به آن bind می‌شود. باید تنظیم و غیرخالی باشد. |
| `uplink_protocol` | enum ترنسپورت | `udp` | ترنسپورت مسیر رو به بالا (client→server). یکی از `udp` \| `icmp` \| `proto58` \| `tcp` \| `quic` \| `ipip` \| `gre`. |
| `downlink_protocol` | enum ترنسپورت | `udp` | ترنسپورت مسیر رو به پایین (server→client). همان مجموعهٔ مقادیر. مسیرهای بالا و پایین می‌توانند جدا باشند. |
| `data_port` | integer (u16) | `51820` | پورت لایهٔ ۴ که ترنسپورت‌های udp/tcp/quic استفاده می‌کنند؛ باید روی هر دو طرف یکی باشد. باید غیرصفر باشد. |
| `shuffle_data_port` | boolean | `false` | چرخش پورت داده طبق زمان‌بندی (فقط udp/tcp، هرگز با QUIC). |
| `shuffle_port_min` | integer (u16) | `20000` | کف بازهٔ پورت برای چرخش. هنگام چرخش باید غیرصفر و کوچک‌تر از `shuffle_port_max` باشد. |
| `shuffle_port_max` | integer (u16) | `60000` | سقف بازهٔ پورت برای چرخش. |
| `icmp_id` | integer (u16) | `4660` (`0x1234`) | شناسهٔ ICMP Echo برای ترنسپورت `icmp`. |
| `randomize_icmp_id` | boolean | `true` | تصادفی‌کردن `icmp_id` به‌ازای هر session (با ترافیک واقعی ping ترکیب می‌شود). |
| `server_endpoints` | list\<IPv4:port\> | `[]` (خالی) | نقاط اتصال سرور که اپراتور کنترل می‌کند و می‌توان بین‌شان جابه‌جا شد (`ip:port`). اولی اصلی است. خالی = یک نقطه از `peer_real_ip:data_port` مشتق می‌شود (در `normalize()`). |
| `endpoint_hop_interval_secs` | integer (u64) | `0` | ثانیه بین جابه‌جایی نقطهٔ اتصال/پورت (۰ = غیرفعال). مقدار `> 0` حداقل دو عضو در `server_endpoints` می‌خواهد. |
| `transport_racing` | boolean | `false` | مسابقهٔ همهٔ ترنسپورت‌های پیکربندی‌شده هنگام راه‌اندازی و نگه‌داشتن سریع‌ترین برای برقراری؛ بقیه نامزد failover می‌شوند. |
| `failover_order` | list\<enum ترنسپورت\> | `[]` (خالی) | فهرست مرتب failover؛ موتور در صورت مسدودشدن/اتلاف به بعدی تنزل می‌کند. |

---

## `[crypto]` — handshake، AEAD، rekey، پساکوانتومی

| کلید | نوع | پیش‌فرض | توضیح |
|------|-----|---------|-------|
| `static_private_key` | string (base64) | `""` (خالی) | کلید خصوصی استاتیک Noise این میزبان (X25519)، base64. **اجباری** برای اجرا؛ با `freespoof genkey` یا manager تولید می‌شود. باید به ۳۲ بایت دیکد شود. |
| `static_public_key` | string (base64) | `""` (خالی) | کلید عمومی استاتیک Noise این میزبان (X25519)، base64. صرفاً اطلاعاتی. |
| `peer_public_key` | string (base64) | `""` (خالی) | کلید عمومی استاتیک Noise طرف مقابل (X25519)، base64. **اجباری** برای handshake نوع Noise_IK. باید به ۳۲ بایت دیکد شود. |
| `pre_shared_key` | string | `""` (خالی) | لایهٔ متقارن اضافی اختیاری که در handshake مخلوط می‌شود (سبک WireGuard، یعنی IKpsk2). base64 یا عبارت عبور؛ خالی = بدون لایهٔ PSK. |
| `aead` | enum: `chacha20_poly1305` \| `aes256_gcm` | `chacha20_poly1305` | ساختار AEAD به‌ازای هر فریم. |
| `aead_auto_hardware` | boolean | `true` | انتخاب خودکار AES-256-GCM وقتی CPU از AES-NI پشتیبانی کند. |
| `pq_hybrid` | boolean | `true` | فعال‌کردن handshake هیبریدی پساکوانتومی X25519 + ML-KEM. |
| `pq_level` | enum: `ml_kem512` \| `ml_kem768` \| `ml_kem1024` | `ml_kem768` | مجموعه‌پارامتر ML-KEM برای هیبرید. |
| `rekey_bytes` | integer (u64) | `68719476736` (۶۴ GiB) | پس از این تعداد بایت روی یک session، کلید دوباره تولید می‌شود (۰ = غیرفعال). |
| `rekey_secs` | integer (u64) | `3600` | پس از این تعداد ثانیه روی یک session، rekey انجام می‌شود (۰ = غیرفعال). اگر غیرصفر باشد باید `>= 10` باشد. |
| `replay_window` | integer (u32) | `2048` | پهنای پنجرهٔ لغزان ضدِ-replay برحسب فریم. باید `>= 64` و مضربی از ۶۴ باشد. |

---

## `[tun]` — دستگاه TUN، مسیریابی، NAT، فایروال

| کلید | نوع | پیش‌فرض | توضیح |
|------|-----|---------|-------|
| `tun_name` | string | `"freespoof0"` | نام رابط TUN (حداکثر ۱۵ کاراکتر، حداقل ۱). |
| `tun_ip` | IPv4 | `10.66.0.1` | آدرس TUN این طرف (لینک نقطه‌به‌نقطه /30). بین دو طرف **جابه‌جا (swap)** می‌شود. |
| `tun_peer_ip` | IPv4 | `10.66.0.2` | آدرس TUN طرف مقابل. بین دو طرف **جابه‌جا** می‌شود. باید با `tun_ip` متفاوت و در همان زیرشبکه باشد. |
| `tun_netmask` | IPv4 | `255.255.255.252` (/30) | ماسک شبکهٔ TUN (لینک نقطه‌به‌نقطه از /30 استفاده می‌کند). |
| `tun_mtu` | integer (u32) | `1380` | MTU داخلی روی دستگاه TUN؛ به `mtu` موتور محدود (clamp) می‌شود. باید `>= 576` باشد. |
| `forward_ports` | list\<u16\> | `[]` (خالی) | پورت‌هایی که به `tun_peer_ip` ترجمهٔ NAT/فوروارد می‌شوند (TCP+UDP). خالی = همهٔ پورت‌ها. |
| `routing_mode` | enum: `full` \| `split` | `full` | وضعیت مسیریابی. `full` = همهٔ ترافیک از تونل؛ `split` = فقط CIDR/پورت‌های پیکربندی‌شده. |
| `split_cidrs` | list\<string\> | `[]` (خالی) | CIDRهای حالت split-tunnel (مثلاً `"10.0.0.0/8"`). در حالت `split` حداقل یک `split_cidrs` یا `split_ports` لازم است. |
| `split_ports` | list\<u16\> | `[]` (خالی) | پورت‌های حالت split-tunnel. |
| `dns_servers` | list\<IPv4\> | `["1.1.1.1", "9.9.9.9"]` | سرورهای DNS که برای تونل push/بازنویسی می‌شوند. |
| `dns_over_https` | boolean | `false` | رِزالو کردن نام‌های خودِ تونل روی DoH/DoT. |
| `kill_switch` | boolean | `true` | نصب kill switch تا اگر تونل افتاد ترافیک روی NIC نشت نکند. |

---

## `[obfs]` — مبهم‌سازی ضدِ-DPI، تقلید و شکل‌دهی

| کلید | نوع | پیش‌فرض | توضیح |
|------|-----|---------|-------|
| `packet_padding` | integer (usize) | `0` | حداقل بایت‌های لایه‌گذاری تصادفی که به هر فریم اضافه می‌شود (۰ = خاموش). باید `<= packet_padding_max` باشد. |
| `packet_padding_max` | integer (usize) | `64` | سقف لایه‌گذاری تصادفی (به‌ازای هر فریم مقداری در بازهٔ `1..=max` انتخاب می‌شود). |
| `ttl_jitter` | list\<u8\> | `[64, 128, 255]` | مقادیر TTL که تصادفی به‌ازای هر بسته انتخاب می‌شوند (**باید روی هر دو طرف یکی باشد**). هیچ مقداری نباید صفر باشد. |
| `fake_tls_header` | boolean | `false` | افزودن یک رکورد جعلی ۵-بایتی TLS Application-Data در ترنسپورت TCP. |
| `random_dscp` | list\<u8\> | `[0, 40, 16]` (`0x00, 0x28, 0x10`) | کدنقاط DSCP که تصادفی به‌ازای هر بسته انتخاب می‌شوند. |
| `timing_jitter_ms` | integer (u64) | `0` | سقف جیتر زمان‌بندی بین بسته‌ها برحسب میلی‌ثانیه (۰ = خاموش). |
| `constant_rate_pps` | integer (u64) | `0` | شکل‌دهی با نرخ ثابت: ارسال با کادنس ثابت بسته (۰ = خاموش). |
| `pad_to_size` | integer (usize) | `0` | لایه‌گذاری هر فریم تا این اندازهٔ ثابت (۰ = خاموش). اگر غیرصفر باشد باید `>= 64` باشد. |
| `mimicry_profile` | enum: `none` \| `http2` \| `http3` \| `doh` \| `web_socket` \| `video_stream` | `none` | پروفایل تقلیدِ توزیع طول بسته‌ها. |
| `tls_fingerprint` | enum: `chrome` \| `firefox` \| `safari` \| `native` | `chrome` | اثرانگشت TLS برای تقلید روی tcp/quic (سبک uTLS). `native` = بدون بازشکل‌دهی (توصیه نمی‌شود). |
| `sni` | string | `"www.cloudflare.com"` | مقدار SNI که ترنسپورت‌های tcp/quic ارائه می‌دهند. |
| `ech` | boolean | `false` | استفاده از Encrypted Client Hello برای پنهان‌کردن SNI واقعی (در صورت پشتیبانی). |
| `cover_traffic_pps` | integer (u64) | `0` | تولید ترافیک پوششی/chaff برای پنهان‌کردن الگوی مصرف (۰ = خاموش). |
| `decoy_enabled` | boolean | `false` | طعمهٔ ضدِ-پروبِ فعال: پراکسی معکوسِ ترافیک احرازنشده به یک سایت واقعی HTTPS تا پروب‌کننده‌ها یک وب‌سایت معتبر ببینند (سبک Reality/Trojan). |
| `decoy_target` | string (`host:port`) | `"www.cloudflare.com:443"` | مقصد بالادستِ طعمه برای پراکسی معکوس. وقتی `decoy_enabled = true` باشد باید غیرخالی باشد. |
| `decoy_listen` | string (`ip:port`) | `""` (خالی) | آدرسی که پراکسی طعمه روی آن گوش می‌دهد (سمت سرور). خالی = از `real_ip:443` مشتق می‌شود. |

---

## `[mux]` — دسته‌بندی بسته‌ها (batching)

| کلید | نوع | پیش‌فرض | توضیح |
|------|-----|---------|-------|
| `enable_multiplex` | boolean | `false` | فعال‌کردن مالتی‌پلکس/دسته‌بندی بسته‌ها. فقط روی ترنسپورت‌های udp/icmp/proto58/ipip معنا دارد. |
| `multiplex_flush_ms` | integer (u64) | `1` | تخلیهٔ دسته پس از این تعداد میلی‌ثانیه حتی اگر پر نشده باشد. |
| `multiplex_max_payload` | integer (usize) | `1200` | حداکثر بایت payload در هر فریم روی سیم هنگام دسته‌بندی. وقتی مالتی‌پلکس فعال است باید `>= 256` باشد. |

---

## `[fec]` — تصحیح خطای رو به جلو (Forward Error Correction)

| کلید | نوع | پیش‌فرض | توضیح |
|------|-----|---------|-------|
| `enable_fec` | boolean | `false` | فعال‌کردن FEC. فقط روی ترنسپورت‌های udp/icmp/proto58/ipip پشتیبانی می‌شود (نه tcp/quic). |
| `fec_group_size` | integer (usize) | `8` | تعداد شاردهای داده در هر گروه FEC. باید `>= 2` باشد. |
| `fec_mode` | enum: `xor` \| `reed_solomon` | `reed_solomon` | طرح کدگذاری. `xor` = تک‌توازی (بازیابی یک اتلاف در هر گروه)؛ `reed_solomon` = بازیابی چند اتلاف. |
| `fec_adaptive` | boolean | `true` | تطبیق میزان افزونگی با نرخ اتلاف اندازه‌گیری‌شده. |
| `fec_parity_shards` | integer (usize) | `2` | تعداد شاردهای توازن برای حالت Reed-Solomon (حالت adaptive آن را درون بازه تنظیم می‌کند). وقتی FEC فعال است باید `>= 1` باشد و `fec_group_size + fec_parity_shards <= 255` (محدودیت GF(2^8)). |

---

## `[perf]` — موازی‌سازی، تنظیم خودکار، بافرها

| کلید | نوع | پیش‌فرض | توضیح |
|------|-----|---------|-------|
| `tunnel_count` | integer (usize) | `4` | تعداد جریان‌های تونل مستقل موازی (با `auto_tune` بازنویسی می‌شود). اگر `auto_tune = false` باشد باید `>= 1` باشد. |
| `auto_tune` | boolean | `true` | شناسایی CPU/RAM/NIC و تنظیم خودکار نخ‌های کارگر، تعداد تونل و ظرفیت‌ها. |
| `perf_mode` | enum: `throughput` \| `latency` \| `balanced` | `balanced` | وضعیت کارایی مورد استفادهٔ تنظیم‌کنندهٔ خودکار. |
| `mtu` | integer (u32) | `1380` | MTU مؤثر موتور (کلمپ برای همهٔ موارد داخلی). باید در بازهٔ `576..=9000` باشد. |
| `channel_capacity` | integer (usize) | `1024` | ظرفیت کانال داخلی. باید غیرصفر باشد. |
| `io_channel_capacity` | integer (usize) | `2048` | ظرفیت کانال ورودی/خروجی. باید غیرصفر باشد. |
| `runtime_worker_threads` | integer (usize) | `0` | تعداد نخ‌های کارگر Tokio (۰ = خودکار / برابر تعداد هسته‌ها). |
| `cpu_pinning` | boolean | `false` | پین‌کردن نخ‌های کارگر به CPUها در توان‌عبوری بالا (best effort). |
| `io_uring` | boolean | `false` | استفاده از بک‌اند io_uring در صورت موجودبودن (best effort؛ در غیر این صورت fallback). |

---

## `[reliability]` — کنترل ازدحام، keepalive، مهاجرت، اتصال مجدد

| کلید | نوع | پیش‌فرض | توضیح |
|------|-----|---------|-------|
| `congestion` | enum: `bbr` \| `aimd` \| `none` | `bbr` | کنترل‌کنندهٔ ازدحام روی مسیرهای سفارشی (غیر-QUIC). `bbr` = مدل‌محور سبک BBR؛ `aimd` = کلاسیک؛ `none` = غیرفعال (ترنسپورت‌های QUIC همیشه کنترل خودشان را نگه می‌دارند). |
| `keepalive_secs` | integer (u64) | `15` | فاصلهٔ keepalive/heartbeat برحسب ثانیه (۰ = خاموش). |
| `dead_peer_timeout_secs` | integer (u64) | `60` | اعلام مرگِ طرف مقابل پس از این تعداد ثانیه بدون ترافیک. |
| `auto_reconnect` | boolean | `true` | اتصال مجدد خودکار با backoff نمایی هنگام افت تونل. |
| `reconnect_backoff_min_ms` | integer (u64) | `500` | کف backoff اتصال مجدد برحسب میلی‌ثانیه. |
| `reconnect_backoff_max_ms` | integer (u64) | `30000` | سقف backoff اتصال مجدد برحسب میلی‌ثانیه. |
| `enable_migration` | boolean | `true` | زنده‌ماندن در برابر تغییر IP کلاینت (Wi-Fi↔cellular) با کلید session id. |

---

## `[observability]` — متریک‌ها، سوکت کنترل، لاگ اضافی

| کلید | نوع | پیش‌فرض | توضیح |
|------|-----|---------|-------|
| `metrics_addr` | string (`ip:port`) | `""` (خالی = غیرفعال) | آدرس گوش‌دادن Prometheus روی `/metrics`. |
| `health_addr` | string (`ip:port`) | `""` (خالی = غیرفعال) | آدرس گوش‌دادن سلامت/وضعیت روی `/health`. |
| `control_socket` | string (مسیر) | `"/run/freespoof.sock"` | سوکت Unix کنترل برای CLI مدیریتی (`freespoof ctl`). خالی = غیرفعال. |
| `json_logs` | boolean | `false` | انتشار لاگ‌های ساختاریافتهٔ JSON در کنار لاگ‌های خوانا. |
| `handshake_rate_limit` | integer (u32) | `30` | سمت سرور: حداکثر تلاش handshake به‌ازای هر IP مبدأ در هر دقیقه. |

---

## `[quic]` — ویژگی‌های اختصاصی ترنسپورت QUIC

| کلید | نوع | پیش‌فرض | توضیح |
|------|-----|---------|-------|
| `cert_path` | string (مسیر) | `"/etc/freespoof/quic-cert.pem"` | مسیر زنجیرهٔ گواهی PEM (سرور). توسط manager تولید می‌شود. اگر مسیر گواهی/کلید موجود نباشد، freespoof یک گواهی زودگذر (ephemeral) خودامضا تولید می‌کند. |
| `key_path` | string (مسیر) | `"/etc/freespoof/quic-key.pem"` | مسیر کلید خصوصی PEM (سرور). |
| `server_name` | string | `"www.cloudflare.com"` | نام سروری که کلاینت تأیید می‌کند / ارائه می‌شود. |
| `connection_window` | integer (u64) | `134217728` (۱۲۸ MiB) | پنجرهٔ کنترل‌جریان در سطح اتصال برحسب بایت. |
| `stream_window` | integer (u64) | `16777216` (۱۶ MiB) | پنجرهٔ کنترل‌جریان به‌ازای هر stream برحسب بایت. |

---

## `[hardening]` — افت امتیاز و sandbox

| کلید | نوع | پیش‌فرض | توضیح |
|------|-----|---------|-------|
| `run_as_user` | string | `""` (خالی = بدون افت) | پس از گرفتن caps/سوکت‌ها/فایروال، به این کاربر افت امتیاز شود (خالی = بدون افت). |
| `run_as_group` | string | `""` (خالی) | پس از راه‌اندازی به این گروه افت شود (خالی = از کاربر مشتق می‌شود). |
| `sandbox` | boolean | `false` | اعمال sandbox سیستم‌فایل با **Landlock** پس از init: دسترسی خواندنی به مسیرهای سیستمیِ لازم و نوشتنی فقط به `/run`، `/var`، `/tmp`. best-effort؛ هسته‌ی فاقد Landlock فقط log و رد می‌شود. |
| `seccomp` | boolean | `false` | نصب **deny-list** فراخوان‌های سیستمی با seccomp-bpf پس از افت امتیاز: فراخوان‌های خطرناک (ptrace، بارگذاری ماژول، mount، kexec، bpf، keyring، `process_vm_*`، userfaultfd و …) با `EPERM` رد می‌شوند. هرگز پروسه را نمی‌کشد؛ best-effort. |

---

## مرجع مقادیر enum

برای راحتی، مقادیر مجاز هر نوع enum (همه انگلیسی، دقیقاً همان‌طور که در TOML نوشته می‌شوند):

- **Role (`role`):** `client`، `server`
- **TransportKind (`uplink_protocol`، `downlink_protocol`، `failover_order`):** `udp` (IP proto 17)، `icmp` (proto 1)، `proto58` (proto 58، بدون سرآیند L4)، `tcp` (proto 6، TCP ساختگی با fake-TLS اختیاری)، `quic` (UDP + QUIC/TLS 1.3 واقعی)، `ipip` (proto 4)، `gre` (proto 47)
- **AeadKind (`aead`):** `chacha20_poly1305`، `aes256_gcm`
- **PqLevel (`pq_level`):** `ml_kem512`، `ml_kem768`، `ml_kem1024`
- **FecMode (`fec_mode`):** `xor`، `reed_solomon`
- **RoutingMode (`routing_mode`):** `full`، `split`
- **PerfMode (`perf_mode`):** `throughput`، `latency`، `balanced`
- **CongestionKind (`congestion`):** `bbr`، `aimd`، `none`
- **MimicryProfile (`mimicry_profile`):** `none`، `http2`، `http3`، `doh`، `web_socket`، `video_stream`
- **TlsFingerprint (`tls_fingerprint`):** `chrome`، `firefox`، `safari`، `native`

---

## قوانین نرمال‌سازی خودکار (`normalize()`)

قبل از اعتبارسنجی، این مقادیر مشتق به‌صورت خودکار (و idempotent) تنظیم می‌شوند:

- `protocol_version` همیشه به `PROTOCOL_VERSION` همین بیلد محدود می‌شود (هر مقدار فایل بازنویسی می‌شود).
- اگر `spoof.no_spoof = true` باشد: `spoofed_ip = real_ip`، `peer_spoofed_ip = peer_real_ip` و `spoofed_ip_pool` پاک می‌شود. **توجه:** QUIC اینجا به‌صورت خودکار بازنویسی **نمی‌شود**؛ ترکیب QUIC با جعل باید توسط اعتبارسنج *رد* شود تا اپراتور عمداً `no_spoof = true` بگذارد.
- اگر `tun.tun_mtu > perf.mtu` باشد، `tun_mtu` به `perf.mtu` کلمپ می‌شود.
- اگر `transport.server_endpoints` خالی باشد و `peer_real_ip` تنظیم شده باشد، نقطهٔ اصلی از `peer_real_ip:data_port` مشتق و افزوده می‌شود.

---

## قوانین اعتبارسنجی محلی (یک‌طرفه)

این قوانین روی فایل یک طرف قابل بررسی هستند و بارگذاری را در صورت تخلف ناموفق می‌کنند
(منبع: `src/config/validate.rs`):

- `log_level` باید یکی از `trace|debug|info|warn|error` باشد.
- `spoof.real_ip` و `spoof.peer_real_ip` باید تنظیم شوند و باهم متفاوت باشند.
- اگر `no_spoof = false`: هم `spoofed_ip` و هم `peer_spoofed_ip` باید تنظیم شوند.
- هر عضو `allowed_peers` باید hex معتبر و پس از دیکد دقیقاً ۳۲ بایت باشد.
- `transport.interface` باید غیرخالی و `transport.data_port` باید غیرصفر باشد.
- اگر `shuffle_data_port = true`: `shuffle_port_min` و `shuffle_port_max` غیرصفر، `min < max`، **با QUIC ناسازگار**، و هر دو جهت باید `udp` یا `tcp` باشند.
- اگر `endpoint_hop_interval_secs > 0`: حداقل دو عضو در `server_endpoints` لازم است.
- `crypto.static_private_key` اجباری و base64 با دیکد ۳۲ بایت؛ `crypto.peer_public_key` اجباری و base64 با دیکد ۳۲ بایت.
- `rekey_secs` باید `0` یا `>= 10` باشد.
- `replay_window` باید `>= 64` و مضرب ۶۴ باشد.
- `tun_name` باید ۱ تا ۱۵ کاراکتر باشد؛ `tun_ip != tun_peer_ip`؛ هر دو در همان زیرشبکهٔ `tun_netmask`؛ `tun_mtu >= 576`.
- در حالت `routing_mode = split` حداقل یک `split_cidrs` یا `split_ports` لازم است.
- `obfs.packet_padding <= obfs.packet_padding_max`؛ مقادیر `ttl_jitter` غیرصفر؛ `pad_to_size` برابر `0` یا `>= 64`؛ اگر `decoy_enabled = true` آنگاه `decoy_target` غیرخالی.
- اگر `enable_fec = true`: `fec_group_size >= 2`، `fec_parity_shards >= 1`، `fec_group_size + fec_parity_shards <= 255`، و حداقل یک جهت باید ترنسپورت پشتیبان mux/FEC (udp/icmp/proto58/ipip) داشته باشد.
- اگر `enable_multiplex = true`: `multiplex_max_payload >= 256`.
- اگر `auto_tune = false`: `tunnel_count >= 1`؛ `mtu` در بازهٔ `576..=9000`؛ ظرفیت‌های کانال غیرصفر.
- اگر هر جهت QUIC باشد، `spoof.no_spoof` باید `true` باشد وگرنه پیکربندی رد می‌شود.

---

## قوانین توافق دو طرف (cross-side agreement rules)

یک فایل تنهایی نمی‌تواند فایل طرف مقابل را ببیند؛ بنابراین بخش‌های محلیِ قابل‌بررسی در
اعتبارسنج اجبار می‌شوند و بقیه در زمان handshake (از طریق هش پارامترها) مذاکره و تأیید
می‌شوند. برای اینکه تونل برقرار شود، کلاینت و سرور **باید** در موارد زیر هماهنگ باشند.
(تأییدشده در برابر `src/config/mod.rs` و `src/config/validate.rs`.)

### الف) فیلدهایی که باید روی هر دو طرف **یکسان** باشند

این‌ها جهت‌های مطلق یا پارامترهای مشترک روی‌سیم را توصیف می‌کنند، نه مقادیر نسبی:

- `transport.uplink_protocol` — باید یکی باشد (هر دو طرف دربارهٔ ترنسپورت client→server توافق دارند).
- `transport.downlink_protocol` — باید یکی باشد (ترنسپورت server→client).
- `transport.data_port` — باید روی هر دو طرف یکی باشد (udp/tcp/quic).
- `transport.icmp_id` — باید یکی باشد، مگر `randomize_icmp_id = true` که آنگاه به‌ازای هر session مذاکره می‌شود.
- `crypto.pre_shared_key` (PSK) — اگر از لایهٔ PSK سبک WireGuard (IKpsk2) استفاده می‌شود باید دقیقاً یکی باشد؛ در غیر این صورت هر دو باید خالی باشند.
- `crypto.aead` — ساختار AEAD باید یکی باشد (مگر از طریق `aead_auto_hardware` به‌طور سازگار مذاکره شود).
- `crypto.pq_hybrid` و `crypto.pq_level` — انتخاب هیبرید پساکوانتومی و سطح ML-KEM باید هماهنگ باشد.
- تنظیمات `[obfs]` که روی ریخت روی‌سیم اثر می‌گذارند باید یکی باشند؛ به‌ویژه:
  - `obfs.ttl_jitter` — طبق مستندِ فیلد **باید روی هر دو طرف یکی باشد**.
  - `obfs.fake_tls_header`، `obfs.packet_padding` / `obfs.packet_padding_max`، `obfs.pad_to_size`، `obfs.random_dscp`، `obfs.mimicry_profile`، `obfs.tls_fingerprint`، `obfs.sni`، `obfs.ech` — باید هماهنگ باشند تا هر دو طرف همان قالب فریم را رمزگشایی/بازسازی کنند.
- `protocol_version` — در handshake مذاکره می‌شود و باید سازگار باشد (هر دو به `PROTOCOL_VERSION` بیلد کلمپ می‌شوند).

### ب) فیلدهایی که باید بین دو طرف **جابه‌جا/آینه (mirror/swap)** شوند

مقدار هر فیلد روی یک طرف باید برابر مقدار فیلد متناظرِ *قرینه* روی طرف دیگر باشد:

- آدرس‌های واقعی:
  - `spoof.real_ip` طرف A == `spoof.peer_real_ip` طرف B، و برعکس.
- آدرس‌های جعلی:
  - `spoof.spoofed_ip` طرف A == `spoof.peer_spoofed_ip` طرف B، و برعکس.
- آدرس‌های TUN (لینک نقطه‌به‌نقطه /30):
  - `tun.tun_ip` طرف A == `tun.tun_peer_ip` طرف B، و برعکس. (محلی: `tun_ip != tun_peer_ip` و هر دو در همان زیرشبکه — توسط اعتبارسنج بررسی می‌شود.)
- کلیدهای عمومی استاتیک:
  - `crypto.peer_public_key` هر طرف باید برابر `crypto.static_public_key` طرف مقابل باشد (برای Noise_IK).
  - در صورت استفاده از `spoof.allowed_peers` روی سرور، باید شامل کلید عمومی کلاینت باشد (خروجی `freespoof pair` آن را چاپ می‌کند).

### ج) ترکیب‌های ممنوع (توسط اعتبارسنج رد می‌شوند)

- **QUIC + جعل ممنوع است:** اگر `uplink_protocol` یا `downlink_protocol` برابر `quic` باشد، باید `spoof.no_spoof = true` باشد. QUIC به مسیریابی واقعی و TLS گره‌خورده به ۴-تاپل متکی است و به‌جای جعل مبدأ از تقلید TLS/ECH استفاده می‌کند.
- **shuffle + QUIC ممنوع است:** `transport.shuffle_data_port = true` با ترنسپورت QUIC ناسازگار است (و فقط روی udp/tcp در هر دو جهت مجاز است).

### د) اندازه‌گذاری گروه FEC و پشتیبانی ترنسپورت

- FEC فقط روی ترنسپورت‌های datagram (udp/icmp/proto58/ipip) پشتیبانی می‌شود، نه روی tcp/quic. اگر هیچ‌یک از دو جهت ترنسپورت پشتیبان mux/FEC نداشته باشد، فعال‌کردن FEC رد می‌شود.
- پارامترهای گروه FEC باید روی هر دو طرف منطبق باشند تا رمزگشا و رمزگذار هم‌راستا شوند:
  - `fec_group_size` (`>= 2`) تعداد شاردهای داده در هر گروه.
  - `fec_parity_shards` (`>= 1`) تعداد شاردهای توازن.
  - قید محلی: `fec_group_size + fec_parity_shards <= 255` (محدودیت Reed-Solomon روی GF(2^8)).
  - `fec_mode` (`xor` یا `reed_solomon`) و رفتار `fec_adaptive` باید یکی باشند.
- به‌طور مشابه، اگر `[mux]` فعال باشد، `multiplex_max_payload` (`>= 256`) باید روی هر دو طرف هم‌راستا باشد تا فریم‌های دسته‌بندی‌شده درست جدا شوند.

---

## نمونهٔ تقارن آدرس بین کلاینت و سرور

برای روشن‌شدن قانون‌های جابه‌جایی بخش (ب):

| فیلد | سمت کلاینت | سمت سرور |
|------|-----------|----------|
| `spoof.real_ip` | IP واقعی کلاینت | IP واقعی سرور |
| `spoof.peer_real_ip` | IP واقعی سرور | IP واقعی کلاینت |
| `spoof.spoofed_ip` | جعلیِ کلاینت | جعلیِ سرور |
| `spoof.peer_spoofed_ip` | جعلیِ سرور | جعلیِ کلاینت |
| `tun.tun_ip` | `10.66.0.2` | `10.66.0.1` |
| `tun.tun_peer_ip` | `10.66.0.1` | `10.66.0.2` |
| `crypto.static_public_key` | pubkey کلاینت | pubkey سرور |
| `crypto.peer_public_key` | pubkey سرور | pubkey کلاینت |
| `transport.uplink_protocol` | یکسان | یکسان |
| `transport.downlink_protocol` | یکسان | یکسان |
| `transport.data_port` | یکسان | یکسان |

> نکته: ابزار `freespoof pair --server-config <path>` به‌طور خودکار یک فایل کلاینت با
> آدرس‌ها و کلیدهای قرینه‌شده و یک share-link به شکل `freespoof://<base64>` می‌سازد و
> pubkey کلاینت را برای افزودن به `allowed_peers` سرور چاپ می‌کند؛ پس در عمل این تقارن
> به‌صورت دستی لازم نیست.

</div>
