# CFVPN Hub

Panel manajemen VPN Worker untuk Cloudflare. Kelola Worker, generate config VLESS/Trojan/Shadowsocks, dan kelola proxy pool dari satu tempat.

**Live:** [https://cfvpn-hub-9xy.pages.dev](https://cfvpn-hub-9xy.pages.dev)

## Fitur

- **Dashboard** — statistik Worker aktif, config dibuat, proxy aktif
- **Workers** — kelola VPN Worker & Load Balancer (grup terpisah, toggle aktif/nonaktif)
- **Generator** — buat config VPN (local generator atau subscription dari Load Balancer)
  - Filter proxy berdasarkan negara & penyedia
  - Pilih proxy spesifik atau acak
  - Output: Raw, V2Ray (Base64), Clash YAML, Sing-box JSON
  - Cache proxy 6 jam
- **Proxy Pool** — tambah proxy (cek aktif sebelum simpan), lihat tabel lengkap
- **Deploy** — deploy VPN Worker / Load Balancer langsung ke Cloudflare
  - Versi Free & Premium (admin only untuk Prem)
  - Auto-save Worker ke dashboard setelah deploy
- **User Management** (admin only) — kelola user, tambah admin, hapus user
- **PWA** — install sebagai app, cache offline
- **Role system** — admin & user biasa

## Tech Stack

- **Frontend:** HTML, CSS, JavaScript (ES Module, no framework)
- **Backend:** Cloudflare Pages Functions
- **Database:** Supabase (auth, proxy pool, user states)
- **Hosting:** Cloudflare Pages
- **PWA:** manifest.json + Service Worker

## Struktur Folder

```
cfvpn-hub/
├── frontend/              # Cloudflare Pages output
│   ├── admin.html         # User management (admin only)
│   ├── app.js             # Logic utama
│   ├── deploy.html        # Deploy worker
│   ├── generator.html     # Generator config
│   ├── index.html         # Dashboard
│   ├── landing.html       # Landing page publik
│   ├── login.html         # Login + Register (tab)
│   ├── manifest.json      # PWA manifest
│   ├── proxy.html         # Proxy pool
│   ├── register.html      # Redirect ke login#register
│   ├── style.css          # Style
│   ├── sw.js              # Service Worker
│   ├── workers.html       # Workers management
│   └── source/            # Source code Worker (di-fetch saat deploy)
│       ├── load-balancer.js
│       ├── vpn-worker-free.js
│       └── vpn-worker-prem.js
├── functions/             # Cloudflare Pages Functions
│   └── api/
│       └── cf.js          # Deploy worker endpoint
├── cron-worker/           # Cron worker (proxy checker)
│   ├── src/index.js
│   ├── package.json
│   └── wrangler.toml
├── deploy-bulk.mjs        # Script menu deploy Worker batch (lokal)
├── workers.txt            # Input nama Worker, satu nama per baris
├── deployed.txt           # Output URL Worker online (dibuat script)
├── status.txt             # Output status Worker (dibuat script)
├── proxy-scraper/         # Scraper proxy (opsional)
├── tests/                 # Test files
├── .env                   # Credentials lokal (jangan commit!)
├── .gitignore
├── package.json
└── wrangler.toml
```

## Setup

### 1. Clone & Install

```bash
git clone https://github.com/jhopan/cfvpn-hub.git
cd cfvpn-hub
npm install
```

### 2. Environment Variables

Buat file `.env`:

```env
# Cloudflare
CLOUDFLARE_API_KEY=your_cf_api_key
CLOUDFLARE_EMAIL=your_email
CLOUDFLARE_ACCOUNT_ID=your_account_id

# Supabase
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your_anon_key
```

### 3. Supabase Database

Jalankan SQL ini di Supabase SQL Editor:

```sql
-- Tabel users
CREATE TABLE IF NOT EXISTS users_custom (
  username TEXT PRIMARY KEY,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  role TEXT DEFAULT 'user',
  telegram_chat_id TEXT
);

-- Tabel proxy pool
CREATE TABLE IF NOT EXISTS proxy_pool (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  ip TEXT NOT NULL,
  port TEXT NOT NULL,
  country TEXT,
  org TEXT,
  is_active BOOLEAN DEFAULT true,
  last_checked TIMESTAMPTZ,
  ping INTEGER,
  -- bukti verifikasi dari aplikasi `proxy-scraping` (lihat catatan di bawah)
  tls_ok BOOLEAN NOT NULL DEFAULT false,
  alt_ok BOOLEAN NOT NULL DEFAULT false,
  exit_ip TEXT
);

-- Catatan `is_active`: hanya verifikasi mendalam (aplikasi `proxy-scraping`) yang boleh
-- menaikkannya. `cron-worker` hanya boleh mematikannya. Cek HTTP dangkal bisa lolos di proxy
-- yang tidak sanggup tunnel TLS 443, sedangkan panel memakai proxy untuk WebSocket VLESS di
-- 443 — hasilnya konfigurasi mati.
--
-- Skema resmi yang dipakai project aktif ada di `supabase/schema.sql`
-- (project `lumbbmhhmkcnxunuryjr`, org "Adelia Hub"; kolom bukti + policy RLS termasuk DELETE).

-- Tabel user states (workers, generated configs)
CREATE TABLE IF NOT EXISTS user_states (
  username TEXT REFERENCES users_custom(username),
  state_data JSONB,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Set user sebagai admin
UPDATE users_custom SET role = 'admin' WHERE username = 'your_username';
```

### 4. Run Local

```bash
npm run dev
```

Buka `http://localhost:8788`

### 5. Deploy

```bash
# Set env vars dulu
export CLOUDFLARE_API_KEY="your_key"
export CLOUDFLARE_EMAIL="your_email"
export CLOUDFLARE_ACCOUNT_ID="your_account_id"

# Deploy
npm run deploy
```

Atau hubungkan GitHub repo ke Cloudflare Pages untuk auto-deploy.

## Cron Worker (Proxy Checker)

Deploy cron worker terpisah untuk cek proxy tiap jam:

```bash
cd cron-worker
npm install
npx wrangler deploy
```

Set env vars di `cron-worker/wrangler.toml` atau Cloudflare dashboard.

### Verifikasi tunnel & kolom baru

Cron worker menembus setiap proxy secara nyata (HTTP CONNECT lalu SOCKS5 ke `example.com:80`) dan
menyimpan hasilnya di kolom baru. Jalankan dulu berkas ini di Supabase SQL Editor:

```
sql/2026-11-14-proxy-tunnel-columns.sql
```

Sebelum SQL dijalankan cron tetap jalan (hanya menulis kolom lama, satu peringatan per siklus).
Yang ditulis: `tunnel_ok` (`null` = belum pernah diperiksa, `false` = terbukti gagal), `tunnel_ms`,
`tunnel_checked`. Worker memakai `tunnel_ok` sebagai urutan pertama saat memilih proxy dari pool,
dan halaman Generator menandai baris terverifikasi dengan ✓.

### Keamanan: auth server-side & rate limit

1. **Deploy panel dulu**, baru jalankan `sql/2026-11-14-auth-hardening.sql` di Supabase SQL Editor.
   Setelah itu kolom hash sandi tidak bisa dibaca dengan anon key dan pembuatan/pengubahan admin
   diverifikasi server (RPC `verify_login`, `register_user`, `admin_action`). Panel tetap bisa
   login sebelum SQL dijalankan karena jalur lama dipakai otomatis. **Status: kedua berkas SQL
   sudah dijalankan di proyek ini (2026-11-14); akun lama perlu login ulang sekali** supaya sesi
   membawa verifikasi untuk aksi admin.
5. `POST /api/login` dan `POST /api/register` (Pages Functions) membatasi percobaan per IP, lalu
   menaikkannya jadi batas **global** lewat `sql/2026-11-14-ratelimit.sql`. Panel otomatis memakai
   jalur lama kalau endpoint atau fungsinya belum ada.
6. State per user (`user_states`) hanya bisa dibaca/ditulis pemiliknya lewat RPC
   (`sql/2026-11-14-state-hardening.sql`), jadi sesi palsu di browser tidak bisa menimpa daftar
   worker orang lain. Batas 256 KB per user.
7. CI: `.github/workflows/ci.yml` menjalankan `npm test`, `npm run check:templates`, dan
   `node --check` untuk semua berkas yang dikirim (harness smoke tidak, karena butuh jaringan).
2. `POST /api/cf` punya rate limit per IP (bawaan 10 permintaan / 600 detik). Atur lewat env
   `RATE_LIMIT` dan `RATE_WINDOW_SEC`. Batas ini per-colo dan best-effort, bukan kuota global.
3. Gerbang Origin opsional: isi env `ALLOWED_ORIGINS` (mis. `https://cfvpn-hub-9xy.pages.dev`,
   boleh pola `*.domain`) untuk menolak pemanggilan dari origin lain. Kosong = seperti sebelumnya.
4. Worker VPN bisa menutup `/health` dengan binding `HEALTH_TOKEN` (`?token=` atau header
   `x-health-token`); badge versi worker di dasbor berhenti bekerja kalau ini diaktifkan.

## Role System

| Role | Akses |
|------|-------|
| User | Dashboard, Workers, Generator, Proxy, Deploy Worker Free |
| Admin | Semua akses User + User Management, pilihan Worker Free/Premium, refresh cache, force cron |

## Deploy Worker (VPN/LB)

1. Buka halaman Deploy
2. Isi Cloudflare credentials
3. Pilih jenis: VPN Worker atau Load Balancer
4. Isi nama worker
5. (Admin) Pilih versi: Free atau Premium
6. Klik "Mulai Deploy"
7. Worker ter-deploy + otomatis masuk ke daftar Workers

**Batas role:** user biasa hanya mendapat Worker Free. Field versi Worker disembunyikan dan backend frontend selalu memilih `vpn-worker-free.js`. Admin dapat memilih Free atau Premium.

**Beda Free vs Premium:** hanya satu konstanta di script worker (`TIER_FREE`). Di Free, relay UDP tidak dipakai walau binding-nya dipasang; sisa kode identik, jadi tidak ada fitur lain yang berbeda dan perbaikan bug berlaku untuk kedua tier.

### Memilih proxy dari path (selector)

Path kedua URL WebSocket menentukan proxy mana yang dipakai worker:

| Path | Arti |
|---|---|
| `/<ip>-<port>` atau `/<ip>:<port>` | pakai proxy itu saja (seperti sebelumnya) |
| `/ALL`, `/ROTATE`, `/AUTO`, `/POOL` | worker memilih acak dari 6 proxy teratas pool |
| `/ID`, `/SG`, `/ID,SG`, `/US-ID` | hanya negara itu (kode 2 huruf), pilih acak dari teratas |

Enaknya: konfigurasi ber-selector tidak perlu diganti saat pool berubah, dan failover tetap
berlaku di atas pilihan itu.

Kalau memakai filter negara, worker **gagal-tertutup**: saat negara itu sedang tidak punya proxy
sehat, koneksi ditutup — bukan diam-diam keluar lewat proxy negara lain. Longgarkan dengan
beberapa negara (`/ID,SG`) atau pakai `/ALL` kalau negara keluar tidak penting. Halaman **Generator** punya centang **"Mode rotasi"**: filter negara
yang dipilih otomatis menjadi path (`/ID`, `/ID,SG`, atau `/ALL` kalau tanpa filter). Daftar negara
bisa dipilih lebih dari satu (Ctrl/Cmd) dan tiap pilihan menampilkan jumlah proxy segar; kalau
tidak ada satu pun proxy siap pakai, Generator memberi peringatan sebelum config dibuat.

## Relay UDP di Halaman Deploy

Worker Cloudflare tidak punya UDP keluar. Supaya UDP non-DNS (QUIC/HTTP3, game, WireGuard, NTP)
tetap jalan, jalankan relay UDP sendiri (repo
[`Pan-VlessRelay`](https://github.com/jhopan/Pan-VlessRelay), Docker siap pakai) lalu isi bagian
**Relay UDP (opsional)** di halaman Deploy — bagian ini **khusus tier Premium** (worker VPN
bertier Premium; user Free selalu memakai template Free tanpa binding relay).

### Di mana relay bisa dijalankan

Relay butuh **port TCP masuk** (worker menyambung ke situ) dan **UDP keluar** (untuk mengirim
datagram). Itu menentukan platform yang bisa dipakai:

| Platform | Relay TCP (sekarang) | Catatan |
|---|---|---|
| VPS biasa (IP publik) | ✅ | Paling sederhana: `docker run -p 7300:7300/tcp` |
| **VPS NAT** (IP bersama, port dipetakan) | ✅ | Asal provider memberi **port forward TCP** + mengizinkan UDP keluar. Cek kuota bandwidth |
| Laptop/rumah di belakang NAT | ⚠️ | Butuh terowongan TCP (mis. SSH `-L`) atau port forward router; sudah diuji lewat SSH tunnel |
| **Render** (web service) | ❌ untuk TCP | Render tidak memberi ingress TCP publik; tapi Render **mendukung WebSocket masuk** → perlu varian relay berbasis WebSocket |
| Railway / Fly.io | ✅ (TCP proxy) | Butuh mengaktifkan TCP proxy / service TCP |
| **Vercel** | ❌ | Vercel Functions bersifat request/response (tanpa server TCP maupun WebSocket persisten) |

Kalau hosting-mu hanya mengizinkan HTTP/WebSocket (Render, Railway tanpa TCP proxy), jalur
yang masuk akal adalah **relay versi WebSocket** (worker menyambung via `fetch` dengan
`Upgrade: websocket`) — belum dibuat; protokol v1 sekarang murni TCP.

**Isian panel → binding Worker** (hanya dikirim untuk deploy tier Premium):

| Isian panel | Menjadi binding Worker | Contoh |
|---|---|---|
| Host relay | `RELAY_SERVER_UDP` | `relay.domainmu.com` |
| Port relay | `RELAY_SERVER_PORT` | `7300` |
| Pakai TLS | `RELAY_SERVER_TLS` | `1` (relay di port 443 dengan sertifikat) |
| Rahasia relay | `RELAY_SECRET` | harus sama dengan `RELAY_SECRET` di relay |

Panel mengirim nilai itu ke `/api/cf` sebagai `vars`, divalidasi, lalu dipasang sebagai binding
pada Worker saat upload; respons deploy menampilkan daftar env yang terpasang. Kosongkan host
(kosong = tidak ada binding) untuk perilaku lama: DNS tetap dijawab lewat DoH dan UDP selain DNS
ditutup cepat. Rahasia wajib diisi kalau host diisi — relay menolak sambungan tanpa rahasia yang
benar.

Deploy massal (`deploy-bulk.mjs`) memakai env shell dengan nama yang sama
(`RELAY_SERVER_UDP`, `RELAY_SERVER_PORT`, `RELAY_SERVER_TLS`, `RELAY_SECRET`) dan memasangnya
sebagai binding untuk setiap worker.

Catatan: jalur UDP lewat relay menambah satu hop dan memakai TCP, jadi QUIC berat bisa lebih
lambat — protokol UDP kecil (DNS/NTP/game ringan) paling cocok.

## Bulk Deploy Script (Lokal)

`deploy-bulk.mjs` adalah script lokal, bukan fitur frontend dan tidak ter-deploy ke Cloudflare Pages. Script membaca kredensial dari `.env`; jangan taruh key pada source code atau commit ke GitHub.

Tambahkan kredensial Cloudflare ini ke `.env`:

```env
CF_EMAIL=your_email
CF_API_KEY=your_cf_global_api_key
CF_ACCOUNT_ID=your_account_id
```

Siapkan `workers.txt`, satu nama Worker per baris:

```txt
vpn-sg-01
vpn-sg-02
vpn-id-01
```

Jalankan:

```bash
node deploy-bulk.mjs
```

Menu tersedia:

```txt
1. Deploy Worker (dari file workers.txt)
2. Deploy Worker (input manual)
3. Cek Status Worker (baca deployed.txt)
4. Cek Status Worker (input URL)
5. Hapus Worker
0. Keluar
```

Pada deploy, script memilih source Worker Free, Premium, atau Load Balancer; upload satu per satu; enable `workers.dev`; lalu cek endpoint `/myip`. Hanya Worker yang menjawab HTTP status `<500` dicatat sebagai online.

Hasil deploy disimpan ke `deployed.txt`:

```txt
vpn-sg-01    https://vpn-sg-01.example.workers.dev    ✅ ONLINE
vpn-id-01    GAGAL                                  ❌ - worker tidak response
```

Cek ulang dari menu 3 menghasilkan `status.txt`.

## Generator

**Mode Local:**
- Pilih VPN Worker
- Filter proxy by negara/penyedia, atau pilih proxy spesifik
- Pilih format output (Raw/V2Ray/Clash/Sing-box)
- Klik "Buat Config"

**Mode Subscription:**
- Pilih Load Balancer
- Set format, jumlah, filter negara
- Klik "Buat Config" → fetch dari LB worker
- URL subscription muncul setelah generate

## Author

**jhopanstore**

## License

MIT
