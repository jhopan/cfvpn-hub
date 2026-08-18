# CFVPN Hub

Panel manajemen VPN Worker untuk Cloudflare. Kelola Worker, generate config VLESS/Trojan/Shadowsocks, dan kelola proxy pool dari satu tempat.

**Live:** [https://cfvpn-hub-dcx.pages.dev](https://cfvpn-hub-dcx.pages.dev)

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
├── proxy-scraper/         # Scraper proxy (opsional)
├── tests/                 # Test files
├── .env                   # Credentials (jangan commit!)
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
  ping INTEGER
);

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

## Role System

| Role | Akses |
|------|-------|
| User | Dashboard, Workers, Generator, Proxy, Deploy (Free only) |
| Admin | Semua + User Management, Deploy Premium, Refresh cache, Force cron |

## Deploy Worker (VPN/LB)

1. Buka halaman Deploy
2. Isi Cloudflare credentials
3. Pilih jenis: VPN Worker atau Load Balancer
4. Isi nama worker
5. (Admin) Pilih versi: Free atau Premium
6. Klik "Mulai Deploy"
7. Worker ter-deploy + otomatis masuk ke daftar Workers

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
