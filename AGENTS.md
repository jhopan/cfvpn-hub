# AGENTS.md — cfvpn-hub

Cloudflare VPN management panel. Frontend statis (vanilla JS) + Cloudflare Pages Functions + Supabase.

## Deploy

```bash
npm run dev      # wrangler pages dev frontend
npm run deploy   # wrangler pages deploy frontend
```

Auto-deploy: repo `jhopan/cfvpn-hub` push ke `main` → Cloudflare Pages rebuild (build output dir = `frontend`).

**Jangan** `wrangler deploy` untuk frontend — itu untuk Worker script.

## Struktur

```
frontend/           # output Cloudflare Pages (build output dir)
  app.js            # logika utama (ES module, ~1100 baris)
  style.css         # semua style
  *.html            # 9 halaman
  sw.js             # service worker (PWA) — bump CACHE_NAME saat ubah asset
  source/           # source code Worker VPN, di-fetch saat user deploy
    vpn-worker-free.js
    vpn-worker-prem.js
    load-balancer.js
functions/api/cf.js # Pages Function: deploy Worker ke Cloudflare API
cron-worker/        # Cron Worker terpisah (proxy checker) — deploy manual
```

## Aturan wajib

1. **Frontend tidak boleh pegang secret.** API key Cloudflare & Supabase hanya di `functions/` (server-side) atau `.env` (lokal, gitignored).
2. `app.js` = ES module. Tidak boleh ada `import statement` di luar module. BOM di awal file bikin crash (`SyntaxError: Unexpected token '}'`).
3. Setelah edit `app.js`: `node --check frontend/app.js` wajib lolos.
4. `sw.js` cache busting: naikkan `CACHE_NAME` kalau asset berubah, kalau tidak user pakai versi lama.
5. Role check: `currentUser?.role !== "admin"` → sembunyikan fitur admin (bukan cuma disable).
6. Halaman protected wajib cek session sebelum render. Kalau `visibility:hidden` dipakai, pastikan JS menampilkannya — kalau tidak, layar hitam.
7. SQL Supabase (kolom baru) = user yang jalankan, bukan agent. Siapkan file `.sql`.

## Env vars

`.env` (gitignored):
```
CLOUDFLARE_API_KEY, CLOUDFLARE_EMAIL, CLOUDFLARE_ACCOUNT_ID
SUPABASE_URL, SUPABASE_ANON_KEY
```

## Supabase

- URL: `https://cgflrpjavyotvolnvcnl.supabase.co`
- Tabel: `users_custom` (auth + role), `proxy_pool` (proxy), `user_states` (worker & config per user)
- RLS: anon boleh SELECT. Update butuh service_role key.
- `role`: `user` | `admin`

## Verify sebelum bilang selesai

```bash
node --check frontend/app.js
curl -sL -o /dev/null -w "%{http_code}" https://cfvpn-hub-dcx.pages.dev/<page>
```

Untuk deploy: cek `https://cfvpn-hub-dcx.pages.dev` benar-benar mencerminkan perubahan (hard refresh, SW cache).
