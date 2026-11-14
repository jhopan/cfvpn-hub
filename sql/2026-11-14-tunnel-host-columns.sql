-- Kolom bukti probe tunnel dari **vantage host** (mesin scanner Pan-ProxyScanner), bukan edge.
--
-- Alasan: `tunnel_ok`/`tunnel_ms`/`tunnel_checked` diisi cron-worker CFVPN dan berjalan dari
-- edge Cloudflare — itu vonis yang paling menentukan untuk worker VLESS (worker memang jalan di
-- edge). Tetapi hasil verifikasi Pan-ProxyScanner (tunnel nyata lewat proxy dari mesin scanner)
-- selama ini hanya tersimpan sebagai `tls_ok`, satu nilai boolean tanpa durasi dan tanpa waktu
-- probe, sehingga tidak bisa dibedakan dari "belum pernah diprobe". Kolom di bawah menyimpan
-- bukti vantage host apa adanya: `true` = paket benar-benar diteruskan proxy itu dari mesin
-- scanner, `false` = sudah diprobe dan gagal, `NULL` = belum pernah diprobe.
--
-- Aturan pemakaian (jangan dibalik):
--   * `tunnel_host_ok` hanya menambah bukti; ia **tidak pernah** membatalkan vonis edge.
--     Baris dengan `tunnel_ok = false` tetap dianggap mati walau `tunnel_host_ok = true`,
--     karena worker VLESS berjalan di edge, bukan di mesin scanner.
--   * Panel (frontend/app.js) memperlakukan `tunnel_host_ok = true` sebagai bukti sah setara
--     `tls_ok = true`, tetapi berbeda label: "terbukti host" vs "terbukti edge".
--   * Kolom ini opsional: selama belum ada, panel/worker jalan dengan proyeksi lama.
--
-- Jalankan manual di Supabase SQL Editor, atau:
--   npx supabase@latest db query --remote=<project-ref> -f sql/2026-11-14-tunnel-host-columns.sql --yes
--
-- Idempoten: aman dijalankan berulang. Selama belum dijalankan, Pan-ProxyScanner tetap jalan
-- (kolom baru tidak ditulis, hanya dicatat sekali di log per siklus).

alter table if exists public.proxy_pool add column if not exists tunnel_host_ok      boolean;
alter table if exists public.proxy_pool add column if not exists tunnel_host_ms      integer;
alter table if exists public.proxy_pool add column if not exists tunnel_host_checked timestamptz;

comment on column public.proxy_pool.tunnel_host_ok      is 'Probe tunnel terakhir dari vantage host (mesin scanner): true = permintaan benar-benar diteruskan proxy; false = gagal; NULL = belum pernah diprobe';
comment on column public.proxy_pool.tunnel_host_ms      is 'Durasi probe tunnel host (ms) saat tunnel_host_ok terakhir ditulis; NULL kalau gagal/timeout';
comment on column public.proxy_pool.tunnel_host_checked is 'Waktu probe tunnel host terakhir; scanner memakai kolom ini untuk giliran (paling lama diprobe lebih dulu)';

-- Index giliran probe host: belum dipakai kode mana pun (panproxyscanner hanya MENULIS kolom
-- ini, tidak membacanya), disiapkan untuk kalau nanti ada probe host terjadwal yang butuh
-- "paling lama tidak diprobe lebih dulu" — pola yang sama dengan proxy_pool_active_tunnel_idx.
create index if not exists proxy_pool_active_tunnel_host_idx
  on public.proxy_pool (is_active, tunnel_host_checked asc nulls first);

-- Policy TIDAK diurus berkas ini. Izin anon (select/insert/update) dan pencabutan DELETE
-- dimiliki oleh sql/2026-11-15-pool-prune-service-key.sql; berkas ini pernah memuat blok policy
-- yang salah bentuk (drop policy ... for insert) sehingga seolah-olah mengatur izin, padahal tidak
-- pernah membuatnya. Jangan menambahkan DROP/CREATE POLICY di sini lagi.
-- PostgREST menyimpan skema di cache; tanpa ini kolom baru masih terlihat tidak ada.
notify pgrst, 'reload schema';
