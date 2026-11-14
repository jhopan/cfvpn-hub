-- Kolom bukti probe tunnel nyata untuk `proxy_pool` (dipakai cron-worker/src/tunnel.js).
--
-- Alasan: `is_active`/`ping` hanya menandai "proxy menjawab cek", bukan "paket benar-benar
-- diteruskan" — terukur 3 baris berstatus hidup tapi 0/3 tembus koneksi TCP nyata dari edge.
-- cron-worker kini memprobe tiap baris aktif (HTTP CONNECT dulu, fallback SOCKS5, lalu
-- "GET / HTTP/1.0" ke example.com) dan menulis hasilnya ke kolom di bawah. Nilai NULL pada
-- `tunnel_ok` berarti baris itu belum pernah diprobe — jadi berbeda dari false (sudah diprobe
-- dan gagal).
--
-- Jalankan manual di Supabase SQL Editor, atau:
--   npx supabase@latest db query --remote=<project-ref> -f sql/2026-11-14-proxy-tunnel-columns.sql --yes
--
-- Idempoten: aman dijalankan berulang. Selama belum dijalankan cron-worker tetap jalan
-- (kolom baru tidak ditulis, hanya dicatat sekali di log per siklus).

alter table public.proxy_pool add column if not exists tunnel_ok      boolean;
alter table public.proxy_pool add column if not exists tunnel_ms      integer;
alter table public.proxy_pool add column if not exists tunnel_checked timestamptz;

comment on column public.proxy_pool.tunnel_ok      is 'Probe tunnel nyata terakhir dari edge: true = permintaan HTTP benar-benar diteruskan proxy; NULL = belum pernah diprobe';
comment on column public.proxy_pool.tunnel_ms      is 'Durasi probe tunnel (ms) saat tunnel_ok terakhir ditulis; NULL kalau gagal/timeout';
comment on column public.proxy_pool.tunnel_checked is 'Waktu probe tunnel terakhir; cron-worker memakai kolom ini untuk giliran (paling lama diprobe lebih dulu)';

-- Giliran probe: baris aktif yang paling lama tidak diprobe didahulukan, NULL (belum pernah)
-- paling awal. Cocok dengan query cron-worker: is_active=eq.true + order tunnel_checked asc.
create index if not exists proxy_pool_active_tunnel_idx
  on public.proxy_pool (is_active, tunnel_checked asc nulls first);

-- PostgREST menyimpan skema di cache; tanpa ini kolom baru masih terlihat tidak ada.
notify pgrst, 'reload schema';
