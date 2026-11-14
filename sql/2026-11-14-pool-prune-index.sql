-- sql/2026-11-14-pool-prune-index.sql
--
-- Dua hal untuk pool proxy:
--   1. Index yang cocok dengan query pemilihan proxy di worker
--      (order: tunnel_ok desc, tunnel_ms asc, ping asc, filter is_active + last_checked).
--   2. Pembersihan baris mati: baris yang TIDAK aktif, belum pernah terbukti tembus, dan sudah
--      lama tidak disentuh. Hasil probe yang benar-benar tembus tidak pernah dihapus; baris yang
--      masih aktif juga tidak. Data ini data sementara (scraper mengisi ulang), jadi aman
--      dijalankan berkala.
--
-- Aman dijalankan berulang kali (idempotent).

-- Berapa yang akan dihapus? (jalankan dulu kalau ingin melihat angkanya)
-- select count(*) from public.proxy_pool
--  where not is_active and coalesce(tunnel_ok, false) = false
--    and (last_checked is null or last_checked < now() - interval '7 days');

create index if not exists proxy_pool_pick_idx
  on public.proxy_pool (tunnel_ok desc nulls last, tunnel_ms asc nulls last, ping asc nulls last)
  where is_active;

create index if not exists proxy_pool_active_check_idx
  on public.proxy_pool (is_active, last_checked)
  where is_active;

delete from public.proxy_pool
 where not is_active
   and coalesce(tunnel_ok, false) = false
   and (last_checked is null or last_checked < now() - interval '7 days');

notify pgrst, 'reload schema';