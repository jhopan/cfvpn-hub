-- sql/2026-11-15-pool-prune-service-key-rollback.sql
--
-- Rollback untuk sql/2026-11-15-pool-prune-service-key.sql: anon (dan authenticated) kembali
-- boleh DELETE pada public.proxy_pool, persis seperti keadaan sebelum migrasi:
--   * `proxy_pool_anon_all`  — for all to anon, authenticated using(true) with check(true)
--                              (supabase/schema.sql).
--   * `proxy_pool_delete_anon` — for delete to anon, authenticated using(true)
--                              (sql/2026-11-14-tunnel-host-columns.sql).
-- Keduanya dikembalikan sekaligus; di project yang hanya pernah menjalankan salah satu migrasi,
-- kehadiran keduanya tidak berbahaya karena sama-sama permissive.
--
-- Grant dikembalikan ke `grant select, insert, update, delete` untuk anon, authenticated
-- sebagaimana supabase/schema.sql. Policy SELECT/INSERT/UPDATE anon tidak disentuh (tidak pernah
-- diubah arahnya oleh migrasi utama; blok 2 migrasi itu hanya menegaskan ulang bentuk yang sama).
--
-- Pakai HANYA kalau pemakai DELETE berbasis service key belum siap dan tombol bersihkan baris
-- mati harus jalan lagi lewat anon key. Konsekuensi: siapa pun yang punya anon key bisa
-- menghapus isi pool.
--
-- Idempoten: aman dijalankan berulang.

alter table if exists public.proxy_pool enable row level security;

-- 1. Kembalikan policy `for all` dari supabase/schema.sql.
drop policy if exists proxy_pool_anon_all on public.proxy_pool;
create policy proxy_pool_anon_all on public.proxy_pool
  for all to anon, authenticated using (true) with check (true);

-- 2. Kembalikan policy delete per-perintah dari sql/2026-11-14-tunnel-host-columns.sql.
drop policy if exists proxy_pool_delete_anon on public.proxy_pool;
create policy proxy_pool_delete_anon on public.proxy_pool
  for delete to anon, authenticated using (true);

-- 3. Grant kembali seperti supabase/schema.sql.
grant select, insert, update, delete on public.proxy_pool to anon, authenticated;

notify pgrst, 'reload schema';