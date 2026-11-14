-- sql/2026-11-14-proxy-evidence-columns.sql
--
-- Kolom bukti dari panproxyscanner (pipeline scraping produksi). Selama kolom ini belum ada,
-- aplikasi itu membuang hasil verifikasinya: `tls_ok` (tunnel TLS 443 dengan verifikasi
-- sertifikat), `alt_ok` (port non-standar 8443/2053), `exit_ip` (alamat keluar dari trace
-- Cloudflare). Tanpa `tls_ok`, panel/worker hanya bisa menilai dari `is_active` + `tunnel_ok`.
--
-- `is_active` saja tidak cukup: cek HTTP dangkal bisa lolos di proxy yang tidak sanggup TLS,
-- dan konfigurasi VLESS hasilnya mati di sisi pengguna.
--
-- Aman diulang (idempoten). RLS + policy di bawah mempertahankan akses anon yang sekarang
-- dipakai panel dan worker; kalau nanti ingin lebih ketat, ganti `to anon` menjadi
-- `to authenticated` dan pindahkan penulisan ke sisi server dengan service key.

alter table if exists public.proxy_pool add column if not exists tls_ok  boolean not null default false;
alter table if exists public.proxy_pool add column if not exists alt_ok  boolean not null default false;
alter table if exists public.proxy_pool add column if not exists exit_ip text;

create index if not exists proxy_pool_active_tls_idx
  on public.proxy_pool (is_active, tls_ok, last_checked desc);

alter table if exists public.proxy_pool enable row level security;

drop policy if exists proxy_pool_select_anon on public.proxy_pool;
create policy proxy_pool_select_anon on public.proxy_pool for select to anon, authenticated using (true);

drop policy if exists proxy_pool_insert_anon on public.proxy_pool;
create policy proxy_pool_insert_anon on public.proxy_pool for insert to anon, authenticated with check (true);

drop policy if exists proxy_pool_update_anon on public.proxy_pool;
create policy proxy_pool_update_anon on public.proxy_pool for update to anon, authenticated using (true) with check (true);

-- DELETE untuk anon: dibutuhkan prune (panproxyscanner /api/supabase/prune) supaya benar-benar
-- menghapus baris mati, bukan melaporkan 0.
drop policy if exists proxy_pool_delete_anon on public.proxy_pool;
create policy proxy_pool_delete_anon on public.proxy_pool for delete to anon, authenticated using (true);

notify pgrst, 'reload schema';