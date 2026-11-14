-- Rollback untuk sql/2026-11-14-tunnel-host-columns.sql.
--
-- Pakai HANYA kalau kolom bukti vantage host bermasalah (mis. Pan-ProxyScanner menulis nilai
-- salah dan kolomnya perlu ditambahkan ulang dari nol). Panel dan worker tetap jalan tanpa kolom
-- ini: panel mengulang proyeksi lamanya, scanner tidak menulis kolom yang tidak ada.
--
-- Konsekuensi: seluruh bukti tunnel vantage host (hasil probe dari mesin scanner) **hilang**, dan
-- proyeksi panel kembali hanya mengenal `tls_ok`. Setelah rollback, jalankan ulang migrasi
-- aslinya (idempoten) begitu penyebabnya diperbaiki.
--
-- Jalankan manual di Supabase SQL Editor, atau:
--   npx supabase@latest db query --remote=<project-ref> -f sql/2026-11-14-tunnel-host-columns-rollback.sql --yes

drop index if exists public.proxy_pool_active_tunnel_host_idx;

alter table if exists public.proxy_pool drop column if exists tunnel_host_checked;
alter table if exists public.proxy_pool drop column if exists tunnel_host_ms;
alter table if exists public.proxy_pool drop column if exists tunnel_host_ok;

-- Policy anon/authenticated dan kolom tunnel edge tidak disentuh: policy berlaku per-baris untuk
-- seluruh tabel (`tls_ok`, `tunnel_ok`, `alt_ok`, ...), jadi bukan milik migrasi ini.

notify pgrst, 'reload schema';
