-- sql/2026-11-14-auth-rollback.sql
--
-- Rollback untuk sql/2026-11-14-auth-hardening.sql. Jalankan HANYA kalau login atau aksi admin
-- rusak setelah migrasi: fungsi RPC dihapus dan izin lama dikembalikan, sehingga panel memakai
-- jalur fallback (select + bandingkan hash di klien) lagi.
--
-- Konsekuensi: hash sandi kembali bisa dibaca dengan anon key dan anon bisa menyisipkan baris
-- role='admin'. Pakai hanya sebagai penyelamat sementara, lalu perbaiki dan jalankan ulang
-- migrasi aslinya.
drop function if exists public.verify_login(text, text);
drop function if exists public.register_user(text, text);
drop function if exists public.admin_action(text, text, text, text, text, text);

grant select on public.users_custom to anon, authenticated;
grant insert, update, delete on public.users_custom to anon, authenticated;