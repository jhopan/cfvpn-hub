-- sql/2026-11-14-state-rollback.sql
--
-- Rollback untuk sql/2026-11-14-state-hardening.sql. Jalankan HANYA kalau panel tidak bisa
-- menyimpan/memuat state setelah migrasi: fungsi dihapus dan izin tabel lama dikembalikan, sehingga
-- panel memakai jalur select/upsert langsung lagi.
--
-- Konsekuensi: siapa pun dengan anon key + username bisa membaca/menimpa state user lain.
drop function if exists public.get_state(text, text);
drop function if exists public.save_state(text, text, jsonb);

grant select, insert, update, delete on public.user_states to anon, authenticated;