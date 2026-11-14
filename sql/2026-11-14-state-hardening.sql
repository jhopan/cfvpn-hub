-- sql/2026-11-14-state-hardening.sql
--
-- Tujuan: `user_states` (daftar worker/config per user) hanya bisa dibaca & ditulis oleh pemilik
-- akunnya. Sebelum ini tabel itu terbuka untuk anon, jadi siapa pun yang tahu username orang lain
-- bisa membaca ATAU menimpa state-nya lewat anon key — sesi palsu di localStorage tidak lagi cukup
-- untuk itu setelah migrasi ini.
--
-- Verifikasi pemilik memakai hash sandi (sha256 hex) yang sudah dipakai kolom password_hash dan
-- yang disimpan sesi panel setelah login. Pola ini sama dengan sql/2026-11-14-auth-hardening.sql;
-- jalankan auth-hardening lebih dulu.
--
-- Panel tahan dua fase: sebelum SQL ini dijalankan ia memakai select/upsert langsung seperti biasa,
-- dan sesudahnya otomatis memakai RPC di bawah (kalau RPC tidak ada, `rpcMissing()` mendeteksinya).
--
-- Batas ukuran state: 256 KB per user (state hanya berisi daftar worker + counter, jauh di bawahnya).

-- ---------------------------------------------------------------------------------------
-- 1. Baca state milik sendiri. Menolak (bukan mengembalikan null) kalau hash tidak cocok.
-- ---------------------------------------------------------------------------------------
create or replace function public.get_state(p_username text, p_actor_hash text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_name text := lower(btrim(coalesce(p_username, '')));
begin
  if not exists (
    select 1
    from public.users_custom u
    where u.username = v_name
      and u.password_hash = coalesce(p_actor_hash, '')
  ) then
    raise exception 'Sesi tidak valid — login ulang.' using errcode = '42501';
  end if;

  return (select s.state_data from public.user_states s where s.username = v_name);
end;
$$;

-- ---------------------------------------------------------------------------------------
-- 2. Tulis state milik sendiri (upsert).
-- ---------------------------------------------------------------------------------------
create or replace function public.save_state(p_username text, p_actor_hash text, p_state jsonb)
returns boolean
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_name text := lower(btrim(coalesce(p_username, '')));
begin
  if not exists (
    select 1
    from public.users_custom u
    where u.username = v_name
      and u.password_hash = coalesce(p_actor_hash, '')
  ) then
    raise exception 'Sesi tidak valid — login ulang.' using errcode = '42501';
  end if;

  if pg_column_size(coalesce(p_state, '{}'::jsonb)) > 262144 then
    raise exception 'State terlalu besar (maks 256 KB).' using errcode = '22023';
  end if;

  insert into public.user_states (username, state_data, updated_at)
  values (v_name, coalesce(p_state, '{}'::jsonb), now())
  on conflict (username) do update
    set state_data = excluded.state_data,
        updated_at = now();
  return true;
end;
$$;

-- ---------------------------------------------------------------------------------------
-- 3. Tidak ada lagi akses tabel langsung dari anon; semua lewat RPC di atas.
-- ---------------------------------------------------------------------------------------
revoke select, insert, update, delete on public.user_states from anon, authenticated;
grant execute on function public.get_state(text, text) to anon, authenticated;
grant execute on function public.save_state(text, text, jsonb) to anon, authenticated;