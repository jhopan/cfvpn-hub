-- sql/2026-11-14-auth-hardening.sql
--
-- Tujuan:
--   1. Kolom password_hash tidak lagi bisa dibaca dengan anon key (sekarang siapa pun yang
--      membaca frontend/app.js bisa menarik SEMUA hash sandi lewat REST).
--   2. Tidak ada lagi izin tulis mentah ke users_custom, jadi anon tidak bisa menyisipkan
--      baris dengan role='admin' untuk membuat dirinya admin.
--   3. Login, daftar, dan aksi admin diverifikasi di server (fungsi SECURITY DEFINER).
--
-- URUTAN AMAN: deploy panel versi baru lebih dulu, baru jalankan berkas ini. Panel baru tetap
-- berfungsi tanpa SQL ini (semua jalur RPC punya fallback ke cara lama), tetapi SQL ini tanpa
-- panel baru akan mematikan login lama.
--
-- Panjang hash: panel memakai SHA-256 hex dari sandi apa adanya (tanpa salt). Skema itu tidak
-- diubah di sini supaya user lama tetap bisa login.
--
-- Yang BELUM ditutup oleh berkas ini (perlu keputusan terpisah):
--   - brute force verify_login (butuh rate limit/CAPTCHA; RPC tidak membatasi percobaan)
--   - otorisasi sisi server untuk halaman selain users_custom (session masih di localStorage)
--   - proxy_pool memang harus bisa dibaca anon (dipakai Load Balancer), jadi tetap terbuka.

create extension if not exists pgcrypto with schema extensions;

-- ---------------------------------------------------------------------------------------
-- 1. Kredensial: cabut SELECT tabel, sisakan kolom non-rahasia untuk UI.
-- ---------------------------------------------------------------------------------------
revoke select on public.users_custom from anon, authenticated;
grant select (username, role) on public.users_custom to anon, authenticated;

-- ---------------------------------------------------------------------------------------
-- 2. Login: server membandingkan hash. Mengembalikan json (objek) atau null.
-- ---------------------------------------------------------------------------------------
create or replace function public.verify_login(p_username text, p_password text)
returns json
language sql
security definer
set search_path = public, extensions
as $$
  select json_build_object('username', u.username, 'role', u.role)
  from public.users_custom u
  where u.username = lower(btrim(coalesce(p_username, '')))
    and u.password_hash = encode(digest(coalesce(p_password, ''), 'sha256'), 'hex')
  limit 1;
$$;

-- ---------------------------------------------------------------------------------------
-- 3. Pendaftaran: hanya boleh membuat role 'user'. true = dibuat, false = username sudah ada.
-- ---------------------------------------------------------------------------------------
create or replace function public.register_user(p_username text, p_password text)
returns boolean
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_name text := lower(btrim(coalesce(p_username, '')));
  v_rows integer := 0;
begin
  if v_name = '' or position(' ' in v_name) > 0 then
    raise exception 'Username tidak valid.' using errcode = '22023';
  end if;
  if length(coalesce(p_password, '')) < 6 then
    raise exception 'Sandi minimal 6 karakter.' using errcode = '22023';
  end if;

  insert into public.users_custom (username, password_hash)
  values (v_name, encode(digest(p_password, 'sha256'), 'hex'))
  on conflict (username) do nothing;

  get diagnostics v_rows = row_count;
  return v_rows > 0;
end;
$$;

-- ---------------------------------------------------------------------------------------
-- 4. Aksi admin: pelaku harus admin DAN hash sandinya cocok (anon key saja tidak cukup).
--    p_action: 'create' | 'set_role' | 'delete'
--    true = ada baris yang berubah, false = tidak ada (mis. username sudah ada / bukan target).
-- ---------------------------------------------------------------------------------------
create or replace function public.admin_action(
  p_actor text,
  p_actor_hash text,
  p_action text,
  p_target text default null,
  p_role text default null,
  p_password text default null
)
returns boolean
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_actor text := lower(btrim(coalesce(p_actor, '')));
  v_target text := lower(btrim(coalesce(p_target, '')));
  v_rows integer := 0;
begin
  if not exists (
    select 1
    from public.users_custom u
    where u.username = v_actor
      and u.role = 'admin'
      and u.password_hash = coalesce(p_actor_hash, '')
  ) then
    raise exception 'Hanya admin yang boleh melakukan ini.' using errcode = '42501';
  end if;

  if p_action = 'create' then
    if v_target = '' or position(' ' in v_target) > 0 or length(coalesce(p_password, '')) < 6 then
      raise exception 'Username atau sandi tidak valid.' using errcode = '22023';
    end if;
    insert into public.users_custom (username, password_hash, role)
    values (v_target, encode(digest(p_password, 'sha256'), 'hex'), coalesce(nullif(p_role, ''), 'admin'))
    on conflict (username) do nothing;
    get diagnostics v_rows = row_count;
    return v_rows > 0;

  elsif p_action = 'set_role' then
    if p_role is null or p_role not in ('admin', 'user') then
      raise exception 'Role tidak dikenal.' using errcode = '22023';
    end if;
    update public.users_custom
       set role = p_role
     where username = v_target
       and username <> v_actor;
    get diagnostics v_rows = row_count;
    return v_rows > 0;

  elsif p_action = 'delete' then
    delete from public.users_custom
     where username = v_target
       and username <> v_actor;
    get diagnostics v_rows = row_count;
    return v_rows > 0;
  end if;

  raise exception 'Aksi tidak dikenal: %', coalesce(p_action, '(null)') using errcode = '22023';
end;
$$;

-- ---------------------------------------------------------------------------------------
-- 5. Semua tulis lewat RPC di atas; tidak ada lagi izin tulis mentah dari anon.
-- ---------------------------------------------------------------------------------------
revoke insert, update, delete on public.users_custom from anon, authenticated;
grant execute on function public.verify_login(text, text) to anon, authenticated;
grant execute on function public.register_user(text, text) to anon, authenticated;
grant execute on function public.admin_action(text, text, text, text, text, text) to anon, authenticated;