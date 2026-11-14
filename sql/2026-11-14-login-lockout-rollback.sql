-- sql/2026-11-14-login-lockout-rollback.sql
--
-- Rollback untuk sql/2026-11-14-login-lockout.sql: verify_login dikembalikan PERSIS ke definisi
-- di sql/2026-11-14-auth-hardening.sql dan whoami ke definisi di sql/2026-11-14-whoami.sql
-- (keduanya tanpa penguncian), helper kunci + tabel penghitungnya dihapus.
--
-- Jalankan HANYA kalau penguncian salah kunci user yang sah (mis. banyak user berbagi satu akun
-- atau di balik NAT yang sama) dan Anda butuh membukanya segera. Izin execute verify_login dan
-- whoami tidak berubah; register_user dan admin_action tidak pernah disentuh berkas ini.
--
-- Konsekuensi: brute force verify_login DAN whoami kembali tidak dibatasi (hanya limiter
-- /api/login yang tetap berlaku, dan itu bisa dilewati dengan memanggil RPC langsung).

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

grant execute on function public.verify_login(text, text) to anon, authenticated;

-- whoami kembali ke definisi sql/2026-11-14-whoami.sql (tanpa lapisan kunci).
create or replace function public.whoami(p_username text, p_hash text)
returns text
language sql
security definer
set search_path = public, extensions
as $$
  select coalesce(u.role, 'user')
  from public.users_custom u
  where u.username = lower(btrim(coalesce(p_username, '')))
    and u.password_hash = coalesce(p_hash, '')
  limit 1;
$$;

revoke all on function public.whoami(text, text) from public;
revoke all on function public.whoami(text, text) from authenticated;
grant execute on function public.whoami(text, text) to anon;

drop function if exists public.login_lockout_locked(text);
drop function if exists public.login_lockout_clear(text);
drop function if exists public.login_lockout_fail(text);
drop table if exists public.login_attempts;
