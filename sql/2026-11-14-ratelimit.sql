-- sql/2026-11-14-ratelimit.sql
--
-- Tujuan: pagar rate limit GLOBAL (lintas-colo) untuk /api/cf, /api/login, dan /api/register.
--
-- Kenapa perlu: limiter Cache API di Worker/Pages Functions bersifat PER-COLO — trafik yang
-- tersebar ke banyak colo (atau cache yang kebetulan kosong) bisa menembusnya. Penghitung di
-- database ini dipakai bersama semua colo, jadi cocok untuk menahan brute force login.
-- Limiter Cache API tetap dipasang di depan sebagai prefilter murah: permintaan yang jelas
-- berlebihan ditolak tanpa menyentuh database sama sekali.
--
-- Aman dijalankan berkali-kali (idempotent) dan aman dijalankan kapan saja: Worker memanggil
-- bump_rate secara best-effort — kalau fungsi ini belum ada, pagar global dilewati dan route
-- tetap berjalan seperti sebelumnya.

-- ---------------------------------------------------------------------------------------
-- 1. Tabel penghitung. Kunci dari Worker: 'scope:ip:nomor_jendela' (scope = cf|login|register),
--    jadi jendela berikutnya memakai kunci berbeda dan baris lama tinggal dihapus.
-- ---------------------------------------------------------------------------------------
create table if not exists public.request_limits (
  key text not null,
  window_start timestamptz not null,
  hits int not null default 0,
  primary key (key, window_start)
);

alter table public.request_limits enable row level security;

-- ---------------------------------------------------------------------------------------
-- 2. bump_rate: naikkan penghitung satu kunci pada jendela waktu berjalan.
--    Atomik dalam satu pernyataan (insert ... on conflict do update), jadi aman dipanggil
--    bersamaan dari banyak colo.
--    true  = masih di bawah batas (permintaan boleh lanjut)
--    false = permintaan ke-(p_limit+1) dan seterusnya pada jendela ini
-- ---------------------------------------------------------------------------------------
create or replace function public.bump_rate(p_key text, p_limit int, p_window_sec int)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  v_window timestamptz;
  v_hits int;
begin
  -- Parameter tidak masuk akal: jangan mengunci permintaan (fail-open, sama seperti sisi Worker).
  if p_key is null or p_key = '' or p_limit is null or p_limit < 1 or p_window_sec is null or p_window_sec < 1 then
    return true;
  end if;

  v_window := to_timestamp(floor(extract(epoch from now()) / p_window_sec) * p_window_sec);

  insert into public.request_limits (key, window_start, hits)
  values (p_key, v_window, 1)
  on conflict (key, window_start) do update set hits = public.request_limits.hits + 1
  returning hits into v_hits;

  -- Baris lama dibersihkan di sini supaya tabel tidak tumbuh tanpa batas tanpa perlu cron.
  -- Jendela bawaan paling lama 600 detik; satu jam sudah jauh melewati jendela berjalan.
  delete from public.request_limits where window_start < now() - interval '1 hour';

  return v_hits <= p_limit;
end;
$$;

-- ---------------------------------------------------------------------------------------
-- 3. Izin: anon hanya boleh memanggil bump_rate, tidak boleh membaca/menulis tabel langsung.
-- ---------------------------------------------------------------------------------------
revoke all on public.request_limits from anon, authenticated;
grant execute on function public.bump_rate(text, int, int) to anon, authenticated;
