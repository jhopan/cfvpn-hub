-- sql/2026-11-14-login-lockout.sql
--
-- Tujuan: menutup brute force DUA oracle hash panel — verify_login dan whoami. Anon key publik
-- ada di frontend/app.js, jadi siapa pun bisa memanggil RPC-RPC itu LANGSUNG lewat PostgREST dan
-- melewati limiter di /api/login (limiter itu per IP di sisi Pages Function + bump_rate); RPC-nya
-- sendiri tidak membatasi percobaan. Berkas ini menambahkan penguncian per-username DI DALAM
-- kedua fungsi, sehingga pagar tetap berlaku walau jalur HTTP-nya dilewati.
--
-- RPC yang terlindungi: public.verify_login (dibuat ulang) dan public.whoami (dibuat ulang).
-- register_user dan admin_action TIDAK disentuh (admin_action sudah menuntut hash admin, dan
-- kegagalannya tidak dibedakan per target; verify_login/whoami-lah oracle yang bisa ditebak).
--
-- Aman dijalankan berkali-kali (idempotent) dan aman dijalankan sebelum/sesudah panel yang
-- sekarang: bentuk balasan tidak berubah — verify_login: json {username, role} saat sukses, null
-- saat kredensial salah; whoami: role saat hash cocok, null saat tidak cocok.
--
-- KETERBATASAN (sengaja, bukan bug):
--   * Kunci bersifat per-username, BUKAN per IP: RPC tidak menerima IP klien dan PostgREST tidak
--     meneruskannya ke fungsi. Jadi penyerang masih bisa menebak BANYAK username berbeda
--     (masing-masing hanya dapat 5 percobaan per jendela); yang dicegah adalah menebak satu akun
--     tanpa batas. Pembatasan per IP tetap tugas /api/login + bump_rate.
--   * Username yang TIDAK ADA juga dihitung, supaya perilaku terkunci tidak membocorkan username
--     mana yang benar-benar terdaftar (dan supaya penebakan massal tetap tertahan).
--   * Kedua oracle memakai SATU ember hitungan per username, jadi penyerang tidak mendapat 10
--     percobaan dengan berpindah dari verify_login ke whoami. Efek samping yang diterima:
--     penyerang yang menghabiskan jatah sebuah username bisa memaksa pemiliknya logout sesaat
--     (whoami terkunci = sesi dianggap tidak valid) — itu memang harga kunci per-username.
--   * Tidak ada CAPTCHA / verifikasi email; kunci hanya menunda.
--
-- URUTAN AMAN: jalankan setelah sql/2026-11-14-auth-hardening.sql (aman juga kalau dijalankan
-- kapan saja; panel lama maupun baru tetap cocok). Definisi whoami ikut di berkas ini, dan berkas
-- terpisah sql/2026-11-14-whoami.sql sudah DIGABUNG ke sini — sengaja: kalau ada dua berkas yang
-- sama-sama mendefinisikan whoami, menjalankan yang satunya sesudah ini akan menghapus lapisan
-- kunci tanpa peringatan. Rollback mengembalikan verify_login + whoami dalam bentuk tanpa kunci.
--
-- OPERASIONAL: membuka kunci satu akun tanpa rollback (jalankan lewat SQL editor / db query):
--   delete from public.login_attempts where username = 'nama_akun';
-- Baris juga hilang sendiri saat login/hash cocok, dan dibersihkan otomatis setelah 1 hari
-- menganggur.

-- ---------------------------------------------------------------------------------------
-- 1. Tabel penghitung kegagalan login, satu baris per username (dinormalkan: huruf kecil).
--    failures       = kegagalan berurutan sejak percobaan terakhir di luar jendela/gagal sukses
--    lock_level     = berapa kali sudah terkunci (dipakai untuk melipatgandakan lama kunci)
--    locked_until   = akhir penguncian berjalan (null = tidak terkunci)
--    last_attempt_at= waktu percobaan terakhir (dipakai menjendelakan rangkaian + bersih-bersih)
-- ---------------------------------------------------------------------------------------
create table if not exists public.login_attempts (
  username text primary key,
  failures int not null default 0,
  lock_level int not null default 0,
  locked_until timestamptz,
  last_attempt_at timestamptz not null default now()
);

-- Dipakai pembersihan baris lama di dalam verify_login (tanpa cron).
create index if not exists login_attempts_last_attempt_idx
  on public.login_attempts (last_attempt_at);

alter table public.login_attempts enable row level security;

-- Anon tidak boleh membaca/menulis tabel ini sama sekali: hanya verify_login (SECURITY DEFINER)
-- yang menyentuhnya. Membaca tabel ini akan membocorkan username mana yang sedang terkunci.
revoke all on public.login_attempts from anon, authenticated;

-- ---------------------------------------------------------------------------------------
-- 2. Helper kunci bersama. verify_login DAN whoami memakai EMBER YANG SAMA per username, jadi
--    penyerang tidak mendapat jatah percobaan tambahan dengan berpindah oracle (5 gagal lewat
--    verify_login + 5 gagal lewat whoami bukan 10 percobaan, tapi satu rangkaian).
--
--    Fungsi-fungsi ini TIDAK BOLEH bisa dipanggil anon: anon yang bisa memanggil
--    login_lockout_clear akan membuka kuncinya sendiri, dan login_lockout_fail bisa dipakai
--    mengunci akun orang lain. Default Postgres memberi EXECUTE ke PUBLIC, jadi hak itu dicabut
--    eksplisit di bawah. verify_login/whoami tetap bisa memanggilnya karena keduanya SECURITY
--    DEFINER milik owner yang sama (anon hanya dapat hak execute pada dua RPC itu).
-- ---------------------------------------------------------------------------------------
create or replace function public.login_lockout_locked(p_username text)
returns timestamptz
language sql
security definer
set search_path = public
as $$
  select a.locked_until
  from public.login_attempts a
  where a.username = lower(btrim(coalesce(p_username, '')))
    and a.locked_until is not null
    and a.locked_until > now();
$$;

create or replace function public.login_lockout_clear(p_username text)
returns void
language sql
security definer
set search_path = public
as $$
  delete from public.login_attempts where username = lower(btrim(coalesce(p_username, '')));
$$;

-- login_lockout_fail mencatat satu kegagalan kredensial dan, kalau ambang tercapai, menulis
-- kuncinya. ---- TUNABLE ada di sini (satu-satunya tempat): ubah angkanya, lalu jalankan ulang
-- berkas ini. Fungsi ini SENGAJA TIDAK PERNAH raise: RAISE membatalkan seluruh transaksi
-- permintaan, jadi kalau ia raise, baris kunci yang baru ditulisnya ikut hilang (kongkretnya:
-- penguncian tidak pernah terjadi). Pemanggil yang memutuskan apa yang dikembalikan/di-raise.
create or replace function public.login_lockout_fail(p_username text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  c_max_failures   constant int      := 5;             -- gagal berurutan sebelum dikunci
  c_base_lock_sec  constant int      := 900;           -- kunci pertama: 15 menit
  c_max_lock_sec   constant int      := 3600;          -- batas atas kunci: 1 jam
  c_max_level      constant int      := 3;             -- 15m -> 30m -> 60m, lalu tetap 60m
  c_failure_window constant int      := 1800;          -- jeda > 30 menit = rangkaian baru
  c_stale_after    constant interval := interval '1 day'; -- umur baris sebelum dibersihkan

  v_name text := lower(btrim(coalesce(p_username, '')));
  v_tracked boolean := false;
  v_failures int := 0;
  v_level int := 0;
  v_last_attempt timestamptz;
  v_lock_sec int;
begin
  -- Username kosong tidak pernah dicatat: perilaku lama juga tidak pernah mencocokkannya.
  if v_name = '' then
    return;
  end if;

  select a.failures, a.lock_level, a.last_attempt_at
    into v_failures, v_level, v_last_attempt
    from public.login_attempts a
   where a.username = v_name;
  v_tracked := found;

  -- Rangkaian baru (belum ada baris, atau kegagalan terakhir sudah lewat jendela) mulai dari 1
  -- dengan level kunci kembali ke 0.
  if not v_tracked or v_last_attempt is null
     or v_last_attempt < now() - make_interval(secs => c_failure_window) then
    v_failures := 1;
    v_level := 0;
  else
    v_failures := v_failures + 1;
  end if;

  -- Bersih-bersih tanpa cron: baris tak tersentuh > c_stale_after dan tidak terkunci. Baris yang
  -- sedang terkunci dibiarkan supaya penguncian tidak pernah hilang sendiri.
  delete from public.login_attempts
   where last_attempt_at < now() - c_stale_after
     and (locked_until is null or locked_until <= now());

  if v_failures >= c_max_failures then
    -- Lama kunci berlipat: 15m, 30m, 60m, lalu berhenti di c_max_lock_sec.
    v_lock_sec := least(c_base_lock_sec * power(2, v_level)::int, c_max_lock_sec);

    insert into public.login_attempts (username, failures, lock_level, locked_until, last_attempt_at)
    values (v_name, 0, least(v_level + 1, c_max_level), now() + make_interval(secs => v_lock_sec), now())
    on conflict (username) do update
      set failures = excluded.failures,
          lock_level = excluded.lock_level,
          locked_until = excluded.locked_until,
          last_attempt_at = excluded.last_attempt_at;
    return;
  end if;

  insert into public.login_attempts (username, failures, lock_level, locked_until, last_attempt_at)
  values (v_name, v_failures, v_level, null, now())
  on conflict (username) do update
    set failures = excluded.failures,
        lock_level = excluded.lock_level,
        locked_until = null,
        last_attempt_at = excluded.last_attempt_at;
end;
$$;

revoke all on function public.login_lockout_locked(text) from public, anon, authenticated;
revoke all on function public.login_lockout_clear(text) from public, anon, authenticated;
revoke all on function public.login_lockout_fail(text) from public, anon, authenticated;

-- ---------------------------------------------------------------------------------------
-- 3. verify_login + penguncian per username.
--
--    Bentuk balasan (TIDAK berubah dari auth-hardening):
--      sukses            -> json {"username": ..., "role": ...}
--      sandi salah       -> null
--      username kosong   -> null
--      sedang terkunci   -> RAISE EXCEPTION errcode '53400' dengan pesan + sisa detik
--
--    Kenapa terkunci = exception, bukan null: "sandi salah" dan "terkunci" harus bisa dibedakan
--    pemanggil supaya pesannya jelas. Errcode '53400' (configuration_limit_exceeded) SENGAJA
--    bukan PGRST202/42883/42P01, karena kode-kode itu dipakai panel sebagai tanda "RPC belum ada"
--    (lihat MISSING_CODES di functions/api/lib/supabase.js) — memakai kode itu justru membuat
--    panel turun ke jalur lama dan brute force berlanjut.
--
--    PENTING soal transaksi: RAISE membatalkan SELURUH transaksi permintaan ini, jadi kunci yang
--    baru saja ditulis pada percobaan ke-5 ikut hilang kalau percobaan itu juga RAISE. Karena itu
--    percobaan yang tepat memicu kunci tetap dibalas null (seperti sandi salah), lalu percobaan
--    BERIKUTNYA — jalur terkunci, yang tidak menulis apa pun — yang membalas pesan kunci.
--
--    Tanda tangan fungsi SENGAJA tidak ditambah parameter: PostgREST memanggil dengan
--    {p_username, p_password} saja, dan menambah parameter (walau berdefault) akan membuat dua
--    kandidat fungsi sehingga PostgREST menolak panggilan itu sebagai ambigu (PGRST203).
-- ---------------------------------------------------------------------------------------
create or replace function public.verify_login(p_username text, p_password text)
returns json
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_name text := lower(btrim(coalesce(p_username, '')));
  v_result json;
  v_locked_until timestamptz;
begin
  -- Perilaku lama: username kosong tidak pernah cocok dengan baris mana pun.
  if v_name = '' then
    return null;
  end if;

  -- Sedang terkunci: tolak dengan pesan yang jelas + sisa detik. Jalur ini tidak menulis apa
  -- pun, jadi aman memakai RAISE (catatan kunci dari percobaan sebelumnya tetap tersimpan).
  v_locked_until := public.login_lockout_locked(v_name);
  if v_locked_until is not null then
    raise exception 'Terlalu banyak percobaan login gagal untuk akun ini. Coba lagi dalam % detik.',
      ceil(extract(epoch from (v_locked_until - now())))::int
      using errcode = '53400';
  end if;

  -- Verifikasi yang sama seperti sebelumnya (SHA-256 hex dari sandi apa adanya).
  select json_build_object('username', u.username, 'role', u.role)
    into v_result
    from public.users_custom u
   where u.username = v_name
     and u.password_hash = encode(digest(coalesce(p_password, ''), 'sha256'), 'hex')
   limit 1;

  if v_result is not null then
    -- Login sukses: hitungan dan riwayat kunci dibersihkan, jadi user sah tidak pernah terhukum
    -- oleh percobaan gagal orang lain (atau salah ketiknya sendiri sebelum ini).
    perform public.login_lockout_clear(v_name);
    return v_result;
  end if;

  -- Kredensial salah: satu kegagalan dicatat (dan kunci ditulis kalau ambang tercapai).
  -- JANGAN RAISE setelah ini — RAISE akan membatalkan baris kunci yang baru ditulis helper.
  perform public.login_lockout_fail(v_name);
  return null;
end;
$$;

-- ---------------------------------------------------------------------------------------
-- 4. whoami = oracle hash KEDUA (sql/2026-11-14-whoami.sql). Ia membandingkan password_hash
--    persis seperti verify_login, jadi tanpa lapisan ini brute force cukup dipindah ke sana.
--    Diterapkan di sini sebagai CREATE OR REPLACE karena berkas itu milik agent lain; helper
--    kunci dipakai bersama supaya tidak ada logika kedua.
--
--    Kontrak dua-fase panel: saat TERKUNCI fungsi ini mengembalikan NULL, bukan error — panel
--    memperlakukan hasil kosong sebagai "hash tidak cocok" (sesi dihapus) dan tidak pernah
--    melempar error ke UI. Kegagalan hash juga hanya menambah hitungan, tidak pernah raise.
--
--    Sisa perilaku sama persis dengan definisi asli: role NULL dianggap 'user'
--    (coalesce(u.role, 'user')), dan hanya anon yang boleh memanggilnya.
-- ---------------------------------------------------------------------------------------
create or replace function public.whoami(p_username text, p_hash text)
returns text
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_name text := lower(btrim(coalesce(p_username, '')));
  v_role text;
begin
  if v_name = '' then
    return null;
  end if;

  -- Terkunci (lewat verify_login maupun whoami): NULL = hash tidak cocok.
  if public.login_lockout_locked(v_name) is not null then
    return null;
  end if;

  select coalesce(u.role, 'user')
    into v_role
    from public.users_custom u
   where u.username = v_name
     and u.password_hash = coalesce(p_hash, '')
   limit 1;

  if v_role is null then
    perform public.login_lockout_fail(v_name);
    return null;
  end if;

  -- Hash cocok: hitungan dibersihkan, sama seperti login sukses di verify_login.
  perform public.login_lockout_clear(v_name);
  return v_role;
end;
$$;

revoke all on function public.whoami(text, text) from public;
revoke all on function public.whoami(text, text) from authenticated;
grant execute on function public.whoami(text, text) to anon;

-- ---------------------------------------------------------------------------------------
-- 5. Izin: sama seperti sebelumnya — anon hanya boleh memanggil verify_login dan whoami
--    (helper kunci sudah dicabut di bagian 2).
-- ---------------------------------------------------------------------------------------
grant execute on function public.verify_login(text, text) to anon, authenticated;
