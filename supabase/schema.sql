-- Skema panel CFVPN Hub (project Supabase yang dipakai frontend + cron-worker + proxy-scraping)
--
-- Diterapkan dengan:
--   npx supabase@latest db query --remote=<project-ref> -f supabase/schema.sql --yes
--
-- Catatan desain (sengaja mengikuti perilaku panel yang sudah ada):
--   * Panel (browser) berbicara langsung ke PostgREST memakai anon key → policy di bawah
--     memberi anon select/insert/update/delete. Artinya siapa pun yang tahu anon key bisa
--     membaca & menulis tabel ini (termasuk hash sandi). Kalau mau lebih ketat, pindahkan
--     verifikasi ke server/service key lalu ganti policy menjadi `to authenticated`.
--   * `is_active` hanya boleh dinaikkan oleh verifikasi mendalam (aplikasi `proxy-scraping`).
--     `cron-worker` hanya boleh mematikannya: cek HTTP dangkal bisa lolos di proxy yang tidak
--     sanggup tunnel TLS 443, sedangkan panel memakai proxy untuk WebSocket VLESS di 443.
--   * Kolom bukti verifikasi: `tls_ok` (sanggup TLS 443), `alt_ok` (sanggup port non-standar),
--     `exit_ip` (alamat keluar sebenarnya).

create extension if not exists pgcrypto;

-- ------------------------------------------------------------------ users_custom -------
create table if not exists public.users_custom (
  username      text primary key,
  password_hash text not null,
  created_at    timestamptz default now(),
  role          text default 'user'
);

-- ------------------------------------------------------------------ proxy_pool ---------
create table if not exists public.proxy_pool (
  id           uuid primary key default gen_random_uuid(),
  ip           text not null,
  port         text not null,
  country      text,
  org          text,
  is_active    boolean default true,
  last_checked timestamptz,
  ping         integer,
  tls_ok       boolean not null default false,
  alt_ok       boolean not null default false,
  exit_ip      text,
  -- Kolom tunnel. `tunnel_*` = verdict probe tunnel dari EDGE Cloudflare (cron-worker CFVPN,
  -- vantage tempat worker VLESS berjalan); `tunnel_host_*` = bukti dari MESIN panproxyscanner
  -- (vantage host). `null` = belum pernah diprobe, berbeda dari `false` = terbukti gagal.
  -- Untuk project yang sudah berjalan, kolom ini ditambahkan lewat berkas di sql/
  -- (2026-11-14-proxy-tunnel-columns.sql dan 2026-11-14-tunnel-host-columns.sql).
  tunnel_ok           boolean,
  tunnel_ms           integer,
  tunnel_checked      timestamptz,
  tunnel_host_ok      boolean,
  tunnel_host_ms      integer,
  tunnel_host_checked timestamptz
);

-- pasangan (ip, port) unik: push dari proxy-scraping memakai upsert on_conflict=ip,port
create unique index if not exists proxy_pool_ip_port_key on public.proxy_pool (ip, port);
-- panel membaca: is_active + last_checked segar, diurutkan ping
create index if not exists proxy_pool_active_idx on public.proxy_pool (is_active, last_checked desc);
create index if not exists proxy_pool_active_tls_idx on public.proxy_pool (is_active, tls_ok, last_checked desc);
create index if not exists proxy_pool_ping_idx on public.proxy_pool (ping);

-- ------------------------------------------------------------------ user_states --------
create table if not exists public.user_states (
  username   text primary key references public.users_custom(username),
  state_data jsonb,
  updated_at timestamptz default now()
);

-- ------------------------------------------------------------------ akses (PostgREST) --
grant usage on schema public to anon, authenticated, service_role;
grant select, insert, update, delete on public.users_custom to anon, authenticated;
grant select, insert, update, delete on public.proxy_pool to anon, authenticated;
grant select, insert, update, delete on public.user_states to anon, authenticated;

-- ------------------------------------------------------------------ RLS + policy -------
alter table public.users_custom enable row level security;
alter table public.proxy_pool   enable row level security;
alter table public.user_states  enable row level security;

drop policy if exists users_custom_anon_all on public.users_custom;
create policy users_custom_anon_all on public.users_custom
  for all to anon, authenticated using (true) with check (true);

drop policy if exists proxy_pool_anon_all on public.proxy_pool;
create policy proxy_pool_anon_all on public.proxy_pool
  for all to anon, authenticated using (true) with check (true);

drop policy if exists user_states_anon_all on public.user_states;
create policy user_states_anon_all on public.user_states
  for all to anon, authenticated using (true) with check (true);

-- PostgREST menyimpan skema di cache; pastikan perubahan kolom langsung terbaca.
notify pgrst, 'reload schema';
