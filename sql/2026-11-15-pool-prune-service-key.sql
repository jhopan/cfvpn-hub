-- sql/2026-11-15-pool-prune-service-key.sql
--
-- Tujuan: mencabut kemampuan DELETE `anon` pada public.proxy_pool.
--
-- Kenapa: baris pool adalah data sementara hasil scrape, tetapi sampai sekarang anon key penuh
-- bisa menghapus isinya. Anon key ikut terkirim ke browser panel, jadi siapa pun yang membuka
-- panel (atau menyalin key itu) bisa `delete from proxy_pool` — sementara scanner hanya butuh
-- menulis, bukan menghapus.
--
-- Pemakai DELETE yang sah setelah migrasi ini:
--   (a) Pan-ProxyScanner (Go): prune baris mati memakai setting `supabase_service_key`.
--   (b) Panel cfvpn-hub: tombol bersihkan baris mati lewat Pages Function yang memakai service
--       key + verifikasi whoami, bukan lagi `supabase.from("proxy_pool").delete()` dari browser.
-- Keduanya memakai `service_role`, yang melewati RLS — jadi TIDAK perlu policy DELETE baru.
-- `authenticated` juga sengaja tidak diberi DELETE: login panel bukan Supabase Auth, tidak ada
-- pemakai sah untuk peran itu.
--
-- SELECT/INSERT/UPDATE `anon` TIDAK diubah: scanner masih perlu upsert `on_conflict=ip,port`
-- dan menulis verdict probe. RLS bersifat per-perintah, jadi ketiga izin itu dibiarkan.
--
-- Jalankan manual di Supabase SQL Editor, atau:
--   npx supabase@latest db query --remote=<project-ref> -f sql/2026-11-15-pool-prune-service-key.sql --yes
--
-- Idempoten: aman dijalankan berulang.

alter table if exists public.proxy_pool enable row level security;

-- ---------------------------------------------------------------------------------------
-- 1. Cabut SEMUA policy yang memberi DELETE ke anon/authenticated/PUBLIC.
--    Policy di repo berlapis: `proxy_pool_anon_all` (`for all` di supabase/schema.sql) dan
--    `proxy_pool_delete_anon` (`for delete` di sql/2026-11-14-tunnel-host-columns.sql); project
--    yang sudah berjalan bisa punya nama lain. Karena itu dicari dari katalog, bukan dari nama,
--    supaya tidak ada policy `for all` yang tertinggal dan masih memberi anon DELETE.
-- ---------------------------------------------------------------------------------------
do $$
declare
  r record;
begin
  for r in
    select p.polname
      from pg_policy p
      join pg_class c     on c.oid = p.polrelid
      join pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'public'
       and c.relname = 'proxy_pool'
       and p.polcmd in ('d', '*')            -- 'd' = DELETE, '*' = ALL
       and (
             p.polroles = '{0}'::oid[]       -- PUBLIC (oid 0): berlaku untuk semua role
             or exists (
                  select 1
                    from unnest(p.polroles) as ro(role_oid)
                    join pg_roles pr on pr.oid = ro.role_oid
                   where pr.rolname in ('anon', 'authenticated')
                )
           )
  loop
    execute format('drop policy if exists %I on public.proxy_pool', r.polname);
    raise notice 'public.proxy_pool: policy % dicabut (memberi DELETE ke anon/authenticated)', r.polname;
  end loop;
end;
$$;

-- ---------------------------------------------------------------------------------------
-- 2. Pastikan SELECT/INSERT/UPDATE anon tetap ada. Kalau langkah 1 membuang policy `for all`,
--    izin baca/tulis anon ikut hilang; blok ini mengembalikannya ke bentuk per-perintah yang
--    sama dengan sql/2026-11-14-tunnel-host-columns.sql. Aman diulang.
-- ---------------------------------------------------------------------------------------
drop policy if exists proxy_pool_select_anon on public.proxy_pool;
create policy proxy_pool_select_anon on public.proxy_pool for select to anon, authenticated using (true);

drop policy if exists proxy_pool_insert_anon on public.proxy_pool;
create policy proxy_pool_insert_anon on public.proxy_pool for insert to anon, authenticated with check (true);

drop policy if exists proxy_pool_update_anon on public.proxy_pool;
create policy proxy_pool_update_anon on public.proxy_pool for update to anon, authenticated using (true) with check (true);

-- ---------------------------------------------------------------------------------------
-- 3. Grant tingkat tabel: DELETE dicabut dari anon dan authenticated, SELECT/INSERT/UPDATE
--    ditegaskan ulang (upsert scanner butuh INSERT + UPDATE). RLS dan grant sama-sama menahan;
--    grant dicabut supaya penolakan DELETE terlihat sebagai error izin, bukan diam-diam 0 baris.
-- ---------------------------------------------------------------------------------------
revoke delete on public.proxy_pool from anon, authenticated;
grant select, insert, update on public.proxy_pool to anon, authenticated;

-- `service_role` melewati RLS; grant-nya ditegaskan supaya prune tetap mungkin walau default
-- privileges project pernah diubah. Dijaga kondisional agar berkas ini tidak gagal di Postgres
-- biasa yang tidak punya role tersebut (mis. saat diuji lokal).
do $$
begin
  if exists (select 1 from pg_roles where rolname = 'service_role') then
    execute 'grant select, insert, update, delete on public.proxy_pool to service_role';
  else
    raise notice 'role service_role tidak ada; grant DELETE dilewati';
  end if;
end;
$$;

-- PostgREST menyimpan skema + policy di cache; tanpa ini panel/scanner masih memakai yang lama.
notify pgrst, 'reload schema';