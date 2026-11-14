-- Pemulihan sekali jalan: baris yang probe tunnel-nya pernah berhasil tetapi dimatikan oleh
-- cek ringan 5 s (kebijakan lama) dinyalakan kembali. Setelah ini, verdict cron memakai probe
-- tunnel, jadi kejadian yang sama tidak terulang.
update public.proxy_pool
   set is_active = true
 where tunnel_ok is true
   and not is_active;

select
  count(*) filter (where is_active) as aktif,
  count(*) filter (where tunnel_ok is true and is_active) as tembus_dan_aktif,
  count(*) filter (where tunnel_ok is true and not is_active) as tembus_tapi_mati
from public.proxy_pool;