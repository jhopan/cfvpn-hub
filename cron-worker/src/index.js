import { createClient } from "@supabase/supabase-js";
import { connect } from "cloudflare:sockets";
import { checkProxy } from "./proxy-check.mjs";

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(this.processProxies(env));
  },
  async fetch(request, env, ctx) {
    if (new URL(request.url).pathname === '/trigger') {
      ctx.waitUntil(this.processProxies(env));
      return new Response("Check process started in background.", { status: 200 });
    }
    return new Response("Cron worker is active.", { status: 200 });
  },
  async processProxies(env) {
    const SUPABASE_URL = "https://lumbbmhhmkcnxunuryjr.supabase.co";
    const SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imx1bWJibWhobWtjbnh1bnVyeWpyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTQ0NzI1MjEsImV4cCI6MjExMDA0ODUyMX0.ylMqMgv2H4vWax-whnXSRHBlD7DZs9DXVRUD9fAO6mc";
    const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

    try {
      // Batch kecil: tiap proxy diuji dengan handshake nyata (SOCKS5/HTTP CONNECT + satu
      // request HTTP), jadi tidak mungkin memeriksa ribuan baris dalam satu run.
      //
      // Peran worker ini HANYA menjaga pool yang sudah aktif (menandai `is_active = false`
      // kalau proxy benar-benar tidak meneruskan permintaan). Worker ini TIDAK PERNAH
      // menyalakan proxy:
      //   - cek dangkal di sini bisa lolos di proxy yang tidak sanggup TLS, sedangkan panel
      //     memakai proxy untuk WebSocket VLESS di 443 → hasilnya konfigurasi mati;
      //   - timeout 5 detik terlalu ketat untuk proxy publik sehat (terukur 7-12 detik),
      //     jadi bisa mematikan proxy bagus — itu ditangani verifikasi mendalam
      //     (proxy-scraping) yang menaikkan kembali barisnya.
      // Karena itu baris aktif didahulukan, dan proxy yang lolos hanya menyegarkan
      // last_checked/ping tanpa menyentuh is_active.
      //
      // `ctx.waitUntil` hanya diberi ~30 detik setelah respons; satu pemeriksaan bisa makan
      // 5-10 detik (SOCKS5 + fallback HTTP CONNECT), jadi jumlahnya dibatasi dan loop
      // berhenti sendiri saat anggaran waktu habis — sisa baris dilanjutkan run berikutnya.
      const BATCH = 12;
      const DEADLINE_MS = 25000;
      const deadline = Date.now() + DEADLINE_MS;
      const { data: proxies, error } = await supabase
        .from('proxy_pool')
        .select('id, ip, port')
        .eq('is_active', true)
        .order('last_checked', { ascending: true, nullsFirst: true })
        .limit(BATCH);
      if (error) {
        console.error("Gagal load proxy dari Supabase:", error);
        return;
      }

      if (!proxies || proxies.length === 0) {
        console.log("Tidak ada proxy aktif untuk diperiksa.");
        return;
      }

      console.log("Memeriksa maksimal " + proxies.length + " proxy aktif (" + DEADLINE_MS + " ms)...");

      let checked = 0;
      let disabled = 0;
      for (const proxy of proxies) {
        if (Date.now() >= deadline) {
          console.log("Anggaran waktu habis setelah " + checked + " proxy; sisanya dilanjutkan run berikutnya.");
          break;
        }
        const result = await checkProxy(proxy.ip, Number(proxy.port), connect, { timeoutMs: 5000 });
        checked++;
        console.log("Proxy " + proxy.ip + ":" + proxy.port + " -> " + (result.alive ? "HIDUP " + result.protocol + " " + result.ms + "ms" : "MATI (" + result.detail + ")"));

        if (result.alive) {
          await supabase.from('proxy_pool')
            .update({ last_checked: new Date().toISOString(), ping: result.ms })
            .eq('id', proxy.id);
        } else {
          await supabase.from('proxy_pool')
            .update({ is_active: false, last_checked: new Date().toISOString(), ping: null })
            .eq('id', proxy.id);
          disabled++;
        }
      }
      console.log("Selesai: " + checked + " diperiksa, " + disabled + " dimatikan (worker ini tidak pernah menyalakan).");

    } catch (err) {
      console.error("Cron crash:", err);
    }
  }
};
