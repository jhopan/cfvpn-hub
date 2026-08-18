import { createClient } from "@supabase/supabase-js";
import { connect } from "cloudflare:sockets";

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
    const SUPABASE_URL = "https://cgflrpjavyotvolnvcnl.supabase.co";
    const SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImNnZmxycGphdnlvdHZvbG52Y25sIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODU5MjU5MTYsImV4cCI6MjEwMTUwMTkxNn0.-e9GFpQBDBQUdAYsqfu7kuUwAQaY_Mf6dc3BhUuGNmc";
    const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

    try {
      const { data: proxies, error } = await supabase.from('proxy_pool').select('*');
      if (error) {
        console.error("Gagal load proxy dari Supabase:", error);
        return;
      }
      
      if (!proxies || proxies.length === 0) {
        console.log("Daftar proxy kosong.");
        return;
      }

      console.log("Memulai cek " + proxies.length + " proxy...");

      for (const proxy of proxies) {
        let isAlive = false;
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 5000);

          const req = await fetch("https://id1.foolvpn.web.id/api/v1/check?ip=" + proxy.ip + ":" + proxy.port, {
            signal: controller.signal
          });
          clearTimeout(timeoutId);

          if (req.ok) {
            const data = await req.json();
            // Endpoint ini mengembalikan data.ip (string IP) jika berhasil nge-ping, tidak ada tcp_port_open
            if (data && data.ip && data.ip !== "") {
              isAlive = true;
            }
          }
        } catch (e) {
          isAlive = false;
        }

        console.log("Proxy " + proxy.ip + ":" + proxy.port + " -> " + (isAlive ? "HIDUP" : "MATI"));

        await supabase.from('proxy_pool')
          .update({ is_active: isAlive, last_checked: new Date().toISOString() })
          .eq('id', proxy.id);
      }
      console.log("Proses cron proxy checker selesai.");

    } catch (err) {
      console.error("Cron crash:", err);
    }
  }
};
