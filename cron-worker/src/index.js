import { createClient } from "@supabase/supabase-js";
import { connect } from "cloudflare:sockets";
import { isMissingColumnError, probeTunnel } from "./tunnel.js";

// Batas kerja satu siklus. `ctx.waitUntil` hanya diberi ~30 detik setelah respons, jadi
// jumlah baris dibatasi dan tiap koneksi punya timeout sendiri.
const ROWS_PER_RUN = 100; // maksimum baris yang dicoba diprobe per siklus (digilir, bukan acak)
const CONCURRENCY = 10;   // baris diperiksa paralel; tiap baris butuh koneksinya sendiri
// ctx.waitUntil hanya diberi ~30 detik setelah respons terkirim. 25 s aman karena dua hal:
// lane tidak pernah memulai baris baru kalau sisa waktu < ROW_BUDGET_MS (9 s), jadi baris
// terakhir mulai paling lambat pada detik ke-16; dan anggaran tiap baris di-clamp ke
// `deadline - now`, jadi lane berhenti paling lambat di deadline (25 s), bukan 25 + 9 s.
// Sisa ~5 s dari jatah platform menampung PATCH penutup. Kuncinya: anggaran per baris TIDAK
// pernah melampaui deadline (lihat `budget` di processProxies), jadi ekor siklus tidak bisa
// jadi deadline + ROW_BUDGET_MS — pola itulah yang dulu memotong siklus di platform.
const DEADLINE_MS = 25000;
const ROW_BUDGET_MS = 9000;
const CHECK_TIMEOUT_MS = 5000;
const TUNNEL_TIMEOUT_MS = 6000; // per koneksi: HTTP CONNECT dulu, lalu SOCKS5 kalau gagal
// 4 s: cukup longgar untuk proxy lambat-tapi-sehat (cek dasar sendiri berbatas 5 s) dan cukup
// ketat untuk proxy blackhole. Sempat dicoba 2,5 s; tidak dipakai karena bisa menandai proxy
// lambat sebagai mati padahal worker ini mematikan baris.
const CONNECT_TIMEOUT_MS = 4000; // hanya menjaga pembukaan soket (lihat guardedConnect)

// Kolom bukti tunnel (sql/2026-11-14-proxy-tunnel-columns.sql). Selama migrasi belum
// dijalankan, PostgREST menolak kolom ini (HTTP 400 / PGRST204); worker mencatatnya sekali
// per siklus lalu lanjut dengan kolom lama saja supaya ping/is_active tetap tercatat.
const TUNNEL_COLUMNS = "tunnel_ok/tunnel_ms/tunnel_checked";

// Ringkasan siklus terakhir, dibaca lewat GET /status. Tanpa ini, kegagalan di dalam
// ctx.waitUntil tidak terlihat dari luar: respons HTTP sudah terkirim, jadi cron bisa "200 tapi
// tidak menulis apa pun" tanpa jejak yang bisa diperiksa.
let lastRun = { startedAt: null, finishedAt: null, rows: 0, checked: 0, tunnel: 0, disabled: 0, tunnelColumns: null, error: null };

// connect() dari cloudflare:sockets bisa menggantung tanpa batas pada alamat yang di-blackhole
// (tidak ada RST) dan socket.opened tidak mendukung abort. Probe punya timeout per tahap, tapi
// semuanya menunggu socket.opened lebih dulu, jadi satu baris seperti itu menahan lane sampai
// siklus dipotong platform (terukur waktu itu: semua lane stuck, checked=0). Bungkus: tutup soket kalau
// tidak terbuka tepat waktu, dan kembalikan objek dengan antarmuka socket yang sama supaya probe
// tidak tahu bedanya.
// Satu set soket per baris supaya penjaga anggaran bisa memutus semuanya sekaligus:
// soket yang tidak pernah terbuka membuat tulis/baca menggantung tanpa batas, dan menutupnya
// adalah satu-satunya cara membuat probe menyerah.
function makeGuardedConnect() {
  const sockets = new Set();
  const connectFn = function (addr, port) {
    const socket = connect(addr, port);
    sockets.add(socket);
    const timer = setTimeout(function () {
      try { socket.close(); } catch (e) {}
    }, CONNECT_TIMEOUT_MS);
    const opened = Promise.resolve(socket.opened).then(
      function (info) { clearTimeout(timer); return info; },
      function (err) { clearTimeout(timer); throw err; },
    );
    return {
      readable: socket.readable,
      writable: socket.writable,
      opened: opened,
      close: function () { clearTimeout(timer); try { socket.close(); } catch (e) {} },
      startTls: function (options) { return socket.startTls(options); },
    };
  };
  return {
    connect: connectFn,
    closeAll: function () {
      sockets.forEach(function (socket) { try { socket.close(); } catch (e) {} });
      sockets.clear();
    },
  };
}

async function noteMissingTunnelColumns(state, error) {
  if (!state.tunnelColumns) return;
  if (!isMissingColumnError(error)) return;
  state.tunnelColumns = false;
  if (state.warned) return;
  state.warned = true;
  console.warn("Kolom " + TUNNEL_COLUMNS + " belum ada di proxy_pool — jalankan sql/2026-11-14-proxy-tunnel-columns.sql di Supabase. Siklus ini lanjut hanya dengan kolom lama.");
}

// Baris aktif, yang paling lama tidak diprobe lebih dulu. Kalau kolom tunnel_checked belum ada,
// urutannya jatuh ke last_checked — kolom itu tetap ditulis setiap baris yang diperiksa, jadi
// giliran tetap berputar (baris yang terlewat karena anggaran waktu tetap di depan).
async function loadActiveProxies(supabase, state) {
  const query = function () {
    return state.tunnelColumns
      ? supabase.from('proxy_pool').select('id, ip, port, tunnel_checked').eq('is_active', true)
        .order('tunnel_checked', { ascending: true, nullsFirst: true }).limit(ROWS_PER_RUN)
      : supabase.from('proxy_pool').select('id, ip, port, last_checked').eq('is_active', true)
        .order('last_checked', { ascending: true, nullsFirst: true }).limit(ROWS_PER_RUN);
  };

  let res = await query();
  if (res.error && state.tunnelColumns) {
    await noteMissingTunnelColumns(state, res.error);
    if (!state.tunnelColumns) res = await query();
  }
  if (res.error) {
    console.error("Gagal load proxy dari Supabase:", res.error);
    state.loadError = String(res.error.code || "") + " " + String(res.error.message || res.error);
    return null;
  }
  return res.data || [];
}

// Tulis satu baris: is_active/last_checked/ping seperti sebelumnya, ditambah bukti tunnel.
// Kalau kolom baru ditolak PostgREST, PATCH diulang tanpa kolom itu (sekali) supaya hasil cek
// lama tidak hilang.
async function patchProxy(supabase, id, fields, tunnelFields, state) {
  const withTunnel = state.tunnelColumns ? Object.assign({}, fields, tunnelFields) : fields;
  const first = await supabase.from('proxy_pool').update(withTunnel).eq('id', id);
  if (!first.error) return;

  if (state.tunnelColumns && isMissingColumnError(first.error)) {
    await noteMissingTunnelColumns(state, first.error);
    const retry = await supabase.from('proxy_pool').update(fields).eq('id', id);
    if (retry.error) console.error("Gagal update proxy " + id + ":", retry.error);
    return;
  }
  console.error("Gagal update proxy " + id + ":", first.error);
}

// Satu baris: cek lama (SOCKS5 → HTTP CONNECT, memutuskan is_active/ping) dan probe tunnel
// (HTTP CONNECT dulu, fallback SOCKS5, "GET / HTTP/1.0" ke example.com) berjalan bersamaan
// supaya anggaran waktu tidak dipakai dua kali berurutan.
function errorText(err) {
  return "error: " + (err && err.message ? err.message : String(err));
}

async function inspectProxy(supabase, row, connectFn, state, stats) {
  const port = Number(row.port);
  // Probe tunnel = bukti nyata paket diteruskan proxy, jadi verdictnyalah yang menentukan
  // `is_active` (dua arah). Kebijakan lama memakai cek ringan 5 detik sebagai penentu dan itu
  // terbukti salah dua arah: 15 baris tembus tapi dimatikan, 7 baris aktif tapi terbukti mati.
  // Sekali probe saja per baris, jadi siklus justru lebih cepat daripada sebelumnya.
  const tunnel = await probeTunnel(row.ip, port, connectFn, { timeoutMs: TUNNEL_TIMEOUT_MS }).catch(function (err) {
    return { ok: false, protocol: null, ms: null, detail: errorText(err) };
  });
  const now = new Date().toISOString();

  stats.checked++;
  if (tunnel.ok) stats.tunnel++;
  if (!tunnel.ok) stats.disabled++;
  console.log("Proxy " + row.ip + ":" + row.port + " -> " +
    (tunnel.ok ? "TEMBUS " + tunnel.protocol + " " + tunnel.ms + "ms (" + tunnel.detail + ")" : "GAGAL (" + tunnel.detail + ")"));

  // Hanya MEMATIKAN. Yang berhak menyalakan baris adalah panproxyscanner (pipeline produksi,
  // aturan di repo Pan-ProxyScanner: cron panel dan pull-verify tidak boleh menyalakan). Di sini
  // kita mencatat bukti (ping/tunnel_*) dan mematikan yang terbukti gagal; baris yang gagal
  // sesaat akan dinyalakan lagi oleh siklus scraper berikutnya.
  const fields = tunnel.ok
    ? { last_checked: now, ping: tunnel.ms }
    : { is_active: false, last_checked: now, ping: null };
  const tunnelFields = { tunnel_ok: tunnel.ok, tunnel_ms: tunnel.ok ? tunnel.ms : null, tunnel_checked: now };
  await patchProxy(supabase, row.id, fields, tunnelFields, state);
}

export default {
  async scheduled(event, env, ctx) {
    ctx.waitUntil(this.processProxies(env));
  },
  async fetch(request, env, ctx) {
    const path = new URL(request.url).pathname;
    if (path === '/status') {
      return new Response(JSON.stringify(Object.assign({ ok: true }, lastRun)), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    if (path === '/trigger') {
      ctx.waitUntil(this.processProxies(env));
      return new Response("Check process started in background.", { status: 200 });
    }
    return new Response("Cron worker is active.", { status: 200 });
  },
  async processProxies(env) {
    const SUPABASE_URL = "https://lumbbmhhmkcnxunuryjr.supabase.co";
    const SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imx1bWJibWhobWtjbnh1bnVyeWpyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTQ0NzI1MjEsImV4cCI6MjExMDA0ODUyMX0.ylMqMgv2H4vWax-whnXSRHBlD7DZs9DXVRUD9fAO6mc";
    const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

    const startedAt = new Date().toISOString();
    lastRun = { startedAt, finishedAt: null, rows: 0, checked: 0, tunnel: 0, disabled: 0, tunnelColumns: null, error: null };
    try {
      // Batch kecil: tiap proxy diuji dengan handshake nyata (SOCKS5/HTTP CONNECT + satu
      // request HTTP), jadi tidak mungkin memeriksa ribuan baris dalam satu run.
      //
      // Worker ini menjaga pool berdasarkan probe tunnel (boleh mematikan DAN menghidupkan kembali
      // kalau proxy benar-benar tidak meneruskan permintaan).
      //   - cek dangkal di sini bisa lolos di proxy yang tidak sanggup TLS, sedangkan panel
      //     memakai proxy untuk WebSocket VLESS di 443 → hasilnya konfigurasi mati;
      //   - timeout 5 detik terlalu ketat untuk proxy publik sehat (terukur 7-12 detik),
      //     jadi bisa mematikan proxy bagus — itu ditangani verifikasi mendalam
      //     (proxy-scraping) yang menaikkan kembali barisnya.
      // Karena itu baris aktif didahulukan, dan proxy yang lolos hanya menyegarkan
      // last_checked/ping tanpa menyentuh is_active.
      //
      // `is_active`/`ping` dari daftar pihak ketiga bukan bukti tunnel jalan (terukur: 3 baris
      // berstatus hidup, 0/3 tembus koneksi TCP nyata dari edge). Karena itu tiap baris juga
      // diprobe tunnel sungguhan (src/tunnel.js) dan hasilnya ditulis ke
      // tunnel_ok/tunnel_ms/tunnel_checked sebagai bukti, tanpa mengubah aturan is_active.
      //
      // Anggaran: satu siklus hanya memuat ROWS_PER_RUN baris (digilir lewat urutan query),
      // menjalankannya CONCURRENCY sekaligus, dan berhenti saat DEADLINE_MS habis; sisanya
      // dilanjutkan siklus berikutnya tanpa baris yang kelaparan.
      // Hitungan: 6 siklus/jam × 100 baris = 600 baris/jam (plafon). Pool ~300 baris aktif
      // karena itu tersapu penuh tiap ~30 menit. Batas waktu per siklus: baris hanya dimulai
      // selama sisa waktu ≥ ROW_BUDGET_MS, jadi dengan baris selambat 9 s pun satu siklus
      // menyelesaikan 10 lane × 2 gelombang = 20 baris (≈120 baris/jam), bukan 0.
      const state = { tunnelColumns: true, warned: false };
      const deadline = Date.now() + DEADLINE_MS;

      const proxies = await loadActiveProxies(supabase, state);
      lastRun.tunnelColumns = state.tunnelColumns;
      lastRun.rows = proxies ? proxies.length : 0;
      if (!proxies) { lastRun.error = "gagal memuat proxy_pool: " + (state.loadError || "?"); lastRun.finishedAt = new Date().toISOString(); return; }
      if (!proxies.length) {
        console.log("Tidak ada proxy aktif untuk diperiksa.");
        return;
      }

      console.log("Memeriksa maksimal " + proxies.length + " proxy aktif (" + CONCURRENCY + " paralel, " + DEADLINE_MS + " ms)...");

      const stats = { checked: 0, disabled: 0, tunnel: 0, stuck: 0 };
      lastRun.stats = stats;
      let cursor = 0;
      const lanes = [];
      for (let i = 0; i < Math.min(CONCURRENCY, proxies.length); i++) {
        lanes.push((async function () {
          for (;;) {
            // Jangan mulai baris baru kalau sisa waktu tidak cukup untuk satu pemeriksaan penuh:
            // baris itu akan dipotong di tengah dan pekerjaannya (PATCH) hilang.
            if (Date.now() + ROW_BUDGET_MS >= deadline) return;
            const index = cursor++;
            if (index >= proxies.length) return;
            // Penjaga keras: probe punya timeout sendiri, tapi koneksi ke alamat yang di-blackhole
            // bisa menggantung tanpa pernah menolak. Tanpa race ini satu baris seperti itu menahan
            // lane sampai siklus dipotong platform (terlihat: /status checked=0, finishedAt null).
            const budget = Math.max(1000, Math.min(ROW_BUDGET_MS, deadline - Date.now()));
            const rowConnect = makeGuardedConnect();
            const row = proxies[index];
            const work = inspectProxy(supabase, row, rowConnect.connect, state, stats);
            work.catch(function () {});
            const guard = new Promise(function (resolve) {
              const timer = setTimeout(function () {
                // Putus soket baris ini, lalu catat baris sebagai mati: alamat yang menggantung
                // (tanpa RST) memang tidak bisa dipakai dari edge.
                rowConnect.closeAll();
                const now = new Date().toISOString();
                patchProxy(supabase, row.id, { is_active: false, last_checked: now, ping: null }, { tunnel_ok: false, tunnel_ms: null, tunnel_checked: now }, state);
                resolve("timeout");
              }, budget);
              work.finally(function () { clearTimeout(timer); });
            });
            const outcome = await Promise.race([work.then(function () { return "done"; }), guard]);
            if (outcome !== "done") stats.stuck = (stats.stuck || 0) + 1;
          }
        })());
      }
      await Promise.all(lanes);

      const remaining = proxies.length - stats.checked;
      console.log("Selesai: " + stats.checked + " diperiksa, " + stats.tunnel + " tunnel tembus, " + stats.disabled + " dimatikan (worker ini tidak pernah menyalakan)." +
        (remaining > 0 ? " " + remaining + " baris dilewati karena anggaran waktu; dilanjutkan run berikutnya." : ""));

    } catch (err) {
      lastRun.error = errorText(err);
      console.error("Cron crash:", err);
    } finally {
      // Field ringkas di atas disalin dari stats supaya /status tidak menampilkan 0 padahal
      // pekerjaan berjalan (dulu membingungkan saat mendiagnosa siklus yang macet).
      if (lastRun.stats) {
        lastRun.checked = lastRun.stats.checked;
        lastRun.tunnel = lastRun.stats.tunnel;
        lastRun.disabled = lastRun.stats.disabled;
      }
      lastRun.finishedAt = new Date().toISOString();
    }
  }
};
