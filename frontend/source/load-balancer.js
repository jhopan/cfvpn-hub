// Load Balancer & Subscription Worker for CFVPN Hub
// Mengambil proxy hidup dari Supabase (berdasarkan Ping terbaik) dan merakit config VLESS

// Pemilihan proxy memakai tingkat bukti yang sama dengan worker VPN: verdict EDGE (tunnel_ok, diisi
// cron-worker) > bukti host TLS (tls_ok) > bukti tunnel host scanner (tunnel_host_ok) > ping.
// Baris yang di edge TERBUKTI MATI (tunnel_ok = false) tidak ikut sama sekali: worker VLESS
// berjalan di edge, jadi vonis edge yang menentukan (pengukuran 15 Nov: 87 dari 276 baris aktif).
const SUPABASE_BASE = "https://lumbbmhhmkcnxunuryjr.supabase.co/rest/v1/proxy_pool?select=*&is_active=eq.true";
const SUPABASE_URL = SUPABASE_BASE +
  "&or=(tunnel_ok.is.null,tunnel_ok.eq.true)" +
  "&order=tunnel_ok.desc.nullslast,tls_ok.desc.nullslast,tunnel_host_ok.desc.nullslast,ping.asc.nullslast";
// Cadangan kalau kolom bukti belum ada di tabel (migrasi belum dijalankan): urut ping saja.
const SUPABASE_URL_FALLBACK = SUPABASE_BASE + "&order=ping.asc.nullslast";
const SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imx1bWJibWhobWtjbnh1bnVyeWpyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTQ0NzI1MjEsImV4cCI6MjExMDA0ODUyMX0.ylMqMgv2H4vWax-whnXSRHBlD7DZs9DXVRUD9fAO6mc";

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS_HEADERS });
    }

    if (url.pathname.startsWith("/api/v1/sub")) {
      return await generateSubscription(url, env);
    }

    return new Response("CFVPN Hub Subscription API. Use /api/v1/sub", { status: 200 });
  },
};

async function getLiveProxies() {
  try {
    const headers = { "apikey": SUPABASE_KEY, "Authorization": `Bearer ${SUPABASE_KEY}` };
    let response = await fetch(SUPABASE_URL, { headers });
    if (!response.ok) {
      // Kolom bukti belum ada (migrasi belum jalan) -> pakai urutan lama supaya langganan tetap hidup.
      response = await fetch(SUPABASE_URL_FALLBACK, { headers });
    }
    if (response.ok) {
      return await response.json();
    }
  } catch (e) {}
  return [];
}

function getFlagEmoji(cc) {
  if (!/^[a-zA-Z]{2}$/.test(cc)) return "";
  return String.fromCodePoint(...cc.toUpperCase().split("").map((char) => 0x1f1e6 + char.charCodeAt(0) - 65));
}

function shuffleArray(items) {
  for (let i = items.length - 1; i > 0; i -= 1) {
    const j = Math.floor(Math.random() * (i + 1));
    [items[i], items[j]] = [items[j], items[i]];
  }
  return items;
}

async function generateSubscription(url, env) {
  const filterCC = url.searchParams.get("cc")?.toUpperCase().split(",") || [];
  const filterPort = url.searchParams.get("port")?.split(",") || ["443", "80"];
  const filterLimit = parseInt(url.searchParams.get("limit")) || 20;
  const format = url.searchParams.get("format") || "raw";

  // Deteksi Tipe Langganan (Prem vs Free)
  // Cara deteksi: parameter 'tier=prem' atau ngecek token di URL. Untuk kemudahan kita pakai parameter tier
  const tier = url.searchParams.get("tier") === "prem" ? "PREM" : "FREE";

  // Ambil list worker VPN berdasarkan tier.
  // env.VPN_DOMAINS_PREM dan env.VPN_DOMAINS_FREE bisa diatur dari panel.
  const fallbackPrem = env.VPN_DOMAINS_PREM || "cfvpn-vpn-prem.terabox-hub.workers.dev";
  const fallbackFree = env.VPN_DOMAINS_FREE || "cfvpn-vpn-free.terabox-hub.workers.dev";

  const vpnDomainsParam = url.searchParams.get("domains") || url.searchParams.get("domain") || (tier === "PREM" ? fallbackPrem : fallbackFree);
  const domainList = vpnDomainsParam.split(",").map(d => d.trim()).filter(Boolean);

  let proxyList = await getLiveProxies();

  if (filterCC.length > 0) {
    proxyList = proxyList.filter(p => filterCC.includes(p.country?.toUpperCase()));
  }

  // SOLUSI TERBAIK:
  // Karena API sudah narik data secara urut bukti lalu ping (lihat SUPABASE_URL),
  // kita ambil (slice) jumlah 2x lipat dari limit permintaan user untuk menjaga kualitas elit.
  const elitPoolSize = filterLimit * 2;
  if (proxyList.length > elitPoolSize) {
    proxyList = proxyList.slice(0, elitPoolSize);
  }

  shuffleArray(proxyList);

  const uuid = crypto.randomUUID();
  const result = [];
  let domainIndex = 0;

  outer: for (const prx of proxyList) {
    const ip = prx.ip || "104.17.2.1";
    const proxyPort = prx.port || "443";
    const country = prx.country || "XX";
    const org = prx.org || "Cloud";

    for (const port of filterPort) {
      if (result.length >= filterLimit) break outer;

      const tls = port === "443" || port === "8443";
      const path = `/${ip}-${proxyPort}`;

      const currentVpnDomain = domainList[domainIndex % domainList.length];
      domainIndex++;

      // Tambahkan Label PREM/FREE supaya user tau dia pakai tipe server apa
      const serviceName = currentVpnDomain.split(".")[0].toUpperCase();
      const label = `${result.length + 1} ${getFlagEmoji(country)} [${tier}] ${org} ${tls ? "TLS" : "NTLS"}`;

      const query = new URLSearchParams({
        encryption: "none",
        type: "ws",
        host: currentVpnDomain,
        security: tls ? "tls" : "none",
        sni: tls ? currentVpnDomain : "",
        path: path
      });

      const config = `vless://${uuid}@${currentVpnDomain}:${port}?${query.toString()}#${encodeURIComponent(label)}`;
      result.push(config);
    }
  }

  let finalOutput = result.join("\n");
  let contentType = "text/plain; charset=utf-8";

  if (format === "v2ray" || format === "base64") {
    finalOutput = btoa(finalOutput);
  } else if (format === "clash") {
    const proxies = result.map(c => {
      const u = new URL(c);
      return `  - name: "${decodeURIComponent(u.hash.slice(1))}"
    type: vless
    server: ${u.hostname}
    port: ${u.port}
    uuid: ${u.username}
    udp: true
    tls: ${u.searchParams.get("security") === "tls"}
    network: ws
    servername: ${u.searchParams.get("sni") || u.hostname}
    ws-opts:
      path: "${u.searchParams.get("path") || "/"}"
      headers:
        Host: ${u.searchParams.get("host") || u.hostname}`;
    }).join("\n");
    finalOutput = `proxies:\n${proxies}`;
    contentType = "application/x-yaml; charset=utf-8";
  }

  return new Response(finalOutput, {
    headers: { ...CORS_HEADERS, "Content-Type": contentType }
  });
}
