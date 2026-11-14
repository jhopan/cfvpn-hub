// CFVPN Hub - VPN Worker (VLESS over WebSocket)
//
// Alur:
//   WebSocket + path /ip:port  -> VLESS tunnel lewat proxy (cmd=1, atau cmd=3 = mux.cool)
//   cmd=2 port 53 (DNS)        -> dijawab worker sendiri lewat DoH, tanpa relay UDP
//   cmd=2 port lain (UDP)      -> diteruskan ke relay UDP sendiri kalau env.RELAY_SERVER_UDP
//                                 diisi (proxy-relay/udp-relay.mjs); tanpa relay ditutup cepat
//   /health                    -> health check JSON + hitungan isolate (version, counters)
//   /myip                      -> info IP client
//   HTTP biasa                 -> reverse proxy (kamuflase)
//
// Proxy dipakai lewat SOCKS5 dulu, lalu HTTP CONNECT. Protokol dideteksi
// dari respons, bukan dari nomor port (proxy SOCKS5 sering di 443).

import { connect } from "cloudflare:sockets";

// Satu-satunya beda script ini dengan vpn-worker-free.js. Tier Free tidak memakai fitur
// premium yang butuh binding/env tambahan (relay UDP); sisanya kode yang sama persis supaya bug
// yang diperbaiki di satu tier tidak tertinggal di tier lain.  yang
// menurunkan berkas free dari berkas ini (hanya baris ini yang berubah).
const TIER_FREE = true;

// Query DNS (cmd=2, port 53) dijawab langsung oleh worker lewat DoH: relay UDP
// eksternal tidak dipakai lagi (keduanya sudah tidak bisa dihubungi). Endpoint bisa
// dioverride lewat env.DOH_ENDPOINT — dipakai oleh tests/smoke-vpn-worker.mjs.
const DOH_ENDPOINT = "https://1.1.1.1/dns-query";
const DOH_TIMEOUT = 5000;
const MAX_DNS_MESSAGE = 1232;

const WS_OPEN = 1;
const WS_CLOSING = 2;
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
  "Access-Control-Max-Age": "86400",
};

const PROXY_HANDSHAKE_TIMEOUT = 8000;
const SOCKS5_PROBE_TIMEOUT = 2500; // deteksi awal SOCKS5; proxy yang diam saja tidak menahan 8 detik
const PROXY_PROTOCOL_MAX_ENTRIES = 64;
const proxyProtocols = new Map(); // per-isolate: "host:port" -> "socks5" | "http"
const dnsInflight = new Map(); // per-isolate: kunci cache -> Promise DoH yang sedang jalan
const MAX_HEADER_BYTES = 4096;

// Failover proxy: kalau proxy di path gagal, worker mencoba cadangan (env.FALLBACK_PROXIES
// dulu, lalu puncak tabel proxy_pool panel) supaya koneksi klien tidak langsung mati.
// Ini BUKAN rotasi: proxy utama tetap yang dipakai selama dia sehat.
const FALLBACK_TTL_MS = 120000;
const FALLBACK_MAX = 3;
const FALLBACK_FETCH_TIMEOUT = 2500;
// Hedge: kalau proxy utama belum selesai setelah HEDGE_DELAY_MS, cadangan mulai dicoba
// paralel; yang pertama berhasil memakai tunnel, yang kalah menutup soketnya sendiri.
// Ini lebih baik daripada memendekkan timeout proxy utama: proxy lambat tapi sehat tetap
// boleh menang, sedangkan proxy yang diam/mati tidak lagi menahan belasan detik.
const HEDGE_DELAY_MS = 1500;

// Batching socket->WebSocket: potongan yang datang berdekatan digabung jadi satu pesan
// (hemat frame + CPU di worker dan klien). Ambang ukuran dan jendela waktu kecil supaya
// trafik interaktif tidak terasa; WS_BATCH_MS=0 mematikan batching.
const BATCH_BYTES_DEFAULT = 16384;
const BATCH_MS_DEFAULT = 2;
const SUPABASE_URL = "https://lumbbmhhmkcnxunuryjr.supabase.co";
const SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imx1bWJibWhobWtjbnh1bnVyeWpyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTQ0NzI1MjEsImV4cCI6MjExMDA0ODUyMX0.ylMqMgv2H4vWax-whnXSRHBlD7DZs9DXVRUD9fAO6mc";
// Cache pool per-filter (kunci "all" atau "ID,SG") + fetch yang sedang jalan per kunci,
// supaya beberapa selector tidak saling menimpa dan tetap menunggu hasil yang sama.
const POOL_CACHE_MAX = 8;
const poolCache = new Map();
const poolFetching = new Map();
// Urutan pool: bukti EDGE dulu, baru bukti host scanner, baru ping tercepat.
// `tunnel_ok` diisi cron CFVPN dari edge = vantage yang sama dengan tempat worker ini jalan,
// jadi verdictnya paling relevan (true -> null/belum diprobe -> false). `tls_ok` diisi
// panproxyscanner dari host scanner = bukti tunnel TLS 443 + verifikasi sertifikat; ia hanya
// penentu untuk baris yang belum pernah diprobe edge, karena host scanner bisa tembus ke
// proxy yang dari edge sudah mati. Proyeksi `select` tidak ikut berubah — kedua kolom itu
// hanya dipakai untuk mengurutkan.
// Urutan pool dicoba berurutan sampai ada yang diterima PostgREST, karena kolom bukti
// ditambahkan manual ke tabel: worker harus tahan pada skema yang belum lengkap.
const POOL_ORDERS = [
  "tunnel_ok.desc.nullslast,tls_ok.desc.nullslast,ping.asc.nullslast",
  "tunnel_ok.desc.nullslast,ping.asc.nullslast",
  "ping.asc.nullslast",
];
const POOL_ORDER_MEMO_MS = 300000;
let poolOrderIndex = 0; // urutan terdalam yang terakhir diterima
let poolOrderAt = 0;
let fallbackUses = 0;

// Watchdog: kalau klien sudah mengirim data tapi target tidak membalas apa pun selama
// IDLE_CLOSE_SECONDS, koneksi ditutup rapi supaya klien cepat pindah (proxy "setengah mati"
// sebelumnya menggantung sampai CDN memutus). 0 = mati.
const IDLE_CLOSE_DEFAULT = 180;

// Path ajaib: "/rotate" (alias "/auto", "/pool", "/ALL") berarti worker MEMILIH SENDIRI proxy dari
// pool panel (dan daftar statis FALLBACK_PROXIES) untuk setiap koneksi baru, jadi konfigurasi
// klien tidak perlu memuat IP proxy dan tidak perlu diganti saat pool berubah. Failover, retry,
// dan hedge tetap berjalan di atas pilihan itu.
const ROTATE_PATHS = ["rotate", "auto", "pool", "all"];
const ROTATE_POOL_LIMIT = 6; // pilih acak dari N proxy teratas (sudah urut ping)

// Versi template: muncul di /health supaya panel bisa memastikan worker mana yang sudah
// memakai kode terbaru.
const WORKER_VERSION = "2026-11-14a";

// Log dibatasi per jenis pesan: hitungan tetap akurat (muncul di /health) tetapi Workers Logs
// tidak dibanjiri ketika pool proxy sedang banyak yang mati.
const LOG_MIN_INTERVAL_MS = 5000;
const logSeen = new Map();
const counters = {
  proxyFail: 0,
  fallbackUsed: 0,
  fallbackFail: 0,
  poolFail: 0,
  pipeError: 0,
  watchdog: 0,
  udpUnsupported: 0,
  dohFail: 0,
  muxError: 0,
  udpRelayUsed: 0,
  udpRelayFail: 0,
  proxyRetry: 0,
  rotateUsed: 0,
  rotateEmpty: 0,
  poolOrder: 0,
};
// Berapa baris log yang benar-benar ditulis per jenis (sisanya ditahan gate). Dibedakan dari
// `counters` supaya efektivitas gate bisa dipantau dari /health, bukan dari logs.
const logEmitted = {};

function logLimited(key, message) {
  counters[key] = (counters[key] || 0) + 1;
  const now = Date.now();
  if (now - (logSeen.get(key) || 0) < LOG_MIN_INTERVAL_MS) return;
  logSeen.set(key, now);
  logEmitted[key] = (logEmitted[key] || 0) + 1;
  console.log("[v" + WORKER_VERSION + "] " + key + " #" + counters[key] + " — " + message);
}

// Cache jawaban DoH per-isolate: setiap query DNS normalnya satu subrequest fetch, dan
// penjelajahan biasa butuh puluhan query untuk domain yang sama berulang kali. TTL dari
// jawaban dihormati (dijepit 30..600 detik), dan entri dibatasi agar memori tidak tumbuh.
const DNS_CACHE_TTL_MIN = 30;
const DNS_CACHE_TTL_MAX = 600;
const DNS_CACHE_MAX_ENTRIES = 256;
const DNS_NEGATIVE_TTL = 30; // NXDOMAIN/NODATA: di-cache singkat supaya tidak diulang terus
const dnsCache = new Map();

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);

      if ((request.headers.get("Upgrade") || "").toLowerCase() === "websocket") {
        const selector = parseSelector(url.pathname);
        if (selector) return await websocketHandler(request, selector, env);
      }

      if (url.pathname === "/health") {
        // Gating opsional: kalau env.HEALTH_TOKEN diisi, /health hanya menjawab dengan
        // ?token=<nilai> atau header x-health-token. Ini menutup hitungan internal (counters,
        // pool_cache, versi). Catatan: panel tidak mengirim token, jadi badge versi worker di
        // dasbor berhenti muncul kalau gating diaktifkan.
        const healthToken = String((env && env.HEALTH_TOKEN) || "");
        if (healthToken) {
          const given = url.searchParams.get("token") || request.headers.get("x-health-token") || "";
          if (given !== healthToken) {
            return new Response(JSON.stringify({ error: "unauthorized" }), {
              status: 401,
              headers: Object.assign({ "Content-Type": "application/json" }, CORS),
            });
          }
        }
        return new Response(
          JSON.stringify({
            ok: true,
            colo: request.cf?.colo,
            ts: Date.now(),
            // Ringkasan kondisi isolate: berguna untuk memantau dari panel tanpa logs.
            fallback_uses: fallbackUses,
            fallback_pool: String((env && env.FALLBACK_POOL) || "on") !== "off",
            dns_mode: dnsCacheMode(env),
            dns_cache: dnsCache.size,
            dns_hits: { memory: dnsMemoryHits, shared: dnsSharedHits, miss: dnsCacheMisses },
            proxy_memo: proxyProtocols.size,
            rotate_paths: ROTATE_PATHS,
            pool_cache: Array.from(poolCache.keys()),
            version: WORKER_VERSION,
            counters: counters,
            log_emitted: logEmitted,
          }),
          { headers: { ...CORS, "Content-Type": "application/json" } }
        );
      }

      if (url.pathname.startsWith("/myip")) {
        return new Response(JSON.stringify({
          ip: request.headers.get("cf-connecting-ip") || request.headers.get("x-real-ip"),
          colo: request.headers.get("cf-ray")?.split("-")[1],
          ...request.cf,
        }), { headers: CORS });
      }

      const target = (env && env.REVERSE_PRX_TARGET) || "example.com";
      const targetUrl = new URL(request.url);
      targetUrl.hostname = target;
      const modified = new Request(targetUrl, request);
      modified.headers.set("X-Forwarded-Host", request.headers.get("Host"));
      const response = await fetch(modified);
      const out = new Response(response.body, response);
      for (const [k, v] of Object.entries(CORS)) out.headers.set(k, v);
      return out;
    } catch (err) {
      return new Response("Error: " + err.message, { status: 500, headers: CORS });
    }
  },
};

async function websocketHandler(request, prx, env) {
  const pair = new WebSocketPair();
  const client = pair[0];
  const webSocket = pair[1];
  webSocket.accept();

  const state = {
    remote: null,
    remoteWriter: null,
    cancelled: false,
    headerBuf: null,
    versionBytes: null,
    udpPrefixed: null,
    udpBuf: new Uint8Array(0),
    responseHeaderSent: false,
    openedAt: Date.now(),
    lastRemoteData: 0,
    clientSent: false,
    idleTimer: null,
  };
  startIdleWatch(state, webSocket, env);
  // Basis URL untuk Cache API (lapisan cache DNS lintas-isolate) — memakai host sendiri
  // supaya kuncinya berada di zone ini.
  state.cacheBase = new URL(request.url).origin;
  state.batchBytes = Number((env && env.WS_BATCH_BYTES) || BATCH_BYTES_DEFAULT);
  state.batchMs = Number((env && env.WS_BATCH_MS) || BATCH_MS_DEFAULT);
  // Hangatkan daftar cadangan (tanpa filter negara) di latar belakang supaya failover tidak
  // ikut menunggu fetch tepat saat proxy utama sudah gagal.
  const warm = poolCache.get("all");
  if (!warm || Date.now() - warm.at > FALLBACK_TTL_MS) {
    poolFallbacks(env).catch(function () {});
  }
  // Early data: klien bisa menaruh paket pertama di header `sec-websocket-protocol` (gaya
  // Xray earlyDataHeaderName) atau di query `?ed=` berisi base64url. Nilai numerik kecil
  // (mis. ?ed=2048) hanya petunjuk ukuran, bukan data.
  const earlyData = earlyDataValue(request);

  const incoming = new ReadableStream({
    start(controller) {
      if (earlyData) {
        try {
          const bin = atob(earlyData.replace(/-/g, "+").replace(/_/g, "/"));
          const bytes = new Uint8Array(bin.length);
          for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
          queueMicrotask(() => {
            if (!state.cancelled) {
              try { controller.enqueue(bytes.buffer); } catch (e) {}
            }
          });
        } catch (e) {}
      }

      webSocket.addEventListener("message", function (e) {
        if (!state.cancelled) {
          try { controller.enqueue(e.data); } catch (err) {}
        }
      });
      webSocket.addEventListener("close", function () {
        stopIdleWatch(state);
        closeUdpRelay(state);
        if (!state.cancelled) {
          try { controller.close(); } catch (err) {}
        }
        safeClose(webSocket);
      });
      webSocket.addEventListener("error", function () {
        stopIdleWatch(state);
        closeUdpRelay(state);
        if (!state.cancelled) {
          try { controller.error(new Error("ws error")); } catch (err) {}
        }
        safeClose(webSocket);
      });
    },
    cancel() {
      state.cancelled = true;
      stopIdleWatch(state);
      closeUdpRelay(state);
      shutdownRemote(state, false);
    },
  });

  incoming
    .pipeTo(new WritableStream({
      async write(chunk) {
        await handleClientChunk(chunk, state, webSocket, prx, env);
      },
      close() {
        shutdownRemote(state, true);
      },
      abort() {
        shutdownRemote(state, false);
      },
    }))
    .catch(function () {
      shutdownRemote(state, false);
      safeClose(webSocket);
    });

  return new Response(null, { status: 101, webSocket: client });
}

async function handleClientChunk(chunk, state, webSocket, prx, env) {
  state.clientSent = true;
  // Sekali koneksi masuk mode mux, SEMUA potongan berikutnya adalah frame mux — jangan
  // di-parse ulang sebagai header VLESS (itu yang dulu langsung menutup koneksi).
  if (state.mux) {
    muxHandle(state, webSocket, prx, env, toBytes(chunk));
    return;
  }
  if (state.remote) {
    await writeToRemote(state, chunk);
    return;
  }

  let bytes = toBytes(chunk);
  if (state.headerBuf) {
    bytes = concatBytes(state.headerBuf, bytes);
    state.headerBuf = null;
  }

  // Byte pertama header VLESS selalu 0x00 (versi 0). Selain itu = trafik
  // non-VLESS, dilayani sebagai TCP mentah lewat proxy.
  if (bytes[0] !== 0) {
    await openRawTunnel(bytes, webSocket, state, prx);
    return;
  }

  const parsed = parseVlessHeader(bytes);

  // Header terpecah antar frame: tahan byte-nya, jangan dial apa pun dulu.
  if (parsed.need) {
    if (bytes.length > MAX_HEADER_BYTES) safeClose(webSocket);
    else state.headerBuf = bytes;
    return;
  }

  if (parsed.invalid) {
    safeClose(webSocket);
    return;
  }

  const header = parsed.header;

  if (!isUuidAllowed(header.uuidBytes, env)) {
    safeClose(webSocket);
    return;
  }

  if (header.isMux) {
    muxHandle(state, webSocket, prx, env, new Uint8Array(header.rawClientData));
    return;
  }

  if (header.isUDP) {
    state.versionBytes = header.version;
    if (header.portRemote !== 53) {
      // UDP non-DNS: diteruskan ke relay (env.RELAY_SERVER_UDP) kalau ada. Tanpa relay,
      // perilakunya tetap seperti sebelumnya: ditutup cepat dengan alasan yang jelas.
      if (await udpRelayEnsure(state, webSocket, env, header)) {
        for (const datagram of splitUdpDatagrams(state, new Uint8Array(header.rawClientData))) {
          udpRelaySend(state, datagram);
        }
        return;
      }
      logLimited("udpUnsupported", "port " + header.portRemote + " tanpa relay UDP");
      safeClose(webSocket);
      return;
    }
    // Beberapa query dalam satu frame dikerjakan paralel: balasan dikirim begitu siap dan
    // klien mencocokkan lewat txid, jadi urutannya tidak penting.
    const queries = takeDnsMessages(state, new Uint8Array(header.rawClientData));
    await Promise.all(queries.map((message) => handleDnsQuery(message, state, webSocket, env)));
    return;
  }

  // Cloudflare memblokir connect() ke port HTTP/HTTPS (80/443):
  //   "cannot connect to the specified address. It looks like you might be
  //    trying to connect to a HTTP-based service - consider using fetch"
  // Jadi SEMUA koneksi harus lewat proxy, tidak ada jalur direct.
  await tryViaProxy(header, webSocket, state, prx, env);
}

// VLESS UDP memakai framing [2B panjang BE][payload] per datagram (spesifikasi Xray),
// tetapi klien lain bisa mengirim pesan DNS polos. Mode ditentukan sekali per koneksi:
// coba framing berpanjang dulu; kalau hasilnya bukan pesan DNS, jatuh ke mode polos.
function takeDnsMessages(state, bytes) {
  state.udpBuf = concatBytes(state.udpBuf, bytes);
  const messages = [];

  if (state.udpPrefixed === false) {
    if (looksLikeDnsMessage(state.udpBuf)) messages.push(state.udpBuf);
    state.udpBuf = new Uint8Array(0);
    return messages;
  }

  if (state.udpPrefixed === null) {
    const parsed = parsePrefixedDatagrams(state.udpBuf);
    const usable = parsed.messages.filter(looksLikeDnsMessage);
    if (usable.length) {
      state.udpPrefixed = true;
      state.udpBuf = parsed.rest;
      return usable;
    }
    if (looksLikeDnsMessage(state.udpBuf)) {
      state.udpPrefixed = false;
      messages.push(state.udpBuf);
      state.udpBuf = new Uint8Array(0);
      return messages;
    }
    if (state.udpBuf.length > MAX_DNS_MESSAGE) state.udpBuf = new Uint8Array(0);
    return messages;
  }

  const parsed = parsePrefixedDatagrams(state.udpBuf);
  state.udpBuf = parsed.rest;
  return parsed.messages.filter(looksLikeDnsMessage);
}

function parsePrefixedDatagrams(buffer) {
  const messages = [];
  let offset = 0;
  while (buffer.length - offset >= 2) {
    const length = (buffer[offset] << 8) | buffer[offset + 1];
    if (length === 0 || length > MAX_DNS_MESSAGE) return { messages: [], rest: new Uint8Array(0) };
    if (buffer.length - offset < length + 2) break;
    messages.push(buffer.slice(offset + 2, offset + 2 + length));
    offset += 2 + length;
  }
  return { messages: messages, rest: buffer.slice(offset) };
}

function looksLikeDnsMessage(view) {
  if (view.length < 17 || view.length > MAX_DNS_MESSAGE) return false;
  if (((view[4] << 8) | view[5]) < 1) return false; // qdcount minimal 1
  let i = 12;
  while (i < view.length) {
    const labelLength = view[i];
    if (labelLength === 0) return i + 5 <= view.length;
    if (labelLength > 63) return false;
    i += labelLength + 1;
  }
  return false;
}

async function handleDnsQuery(message, state, webSocket, env) {
  if (message.length < 12 || message.length > MAX_DNS_MESSAGE) return;

  const key = dnsCacheKey(message);
  const mode = dnsCacheMode(env);
  if (key && mode !== "off") {
    if (mode !== "cache") {
      const cached = readDnsCache(key);
      if (cached) {
        dnsMemoryHits++;
        if (state.cancelled || webSocket.readyState !== WS_OPEN) return;
        sendVlessPayload(state, webSocket, withTxid(cached, message));
        return;
      }
    }
    if (mode !== "memory") {
      const shared = await readDnsCacheShared(state, key);
      if (shared) {
        dnsSharedHits++;
        // Promosikan ke cache memori supaya query berikutnya tidak menyentuh Cache API.
        storeDnsMemory(key, shared.answer, shared.ttl);
        if (state.cancelled || webSocket.readyState !== WS_OPEN) return;
        sendVlessPayload(state, webSocket, withTxid(shared.answer, message));
        return;
      }
    }
  }

  let answer;
  try {
    answer = await resolveDohCoalesced(key, message, env);
  } catch (err) {
    // Semua endpoint DoH gagal: balas SERVFAIL supaya klien tahu saat itu juga dan tidak
    // menunggu timeout-nya sendiri (sebelumnya balasan tidak dikirim sama sekali).
    logLimited("dohFail", String(err && err.message));
    answer = servfailResponse(message);
    if (!answer) return;
  }

  if (state.cancelled || webSocket.readyState !== WS_OPEN) return;
  // Query identik yang datang bersamaan berbagi satu jawaban DoH, jadi txid disesuaikan
  // dengan pertanyaan pemanggil sebelum dikirim.
  sendVlessPayload(state, webSocket, withTxid(answer, message));

  if (key && mode !== "off") {
    const ttl = storeDnsAnswer(key, answer);
    if (ttl && mode !== "memory") {
      // Tulis Cache API tidak perlu ditunggu klien.
      storeDnsCacheShared(state, key, answer, ttl).catch(function () {});
    }
  }
  dnsCacheMisses++;
}

// Query identik yang sedang jalan berbagi satu panggilan DoH — beberapa koneksi ke domain
// yang sama sering dibuka bersamaan, dan tiap panggilan DoH adalah satu subrequest fetch.
function resolveDohCoalesced(key, query, env) {
  if (!key) return resolveDoh(query, env);
  const pending = dnsInflight.get(key);
  if (pending) return pending;
  const promise = resolveDoh(query, env).finally(function () { dnsInflight.delete(key); });
  dnsInflight.set(key, promise);
  return promise;
}

function sendVlessPayload(state, webSocket, payload) {
  const withHeader = !state.responseHeaderSent;
  const version = withHeader ? (state.versionBytes || new Uint8Array([0, 0])) : null;
  const prefixLength = state.udpPrefixed ? 2 : 0;
  const out = new Uint8Array((version ? version.length : 0) + prefixLength + payload.length);

  let offset = 0;
  if (version) {
    state.responseHeaderSent = true;
    out.set(version, offset);
    offset += version.length;
  }
  if (prefixLength) {
    out[offset] = (payload.length >> 8) & 0xff;
    out[offset + 1] = payload.length & 0xff;
    offset += 2;
  }
  out.set(payload, offset);
  webSocket.send(out);
}

async function resolveDoh(query, env) {
  const endpoints = dohEndpoints(env);
  let lastError = null;
  for (const endpoint of endpoints) {
    try {
      return await fetchDoh(endpoint, query);
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError || new Error("DoH tidak tersedia");
}

async function fetchDoh(endpoint, query) {
  const response = await withTimeout(fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/dns-message", "Accept": "application/dns-message" },
    body: query,
  }), DOH_TIMEOUT);
  if (!response.ok) throw new Error("DoH HTTP " + response.status);
  const answer = new Uint8Array(await response.arrayBuffer());
  if (!answer.length) throw new Error("DoH kosong");
  if (answer.length > MAX_DNS_MESSAGE) throw new Error("DoH terlalu besar");
  return answer;
}

// Endpoint DoH yang dipakai: kalau operator menyetel env.DOH_ENDPOINT atau env.DOH_FALLBACK,
// HANYA itu yang dipakai (dipakai uji lokal dan supaya resolver bisa dipaksa). Tanpa env,
// pakai Cloudflare lalu Google sebagai cadangan.
function dohEndpoints(env) {
  const configured = [];
  if (env) {
    if (env.DOH_ENDPOINT) configured.push(String(env.DOH_ENDPOINT));
    if (env.DOH_FALLBACK) configured.push(String(env.DOH_FALLBACK));
  }
  if (configured.length) {
    return configured.filter(function (value, index, all) { return all.indexOf(value) === index; });
  }
  return [DOH_ENDPOINT, "https://dns.google/dns-query"];
}

// Kunci cache = nama + tipe + kelas pertanyaan (tanpa txid), huruf kecil dilekatkan supaya
// "Example.com" dan "example.com" berbagi entri.
function questionEnd(message) {
  let i = 12;
  while (i < message.length) {
    const labelLength = message[i];
    if (labelLength === 0) return i + 5 <= message.length ? i + 5 : -1;
    if (labelLength > 63) return -1;
    i += labelLength + 1;
  }
  return -1;
}

function dnsCacheKey(message) {
  const end = questionEnd(message);
  if (end < 12) return null;
  let key = "";
  for (let i = 12; i < end; i++) {
    const byte = message[i];
    key += String.fromCharCode(byte >= 65 && byte <= 90 ? byte + 32 : byte);
  }
  return key;
}

let dnsMemoryHits = 0;
let dnsSharedHits = 0;
let dnsCacheMisses = 0;

// Mode cache DNS: "both" (Map isolate + Cache API, bawaan), "memory" (hanya Map),
// "cache" (hanya Cache API), "off".
function dnsCacheMode(env) {
  const mode = String((env && env.DNS_CACHE_MODE) || "both").toLowerCase();
  return mode === "off" || mode === "memory" || mode === "cache" ? mode : "both";
}

function readDnsCache(key) {
  const entry = dnsCache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expires) {
    dnsCache.delete(key);
    return null;
  }
  return entry.answer;
}

function storeDnsMemory(key, answer, ttl) {
  if (dnsCache.size >= DNS_CACHE_MAX_ENTRIES) {
    const oldest = dnsCache.keys().next();
    if (!oldest.done) dnsCache.delete(oldest.value);
  }
  dnsCache.set(key, { answer: answer, expires: Date.now() + ttl * 1000 });
}

// TTL cache: jawaban sukses memakai TTL catatan (dijepit 30..600 detik), jawaban negatif
// (NXDOMAIN/NODATA) dipakai singkat, dan SERVFAIL/terpotong tidak di-cache sama sekali.
function dnsCacheTtl(answer) {
  if (answer.length < 12) return 0;
  if ((answer[2] & 0x02) !== 0) return 0;
  const rcode = answer[3] & 0x0f;
  if (rcode === 2) return 0;
  const ancount = (answer[6] << 8) | answer[7];
  if (rcode !== 0 || ancount < 1) return DNS_NEGATIVE_TTL;
  return Math.min(Math.max(minAnswerTtl(answer), DNS_CACHE_TTL_MIN), DNS_CACHE_TTL_MAX);
}

function storeDnsAnswer(key, answer) {
  const ttl = dnsCacheTtl(answer);
  if (!ttl) return 0;
  storeDnsMemory(key, answer, ttl);
  return ttl;
}

// --- Cache API: lapisan kedua supaya cache bertahan saat isolate didaur ulang --------------
function dnsCacheRequest(state, key) {
  return new Request(state.cacheBase + "/__dnscache__/" + encodeURIComponent(key), { method: "GET" });
}

async function readDnsCacheShared(state, key) {
  try {
    const hit = await caches.default.match(dnsCacheRequest(state, key));
    if (!hit) return null;
    const age = /max-age=(\d+)/.exec(hit.headers.get("Cache-Control") || "");
    const ttl = age ? Number(age[1]) : DNS_CACHE_TTL_MIN;
    return { answer: new Uint8Array(await hit.arrayBuffer()), ttl: Math.max(ttl, DNS_CACHE_TTL_MIN) };
  } catch (err) {
    return null;
  }
}

async function storeDnsCacheShared(state, key, answer, ttl) {
  try {
    await caches.default.put(dnsCacheRequest(state, key), new Response(answer, {
      headers: { "Cache-Control": "max-age=" + ttl, "Content-Type": "application/octet-stream" },
    }));
  } catch (err) {
    // Cache API bisa menolak (kuota/policy); cache memori tetap jalan.
  }
}

// TTL terkecil di bagian answer; bagian yang tidak terbaca diabaikan (pakai 60 detik).
function minAnswerTtl(answer) {
  const count = (answer[6] << 8) | answer[7];
  let i = questionEnd(answer);
  if (i < 12) return 60;
  let ttl = 0;
  for (let n = 0; n < count; n++) {
    if (i >= answer.length) break;
    const first = answer[i];
    if (first === 0) {
      i += 1;
    } else if ((first & 0xc0) === 0xc0) {
      i += 2;
    } else {
      while (i < answer.length && answer[i] !== 0) i += answer[i] + 1;
      i += 1;
    }
    if (i + 10 > answer.length) break;
    const recordTtl = ((answer[i + 4] << 24) | (answer[i + 5] << 16) | (answer[i + 6] << 8) | answer[i + 7]) >>> 0;
    const rdLength = (answer[i + 8] << 8) | answer[i + 9];
    if (!ttl || recordTtl < ttl) ttl = recordTtl;
    i += 10 + rdLength;
  }
  return ttl || 60;
}

// Jawaban cache dibuat ulang dengan txid pertanyaan baru (klien mencocokkan lewat txid).
// Kalau txid-nya sama, array yang ada dipakai apa adanya supaya tidak ada salinan.
function withTxid(answer, query) {
  if (answer.length < 2 || query.length < 2) return answer;
  if (answer[0] === query[0] && answer[1] === query[1]) return answer;
  const out = new Uint8Array(answer);
  out[0] = query[0];
  out[1] = query[1];
  return out;
}

// SERVFAIL minimal (pertanyaan dipertahankan) supaya klien gagal cepat.
function servfailResponse(query) {
  const end = questionEnd(query);
  if (end < 12) return null;
  const out = new Uint8Array(end);
  out.set(query.subarray(0, end), 0);
  out[2] = (query[2] | 0x80) & 0xff;
  out[3] = (query[3] & 0xf0) | 0x02;
  out[6] = 0;
  out[7] = 0;
  out[8] = 0;
  out[9] = 0;
  out[10] = 0;
  out[11] = 0;
  return out;
}

function sleepMs(ms) {
  return new Promise(function (resolve) { setTimeout(resolve, ms); });
}

function withTimeout(promise, ms) {
  return new Promise(function (resolve, reject) {
    const timer = setTimeout(function () { reject(new Error("timeout " + ms + "ms")); }, ms);
    promise.then(function (value) {
      clearTimeout(timer);
      resolve(value);
    }, function (err) {
      clearTimeout(timer);
      reject(err);
    });
  });
}

// Early data bisa datang dari header `sec-websocket-protocol` (gaya Xray) atau query `?ed=`.
// Nilai yang seluruhnya angka (mis. ?ed=2048) adalah petunjuk ukuran, bukan data.
function earlyDataValue(request) {
  const header = request.headers.get("sec-websocket-protocol");
  if (header) return header;
  let raw = "";
  try {
    raw = new URL(request.url).searchParams.get("ed") || "";
  } catch (err) {
    return "";
  }
  if (!raw || /^\d+$/.test(raw)) return "";
  return raw;
}

// Selector dari path kedua URL:
//   /<ip>-<port> atau /<ip>:<port>   -> proxy itu saja
//   /ALL, /ROTATE, /AUTO, /POOL      -> pilih acak dari beberapa proxy teratas di pool
//   /ID, /SG, /ID,SG, /US-ID         -> hanya negara itu (kode 2 huruf), pilih acak dari teratas
// Alamat IPv6 aman karena pemisah port dibaca dari kanan pada splitProxy.
function parseSelector(rawPath) {
  const raw = String(rawPath).replace(/^\/+/, "").trim();
  if (!raw || raw.indexOf("/") !== -1) return null;

  const upper = raw.toUpperCase();
  if (ROTATE_PATHS.indexOf(upper.toLowerCase()) !== -1) return { rotate: true, countries: [] };
  if (/^[A-Z]{2}([,-][A-Z]{2})*$/.test(upper)) {
    return { rotate: true, countries: upper.split(/[,-]/) };
  }
  const proxy = splitProxy(raw);
  if (proxy) return proxy;
  return null;
}

// Path dari klien: "/<proxy-host>-<port>" atau "/<proxy-host>:<port>". Pemisah port dibaca
// dari kanan, jadi alamat IPv6 (yang memuat ":") juga terbaca benar.
function splitProxy(raw) {
  const m = /^(.*?)[:-](\d+)$/.exec(String(raw));
  if (!m || !m[1]) return null;
  const port = Number(m[2]);
  if (!port || port < 1 || port > 65535) return null;
  return { host: m[1], port: port };
}

function parseIpv4(host) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(host));
  if (!m) return null;
  const out = new Uint8Array(4);
  for (let i = 1; i <= 4; i++) {
    const value = Number(m[i]);
    if (value > 255) return null;
    out[i - 1] = value;
  }
  return out;
}

// IPv6 literal -> 16 byte; mendukung "::" dan bentuk IPv4 di ujung (mis. ::ffff:1.2.3.4).
function parseIpv6(host) {
  let text = String(host).trim();
  if (text.startsWith("[") && text.endsWith("]")) text = text.slice(1, -1);
  if (text.indexOf(":") === -1) return null;

  const halves = text.split("::");
  if (halves.length > 2) return null;

  const toGroups = function (segment) {
    const out = [];
    if (!segment) return out;
    for (const part of segment.split(":")) {
      if (part === "") return null;
      if (part.indexOf(".") !== -1) {
        const v4 = parseIpv4(part);
        if (!v4) return null;
        out.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
        continue;
      }
      if (!/^[0-9a-fA-F]{1,4}$/.test(part)) return null;
      out.push(parseInt(part, 16));
    }
    return out;
  };

  const head = toGroups(halves[0]);
  if (!head) return null;
  let groups = head;
  if (halves.length === 2) {
    const tail = toGroups(halves[1]);
    if (!tail) return null;
    const fill = 8 - head.length - tail.length;
    if (fill < 1) return null;
    groups = head.concat(new Array(fill).fill(0), tail);
  }
  if (groups.length !== 8) return null;

  const out = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    out[i * 2] = (groups[i] >> 8) & 0xff;
    out[i * 2 + 1] = groups[i] & 0xff;
  }
  return out;
}

// IPv6 literal ditulis dalam kurung siku pada request line HTTP (RFC 7230) supaya proxy
// tidak salah memotong host:port.
function targetAuthority(host, port) {
  const text = String(host);
  const bracketed = text.indexOf(":") !== -1 && text[0] !== "[" ? "[" + text + "]" : text;
  return bracketed + ":" + port;
}

// Permintaan CONNECT SOCKS5: tujuan berupa IP numerik dikirim sebagai ATYP 1 (IPv4) atau 4
// (IPv6), bukan sebagai domain — proxy tidak perlu resolusi sendiri (lebih cepat, dan
// literal IP yang dikirim sebagai domain ditolak sebagian proxy).
function socks5Request(host, port) {
  const ipv4 = parseIpv4(host);
  if (ipv4) {
    const req = new Uint8Array(10);
    req.set([0x05, 0x01, 0x00, 0x01], 0);
    req.set(ipv4, 4);
    req[8] = (port >> 8) & 0xff;
    req[9] = port & 0xff;
    return req;
  }

  const ipv6 = parseIpv6(host);
  if (ipv6) {
    const req = new Uint8Array(22);
    req.set([0x05, 0x01, 0x00, 0x04], 0);
    req.set(ipv6, 4);
    req[20] = (port >> 8) & 0xff;
    req[21] = port & 0xff;
    return req;
  }

  const hostBytes = new TextEncoder().encode(String(host));
  const req = new Uint8Array(5 + hostBytes.length + 2);
  req.set([0x05, 0x01, 0x00, 0x03, hostBytes.length], 0);
  req.set(hostBytes, 5);
  req[5 + hostBytes.length] = (port >> 8) & 0xff;
  req[6 + hostBytes.length] = port & 0xff;
  return req;
}

async function openRawTunnel(bytes, webSocket, state, prx) {
  const sock = connect({
    hostname: prx.host,
    port: prx.port,
    secureTransport: "off",
  });
  const w = sock.writable.getWriter();
  await w.write(bytes);
  w.releaseLock();
  state.remote = { readable: sock.readable, writable: sock.writable, close: function () { sock.close(); } };
  pipeRemoteToWs(state.remote, webSocket, state);
}

async function tryViaProxy(header, webSocket, state, prx, env) {
  // Mode rotate: pilih proxy dari pool (dan daftar statis) untuk koneksi ini.
  if (prx.rotate) {
    const chosen = await pickRotateProxy(env, prx.countries);
    if (!chosen) {
      counters.rotateEmpty++;
      logLimited("rotateEmpty", "tidak ada kandidat proxy untuk selector " + (prx.countries && prx.countries.length ? prx.countries.join(",") : "pool"));
      safeClose(webSocket);
      return;
    }
    counters.rotateUsed++;
    prx = chosen;
  }
  // Proxy utama dicoba penuh (timeout normal) supaya proxy lambat tapi sehat tetap menang.
  // Kalau belum selesai setelah HEDGE_DELAY_MS, jalur cadangan mulai berjalan paralel.
  let fallbackPromise = null;
  const startFallbacks = function () {
    if (!fallbackPromise) {
      fallbackPromise = runFallbacks(header, webSocket, state, env, prx).catch(function () { return false; });
    }
    return fallbackPromise;
  };

  const hedge = setTimeout(startFallbacks, HEDGE_DELAY_MS);
  try {
    await establishTunnel(prx, header, webSocket, state, PROXY_HANDSHAKE_TIMEOUT);
    return;
  } catch (err) {
    logLimited("proxyFail", err.message + " (" + prx.host + ":" + prx.port + ")");
    // Satu percobaan ulang ke proxy yang sama: handshake yang gagal karena paket hilang sering
    // lolos di percobaan kedua, dan itu lebih murah daripada pindah ke cadangan. Dilewati kalau
    // jalur cadangan sudah berjalan atau tunnel sudah terpasang.
    if (!fallbackPromise && !state.remote) {
      await sleepMs(180);
      try {
        await establishTunnel(prx, header, webSocket, state, PROXY_HANDSHAKE_TIMEOUT);
        counters.proxyRetry++;
        return;
      } catch (retryErr) {
        logLimited("proxyFail", "ulang: " + (retryErr && retryErr.message));
      }
    }
  } finally {
    clearTimeout(hedge);
  }

  if (await startFallbacks()) return;
  safeClose(webSocket);
}

// Membuka tunnel lewat satu proxy lalu menyambungkannya ke WebSocket. Dipakai proxy utama
// maupun cadangan supaya jalurnya identik (termasuk header balasan VLESS yang dikirim awal).
// Tunnel pertama yang selesai "mengklaim" koneksi; percobaan lain menutup soketnya sendiri —
// perlu karena jalur cadangan bisa berjalan paralel dengan proxy utama.
async function establishTunnel(proxy, header, webSocket, state, timeoutMs) {
  const tunnel = await openProxyTunnel(
    proxy.host, proxy.port, header.addressRemote, header.portRemote, timeoutMs || PROXY_HANDSHAKE_TIMEOUT
  );
  if (state.remote) {
    try { tunnel.close(); } catch (e) {}
    throw new Error("tunnel lain sudah aktif");
  }
  state.remote = tunnel;

  const w = tunnel.writable.getWriter();
  await w.write(new Uint8Array(header.rawClientData));
  w.releaseLock();
  // Header balasan VLESS (2 byte) dikirim begitu tunnel siap, bukan menunggu byte pertama
  // dari target: target yang lama diam tidak lagi membuat klien menunggu tanpa kabar.
  if (webSocket.readyState === WS_OPEN) webSocket.send(header.version);
  pipeRemoteToWs(tunnel, webSocket, state);
}

// --- failover proxy ----------------------------------------------------------------
// Kalau proxy utama gagal (atau terlalu lama), worker mencoba cadangan: env.FALLBACK_PROXIES
// lebih dulu, lalu puncak tabel proxy_pool panel. Ini bukan rotasi (proxy utama tetap dipakai
// selama sehat); akibatnya IP keluar bisa berbeda dari proxy yang tertulis di path klien.
async function runFallbacks(header, webSocket, state, env, prx) {
  let candidates = [];
  try {
    candidates = await fallbackCandidates(prx, env);
  } catch (err) {
    logLimited("poolFail", String(err && err.message));
    return false;
  }
  for (const candidate of candidates) {
    if (state.remote) return true; // proxy utama ternyata menang duluan
    try {
      await establishTunnel(candidate, header, webSocket, state, PROXY_HANDSHAKE_TIMEOUT);
      fallbackUses++;
      logLimited("fallbackUsed", candidate.host + ":" + candidate.port);
      return true;
    } catch (err) {
      logLimited("fallbackFail", candidate.host + ":" + candidate.port + " — " + err.message);
    }
  }
  return false;
}

// Proxy untuk mode rotate: gabungan pool panel + daftar statis, ambil N teratas lalu pilih acak
// (acak, bukan round-robin, supaya beban tersebar tanpa butuh state bersama antar isolate).
async function pickRotateProxy(env, countries) {
  const candidates = [];
  try {
    for (const proxy of await poolProxies(env, countries || [])) candidates.push(proxy);
  } catch (err) {
    logLimited("poolFail", String(err && err.message));
  }
  // Daftar statis (tanpa label negara) hanya dipakai kalau klien tidak memfilter negara:
  // untuk /ID, memakai proxy statis berarti keluar dari negara lain tanpa bilang.
  if (!(countries && countries.length)) {
    for (const proxy of staticFallbackProxies(env)) candidates.push(proxy);
  }

  const seen = new Set();
  const unique = [];
  for (const proxy of candidates) {
    const key = proxy.host + ":" + proxy.port;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(proxy);
    if (unique.length >= ROTATE_POOL_LIMIT) break;
  }
  if (!unique.length) return null;
  // Tercepat dulu: urutan kandidat datang dari server (tunnel_ok edge, lalu tls_ok host
  // scanner, lalu ping), jadi kandidat pertama memang yang paling layak. Konsekuensinya beban
  // menumpuk di proxy teratas; itu diterima karena yang dicari adalah koneksi paling cepat, dan
  // kalau proxy itu ternyata gagal, jalur cadangan (`fallbackCandidates`: hedge + FALLBACK_MAX)
  // tetap mencoba kandidat berikutnya dari daftar yang sama.
  return unique[0];
}

function staticFallbackProxies(env) {
  const raw = env && env.FALLBACK_PROXIES;
  if (!raw) return [];
  const out = [];
  for (const part of String(raw).split(",")) {
    const proxy = splitProxy(part.trim());
    if (proxy) out.push(proxy);
  }
  return out;
}

// Cadangan dinamis dari tabel proxy_pool panel. Anon key memang publik di repo ini (sama
// seperti load-balancer.js). Hasil di-cache singkat per isolate; kalau fetch sedang jalan,
// pemanggil MENUNGGU fetch itu (bukan menerima daftar kosong) — tanpa itu koneksi pertama
// yang gagal akan menutup sebelum daftar cadangan sempat tiba.
// Proxy dari pool panel untuk satu filter negara (kosong = semua). Cache per filter.
// Pemanggil MENUNGGU fetch yang sedang jalan — tanpa itu koneksi pertama yang gagal menutup
// sebelum daftar cadangan tiba.
async function poolProxies(env, countries) {
  if (String((env && env.FALLBACK_POOL) || "") === "off") return [];
  const key = countries && countries.length ? countries.join(",") : "all";
  const cached = poolCache.get(key);
  if (cached && Date.now() - cached.at < FALLBACK_TTL_MS && cached.list.length) return cached.list;

  const running = poolFetching.get(key);
  if (running) return await running.catch(function () { return (cached && cached.list) || []; });

  const task = fetchPoolProxies(env, countries).then(function (list) {
    if (poolCache.size >= POOL_CACHE_MAX) {
      const oldest = poolCache.keys().next();
      if (!oldest.done) poolCache.delete(oldest.value);
    }
    poolCache.set(key, { at: Date.now(), list: list });
    return list;
  }).finally(function () { poolFetching.delete(key); });
  poolFetching.set(key, task);
  try {
    return await task;
  } catch (err) {
    return (cached && cached.list) || [];
  }
}

// Jalur cadangan memakai daftar tanpa filter negara.
async function poolFallbacks(env) {
  return await poolProxies(env, []);
}

// Coba urutan bukti edge dulu, kecuali kolomnya sudah terbukti (masih dalam masa ingat) tidak ada.

async function fetchPoolProxies(env, countries) {
  try {
    const fresh = new Date(Date.now() - 6 * 3600 * 1000).toISOString();
    const base = (env && env.FALLBACK_POOL_URL) || SUPABASE_URL;
    const table = (env && env.FALLBACK_TABLE) || "proxy_pool";
    const head = String(base).replace(/\/$/, "") + "/rest/v1/" + table +
      "?select=ip,port&is_active=eq.true&last_checked=gt." + encodeURIComponent(fresh) +
      (countries && countries.length ? "&country=in.(" + countries.join(",") + ")" : "");
    const get = function (order) {
      return withTimeout(fetch(head + "&order=" + order + "&limit=16", {
        headers: { apikey: SUPABASE_ANON_KEY, Authorization: "Bearer " + SUPABASE_ANON_KEY },
      }), FALLBACK_FETCH_TIMEOUT);
    };

    // Mulai dari urutan terdalam yang terakhir diterima. Kalau ingatan sudah lama, coba lagi
    // dari atas: skema bisa saja sudah dilengkapi (kolom baru ditambahkan manual).
    // `counters.poolOrder` naik sekali per urutan yang ditolak (gate log) + sekali saat akhirnya
    // turun ke urutan yang lebih tua, jadi /health memperlihatkan berapa kali isolate ini
    // membayar percobaan urutan.
    let start = poolOrderAt && Date.now() - poolOrderAt <= POOL_ORDER_MEMO_MS ? poolOrderIndex : 0;
    let res = null;
    let used = start;
    for (let i = start; i < POOL_ORDERS.length; i++) {
      res = await get(POOL_ORDERS[i]);
      if (res.ok) { used = i; break; }
      logLimited("poolOrder", "HTTP " + res.status);
    }
    if (!res || !res.ok) throw new Error("HTTP " + (res ? res.status : "?"));
    if (used !== poolOrderIndex || !poolOrderAt) {
      if (used > start) counters.poolOrder = (counters.poolOrder || 0) + 1;
      poolOrderIndex = used;
      poolOrderAt = Date.now();
    }
    const rows = await res.json();
    return rows
      .map(function (row) { return { host: row && row.ip, port: Number(row && row.port) }; })
      .filter(function (proxy) { return proxy.host && proxy.port; });
  } catch (err) {
    logLimited("poolFail", String(err && err.message));
    return [];
  }
}

async function fallbackCandidates(prx, env) {
  const seen = new Set([prx.host + ":" + prx.port]);
  const out = [];
  const push = function (proxy) {
    const key = proxy.host + ":" + proxy.port;
    if (seen.has(key)) return;
    seen.add(key);
    out.push(proxy);
  };

  // Selector negara TIDAK boleh diselamatkan proxy negara lain: kalau klien minta /ID, keluar
  // dari NL diam-diam lebih buruk daripada gagal (IP keluar adalah alasan filter itu dipakai).
  // Jadi daftar statis (tanpa label negara) dan pool tanpa filter hanya dipakai saat tidak ada
  // filter negara; dengan filter, kandidat cadangan ikut difilter.
  const countries = (prx && prx.countries) || [];
  if (!countries.length) {
    for (const proxy of staticFallbackProxies(env)) push(proxy);
  }
  if (out.length < FALLBACK_MAX) {
    for (const proxy of await poolProxies(env, countries)) push(proxy);
  }
  return out.slice(0, FALLBACK_MAX);
}

async function openProxyTunnel(proxyHost, proxyPort, targetHost, targetPort, timeoutMs) {
  const known = proxyProtocols.get(proxyHost + ":" + proxyPort);
  if (known === "http") {
    return await orderedProxyTunnel("http", proxyHost, proxyPort, targetHost, targetPort, timeoutMs);
  }
  if (known === "socks5") {
    return await orderedProxyTunnel("socks5", proxyHost, proxyPort, targetHost, targetPort, timeoutMs);
  }
  return await raceProxyProtocols(proxyHost, proxyPort, targetHost, targetPort, timeoutMs);
}

// Protokol yang sudah diketahui: dicoba berurutan (yang diingat lebih dulu).
async function orderedProxyTunnel(first, proxyHost, proxyPort, targetHost, targetPort, timeoutMs) {
  const errors = [];
  const order = first === "http" ? ["http", "socks5"] : ["socks5", "http"];
  for (const protocol of order) {
    try {
      const tunnel = protocol === "socks5"
        ? await socks5Tunnel(proxyHost, proxyPort, targetHost, targetPort, timeoutMs)
        : await httpConnectTunnel(proxyHost, proxyPort, targetHost, targetPort, timeoutMs);
      rememberProxyProtocol(proxyHost, proxyPort, protocol);
      return tunnel;
    } catch (e) {
      errors.push(protocol + ": " + e.message);
    }
  }
  throw new Error(errors.join(" | "));
}

// Proxy yang protokolnya belum diketahui: SOCKS5 dan HTTP CONNECT dicoba BERSAMAAN, yang
// pertama berhasil dipakai dan soket yang kalah ditutup. Hanya terjadi sekali per proxy per
// isolate (setelah itu memo `proxyProtocols` yang menentukan), jadi proxy HTTP-only tidak
// perlu membayar penuh probe SOCKS5 sementara proxy SOCKS5 tidak dirugikan.
async function raceProxyProtocols(proxyHost, proxyPort, targetHost, targetPort, timeoutMs) {
  const race = { sockets: new Set() };
  const errors = [];
  const guard = function (promise, label) {
    return promise.then(function (tunnel) {
      return { tunnel: tunnel, protocol: label };
    }, function (err) {
      errors.push(label + ": " + (err && err.message));
      throw err;
    });
  };

  let winner;
  try {
    winner = await Promise.any([
      guard(socks5Tunnel(proxyHost, proxyPort, targetHost, targetPort, timeoutMs, race), "socks5"),
      guard(httpConnectTunnel(proxyHost, proxyPort, targetHost, targetPort, timeoutMs, race), "http"),
    ]);
  } catch (err) {
    throw new Error(errors.join(" | ") || "socks5/http gagal");
  }

  rememberProxyProtocol(proxyHost, proxyPort, winner.protocol);
  for (const sock of race.sockets) {
    if (sock === winner.tunnel.socket) continue;
    try { sock.close(); } catch (e) {}
  }
  return winner.tunnel;
}

function rememberProxyProtocol(host, port, protocol) {
  const key = host + ":" + port;
  if (proxyProtocols.size >= PROXY_PROTOCOL_MAX_ENTRIES) {
    const oldest = proxyProtocols.keys().next();
    if (!oldest.done) proxyProtocols.delete(oldest.value);
  }
  proxyProtocols.set(key, protocol);
}

async function socks5Tunnel(proxyHost, proxyPort, targetHost, targetPort, timeoutMs, race) {
  const sock = connect({ hostname: proxyHost, port: proxyPort, secureTransport: "off" });
  if (race) race.sockets.add(sock);
  const writer = sock.writable.getWriter();
  const reader = sock.readable.getReader();

  try {
    await writer.write(new Uint8Array([0x05, 0x01, 0x00]));
    const g = await readBytes(reader, 2, SOCKS5_PROBE_TIMEOUT, "socks5-greeting");
    if (g.bytes[0] !== 0x05) throw new Error("bukan SOCKS5");
    if (g.bytes[1] !== 0x00) throw new Error("butuh auth");

    await writer.write(socks5Request(targetHost, targetPort));

    const h = await readBytes(reader, 4, timeoutMs, "socks5-reply");
    if (h.bytes[1] !== 0x00) throw new Error("CONNECT ditolak " + h.bytes[1]);

    let pending = h.leftover;
    const atyp = h.bytes[3];
    let need;
    if (atyp === 0x01) {
      need = 6;
    } else if (atyp === 0x04) {
      need = 18;
    } else if (atyp === 0x03) {
      let len;
      if (pending && pending.length >= 1) {
        len = pending[0];
        pending = pending.length > 1 ? pending.slice(1) : null;
      } else {
        const lb = await readBytes(reader, 1, timeoutMs, "socks5-atyp");
        len = lb.bytes[0];
        pending = lb.leftover;
      }
      need = len + 2;
    } else {
      throw new Error("ATYP " + atyp);
    }

    if (pending && pending.length) {
      if (pending.length >= need) {
        pending = pending.length > need ? pending.slice(need) : null;
        need = 0;
      } else {
        need -= pending.length;
        pending = null;
      }
    }
    if (need > 0) {
      const rest = await readBytes(reader, need, timeoutMs, "socks5-bind");
      pending = rest.leftover;
    }

    return rebuildTunnel(sock, reader, pending, writer);
  } catch (err) {
    try { reader.cancel(); } catch (e) {}
    try { writer.releaseLock(); } catch (e) {}
    try { sock.close(); } catch (e) {}
    throw err;
  }
}

async function httpConnectTunnel(proxyHost, proxyPort, targetHost, targetPort, timeoutMs, race) {
  const sock = connect({ hostname: proxyHost, port: proxyPort, secureTransport: "off" });
  if (race) race.sockets.add(sock);
  const writer = sock.writable.getWriter();
  const reader = sock.readable.getReader();

  try {
    const authority = targetAuthority(targetHost, targetPort);
    const req = "CONNECT " + authority + " HTTP/1.1\r\n" +
      "Host: " + authority + "\r\n" +
      "User-Agent: Mozilla/5.0\r\n\r\n";
    await writer.write(new TextEncoder().encode(req));

    const r = await readUntil(reader, "\r\n\r\n", timeoutMs, 8192, "http-connect");
    const line = r.head.split("\r\n")[0] || "";
    const m = line.match(/^HTTP\/1\.[01]\s+(\d{3})/);
    if (!m) throw new Error("bukan HTTP proxy");
    const code = Number(m[1]);
    if (code !== 200) throw new Error("CONNECT ditolak " + code);

    return rebuildTunnel(sock, reader, r.rest, writer);
  } catch (err) {
    try { reader.cancel(); } catch (e) {}
    try { writer.releaseLock(); } catch (e) {}
    try { sock.close(); } catch (e) {}
    throw err;
  }
}

function rebuildTunnel(sock, reader, leftover, writer) {
  const writable = new WritableStream({
    async write(chunk) {
      await writer.write(chunk);
    },
    close() {
      try { writer.close(); } catch (e) {}
      try { sock.close(); } catch (e) {}
    },
    abort() {
      try { sock.close(); } catch (e) {}
    },
  });

  const readable = new ReadableStream({
    async start(controller) {
      if (leftover && leftover.length) {
        try { controller.enqueue(leftover); } catch (e) {}
      }
      try {
        for (;;) {
          const r = await reader.read();
          if (r.done) break;
          if (r.value && r.value.length) controller.enqueue(r.value);
        }
        try { controller.close(); } catch (e) {}
      } catch (err) {
        try { controller.error(err); } catch (e) {}
      }
    },
    cancel() {
      try { reader.cancel(); } catch (e) {}
      try { sock.close(); } catch (e) {}
    },
  });

  return { readable: readable, writable: writable, close: function () { sock.close(); }, socket: sock };
}

// Satu pembacaan dengan batas waktu; timernya selalu dibersihkan supaya handshake proxy
// (yang melakukan beberapa pembacaan) tidak menumpuk timer yang menggantung.
async function readWithTimeout(reader, ms, label) {
  let timer = null;
  try {
    return await Promise.race([
      reader.read(),
      new Promise(function (_, reject) {
        timer = setTimeout(function () { reject(new Error(label + ": timeout")); }, ms);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function readBytes(reader, n, timeoutMs, label) {
  const chunks = [];
  let total = 0;
  const deadline = Date.now() + timeoutMs;

  while (total < n) {
    const remain = deadline - Date.now();
    if (remain <= 0) throw new Error(label + ": timeout");

    const res = await readWithTimeout(reader, remain, label);
    if (res.done) throw new Error(label + ": closed");
    if (!res.value || !res.value.length) continue;
    chunks.push(res.value);
    total += res.value.length;
  }

  const all = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    all.set(c, off);
    off += c.length;
  }

  if (total > n) return { bytes: all.slice(0, n), leftover: all.slice(n) };
  return { bytes: all, leftover: null };
}

async function readUntil(reader, needle, timeoutMs, maxBytes, label) {
  const needleBytes = new TextEncoder().encode(needle);
  const deadline = Date.now() + timeoutMs;
  let buf = new Uint8Array(0);

  for (;;) {
    const idx = indexOfBytes(buf, needleBytes);
    if (idx !== -1) {
      const cut = idx + needleBytes.length;
      return {
        head: new TextDecoder().decode(buf.slice(0, cut)),
        rest: buf.length > cut ? buf.slice(cut) : null,
      };
    }
    if (buf.length > maxBytes) throw new Error(label + ": header terlalu besar");

    const remain = deadline - Date.now();
    if (remain <= 0) throw new Error(label + ": timeout");

    const res = await readWithTimeout(reader, remain, label);
    if (res.done) throw new Error(label + ": closed");
    if (!res.value || !res.value.length) continue;

    const merged = new Uint8Array(buf.length + res.value.length);
    merged.set(buf, 0);
    merged.set(res.value, buf.length);
    buf = merged;
  }
}

function indexOfBytes(haystack, needle) {
  const limit = haystack.length - needle.length;
  for (let i = 0; i <= limit; i++) {
    let match = true;
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) { match = false; break; }
    }
    if (match) return i;
  }
  return -1;
}

function parseVlessHeader(view) {
  if (view.length < 19) return { need: 19 };

  const version = view[0];
  const optLength = view[17];
  const cmdIndex = 18 + optLength;
  if (view.length < cmdIndex + 1) return { need: cmdIndex + 1 };

  const cmd = view[cmdIndex];
  if (cmd !== 1 && cmd !== 2 && cmd !== 3) return { invalid: "cmd " + cmd };

  // cmd=3 = Mux (mux.cool): tidak ada port/atyp/alamat di header VLESS; sisanya adalah frame
  // mux. Ini penanda yang dipakai Xray, jadi tidak perlu tebak-tebakan.
  if (cmd === 3) {
    return {
      header: {
        uuidBytes: view.subarray(1, 17),
        isMux: true,
        isUDP: false,
        rawClientData: view.slice(cmdIndex + 1),
        version: new Uint8Array([version, 0]),
      },
    };
  }

  const portIndex = cmdIndex + 1;
  const atypIndex = portIndex + 2;
  if (view.length < atypIndex + 1) return { need: atypIndex + 1 };

  const portRemote = (view[portIndex] << 8) | view[portIndex + 1];
  const atyp = view[atypIndex];
  let addressLength;
  let addressRemote = "";

  if (atyp === 1) {
    addressLength = 4;
    if (view.length >= atypIndex + 5) {
      addressRemote = [view[atypIndex + 1], view[atypIndex + 2], view[atypIndex + 3], view[atypIndex + 4]].join(".");
    }
  } else if (atyp === 3) {
    addressLength = 16;
    if (view.length >= atypIndex + 17) {
      const parts = [];
      for (let k = 0; k < 8; k++) {
        parts.push(((view[atypIndex + 1 + k * 2] << 8) | view[atypIndex + 2 + k * 2]).toString(16));
      }
      addressRemote = parts.join(":");
    }
  } else if (atyp === 2) {
    if (view.length < atypIndex + 2) return { need: atypIndex + 2 };
    addressLength = 1 + view[atypIndex + 1];
    if (view.length >= atypIndex + 1 + addressLength) {
      addressRemote = new TextDecoder().decode(view.slice(atypIndex + 2, atypIndex + 1 + addressLength));
    }
  } else {
    return { invalid: "atyp " + atyp };
  }

  const total = atypIndex + 1 + addressLength;
  if (view.length < total) return { need: total };

  return {
    header: {
      // UUID dibiarkan sebagai byte: stringnya hanya dibangun kalau ada allowlist.
      uuidBytes: view.subarray(1, 17),
      addressRemote: addressRemote,
      portRemote: portRemote,
      rawClientData: view.slice(total),
      version: new Uint8Array([version, 0]),
      isUDP: cmd === 2,
    },
  };
}

// --- mux.cool (Xray Mux) ------------------------------------------------------------
// Format diambil dari klien Xray asli (diverifikasi lewat tests/mux-probe.mjs):
//   [2B metaLen][meta][2B dataLen][data]
// Dua byte panjang data hanya ada kalau opt punya bit 0x01 (Opt D). meta:
//   [2B id][1B status][1B opt] lalu untuk New (dan Keep XUDP): [1B network][2B port][1B atyp][addr]
// XUDP menambah 8 byte Global ID. status: 1=New, 2=Keep, 3=End, 4=KeepAlive.
// Kehadiran cmd=3 di header VLESS sudah cukup sebagai penanda mux (tanpa tebak-tebakan).
const MUX_STATUS_NEW = 1;
const MUX_STATUS_KEEP = 2;
const MUX_STATUS_END = 3;
const MUX_STATUS_KEEPALIVE = 4;
const MUX_OPT_DATA = 0x01;
const MUX_MAX_META = 512;
const MUX_MAX_SESSIONS = 64;

function muxEnabled(env) {
  return String((env && env.MUX) || "auto").toLowerCase() !== "off";
}

function parseMuxAddress(bytes, offset, atyp) {
  if (atyp === 1) {
    if (bytes.length < offset + 4) return null;
    return { address: [bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]].join("."), offset: offset + 4 };
  }
  if (atyp === 2) {
    if (bytes.length < offset + 1) return null;
    const length = bytes[offset];
    if (bytes.length < offset + 1 + length) return null;
    return { address: new TextDecoder().decode(bytes.subarray(offset + 1, offset + 1 + length)), offset: offset + 1 + length };
  }
  if (atyp === 3) {
    if (bytes.length < offset + 16) return null;
    const parts = [];
    for (let i = 0; i < 8; i++) {
      parts.push(((bytes[offset + i * 2] << 8) | bytes[offset + i * 2 + 1]).toString(16));
    }
    return { address: parts.join(":"), offset: offset + 16 };
  }
  return null;
}

function parseMuxMeta(meta) {
  if (meta.length < 4) return null;
  const frame = {
    id: (meta[0] << 8) | meta[1],
    status: meta[2],
    opt: meta[3],
    network: 0,
    port: 0,
    address: "",
    globalId: null,
  };
  if (frame.status < MUX_STATUS_NEW || frame.status > MUX_STATUS_KEEPALIVE) return null;

  const hasTarget = frame.status === MUX_STATUS_NEW ||
    (frame.status === MUX_STATUS_KEEP && meta.length > 4 && meta[4] === 2);
  if (hasTarget) {
    if (meta.length < 8) return null;
    frame.network = meta[4];
    frame.port = (meta[5] << 8) | meta[6];
    const parsed = parseMuxAddress(meta, 8, meta[7]);
    if (!parsed) return null;
    frame.address = parsed.address;
    if (frame.network === 2 && meta.length >= parsed.offset + 8) {
      frame.globalId = meta.subarray(parsed.offset, parsed.offset + 8);
    }
  }
  return frame;
}

function muxFrameBytes(id, status, opt, data) {
  const metaLen = 4; // id(2) + status(1) + opt(1)
  const payload = opt & MUX_OPT_DATA ? data || new Uint8Array(0) : new Uint8Array(0);
  const out = new Uint8Array(2 + metaLen + (opt & MUX_OPT_DATA ? 2 + payload.length : 0));
  out[0] = (metaLen >> 8) & 0xff;
  out[1] = metaLen & 0xff;
  out[2] = (id >> 8) & 0xff;
  out[3] = id & 0xff;
  out[4] = status;
  out[5] = opt;
  if (opt & MUX_OPT_DATA) {
    out[6] = (payload.length >> 8) & 0xff;
    out[7] = payload.length & 0xff;
    out.set(payload, 8);
  }
  return out;
}

function muxSend(state, webSocket, id, data) {
  if (webSocket.readyState !== WS_OPEN) return;
  const frame = data && data.length
    ? muxFrameBytes(id, MUX_STATUS_KEEP, MUX_OPT_DATA, data)
    : muxFrameBytes(id, MUX_STATUS_KEEP, 0, null);
  if (state.mux && state.mux.batcher) state.mux.batcher.push(frame);
  else webSocket.send(frame);
}

function muxSendEnd(state, webSocket, id) {
  if (webSocket.readyState !== WS_OPEN) return;
  const frame = muxFrameBytes(id, MUX_STATUS_END, 0, null);
  if (state.mux && state.mux.batcher) state.mux.batcher.push(frame);
  else webSocket.send(frame);
}

function muxHandle(state, webSocket, prx, env, bytes) {
  if (!muxEnabled(env)) {
    safeClose(webSocket);
    return;
  }
  if (!state.mux) {
    state.mux = { buf: new Uint8Array(0), sessions: new Map(), headerSent: false, batcher: createWsBatcher(webSocket, state) };
  }
  const mux = state.mux;
  if (!mux.headerSent) {
    mux.headerSent = true;
    if (webSocket.readyState === WS_OPEN) webSocket.send(state.versionBytes || new Uint8Array([0, 0]));
  }
  mux.buf = concatBytes(mux.buf, bytes);

  for (;;) {
    if (mux.buf.length < 2) return;
    const metaLen = (mux.buf[0] << 8) | mux.buf[1];
    if (metaLen < 4 || metaLen > MUX_MAX_META) {
      logLimited("muxError", "metaLen " + metaLen);
      safeClose(webSocket);
      return;
    }
    if (mux.buf.length < 2 + metaLen) return;
    const frame = parseMuxMeta(mux.buf.subarray(2, 2 + metaLen));
    if (!frame) {
      logLimited("muxError", "meta tidak valid");
      safeClose(webSocket);
      return;
    }
    let consumed = 2 + metaLen;
    let data = new Uint8Array(0);
    if (frame.opt & MUX_OPT_DATA) {
      if (mux.buf.length < consumed + 2) return;
      const dataLen = (mux.buf[consumed] << 8) | mux.buf[consumed + 1];
      if (mux.buf.length < consumed + 2 + dataLen) return;
      data = mux.buf.subarray(consumed + 2, consumed + 2 + dataLen);
      consumed += 2 + dataLen;
    }
    mux.buf = mux.buf.subarray(consumed);

    if (frame.status === MUX_STATUS_KEEPALIVE) continue;
    if (frame.status === MUX_STATUS_END) {
      muxCloseSession(state, webSocket, frame.id, false);
      continue;
    }
    if (frame.status === MUX_STATUS_NEW) {
      muxNewSession(state, webSocket, prx, env, frame, data);
      continue;
    }
    muxKeepSession(state, webSocket, env, frame, data);
  }
}

function muxKeepSession(state, webSocket, env, frame, data) {
  const session = state.mux.sessions.get(frame.id);
  if (!session) return;
  if (session.udp) {
    if (data.length) muxUdpQuery(state, webSocket, env, frame.id, frame, data).catch(function () {});
    return;
  }
  muxWriteSession(session, data).catch(function (err) {
    logLimited("muxError", "tulis sesi " + frame.id + " — " + (err && err.message));
  });
}

function muxNewSession(state, webSocket, prx, env, frame, data) {
  if (state.mux.sessions.size >= MUX_MAX_SESSIONS) {
    muxSendEnd(state, webSocket, frame.id);
    return;
  }
  if (frame.network === 2) {
    // XUDP (UDP lewat mux): Workers tidak punya UDP keluar, jadi hanya DNS yang dijawab.
    state.mux.sessions.set(frame.id, { id: frame.id, udp: true });
    if (data.length) muxUdpQuery(state, webSocket, env, frame.id, frame, data).catch(function () {});
    return;
  }

  const session = { id: frame.id, udp: false, tunnel: null, writer: null, closed: false };
  state.mux.sessions.set(frame.id, session);
  muxOpenTunnel(prx, frame.address, frame.port, env)
    .then(function (tunnel) {
      if (session.closed || !state.mux.sessions.has(frame.id)) {
        try { tunnel.close(); } catch (e) {}
        return;
      }
      session.tunnel = tunnel;
      muxPipeSession(state, webSocket, session);
      if (data.length) return muxWriteSession(session, data);
    })
    .catch(function (err) {
      logLimited("muxError", "tunnel " + frame.address + ":" + frame.port + " — " + (err && err.message));
      muxCloseSession(state, webSocket, frame.id, true);
    });
}

async function muxWriteSession(session, data) {
  if (!session.tunnel || session.closed) return;
  if (!session.writer) session.writer = session.tunnel.writable.getWriter();
  await session.writer.write(data);
}

function muxPipeSession(state, webSocket, session) {
  const batcher = state.mux.batcher;
  session.tunnel.readable
    .pipeTo(new WritableStream({
      write(chunk) {
        if (session.closed || webSocket.readyState !== WS_OPEN) return;
        state.lastRemoteData = Date.now();
        batcher.push(muxFrameBytes(session.id, MUX_STATUS_KEEP, MUX_OPT_DATA, chunk));
      },
      close() {},
      abort() {},
    }))
    .catch(function () {})
    .then(function () {
      muxCloseSession(state, webSocket, session.id, true);
    });
}

function muxCloseSession(state, webSocket, id, notify) {
  const session = state.mux ? state.mux.sessions.get(id) : null;
  if (!session) return;
  state.mux.sessions.delete(id);
  session.closed = true;
  const writer = session.writer;
  const tunnel = session.tunnel;
  session.writer = null;
  session.tunnel = null;
  if (writer) {
    try { writer.releaseLock(); } catch (e) {}
  }
  if (tunnel) {
    try { tunnel.close(); } catch (e) {}
  }
  if (notify && webSocket) muxSendEnd(state, webSocket, id);
}

// Buka tunnel untuk satu sub-koneksi mux: proxy utama dulu, lalu cadangan (sama seperti jalur
// non-mux, tanpa hedge karena sub-koneksi murah dan klien bisa membukanya lagi).
async function muxOpenTunnel(prx, target, port, env) {
  try {
    return await openProxyTunnel(prx.host, prx.port, target, port, PROXY_HANDSHAKE_TIMEOUT);
  } catch (err) {
    const candidates = await fallbackCandidates(prx, env).catch(function () { return []; });
    for (const candidate of candidates) {
      try {
        return await openProxyTunnel(candidate.host, candidate.port, target, port, PROXY_HANDSHAKE_TIMEOUT);
      } catch (e) {
        // coba cadangan berikutnya
      }
    }
    throw err;
  }
}

// XUDP: datagram dibalas dengan panjang 2 byte di depan (format XUDP), dan hanya DNS yang
// bisa dilayani karena Workers tidak punya UDP keluar.
async function muxUdpQuery(state, webSocket, env, id, frame, data) {
  if (frame.port !== 53) {
    muxCloseSession(state, webSocket, id, true);
    return;
  }
  try {
    const answer = await resolveDohCoalesced(dnsCacheKey(data), data, env);
    const framed = new Uint8Array(2 + answer.length);
    framed[0] = (answer.length >> 8) & 0xff;
    framed[1] = answer.length & 0xff;
    framed.set(answer, 2);
    muxSend(state, webSocket, id, framed);
  } catch (err) {
    logLimited("dohFail", String(err && err.message));
  }
}

// --- relay UDP opsional (proxy-relay/udp-relay.mjs) ---------------------------------
// Workers tidak punya UDP keluar, jadi datagram UDP non-DNS bisa diteruskan ke proses relay
// milik sendiri lewat TCP: "udp <alamat> <port> <rahasia>\n" lalu [2B panjang][payload]
// dua arah. Tanpa env.RELAY_SERVER_UDP perilakunya tetap seperti sebelumnya (tutup cepat).
const MAX_UDP_DATAGRAM = 8192;

function udpRelayConfig(env) {
  // Tier Free: relay UDP adalah fitur premium, jadi binding RELAY_SERVER_UDP diabaikan walau ada
  // (panel juga tidak pernah mengirimkannya untuk tier Free).
  if (TIER_FREE) return null;
  const host = env && env.RELAY_SERVER_UDP;
  if (!host) return null;
  return {
    host: String(host),
    port: Number((env && env.RELAY_SERVER_PORT) || 7300),
    tls: String((env && env.RELAY_SERVER_TLS) || "") === "1",
    secret: String((env && env.RELAY_SECRET) || ""),
  };
}

async function udpRelayEnsure(state, webSocket, env, header) {
  if (state.udpRelay) return true;
  const relay = udpRelayConfig(env);
  if (!relay) return false;
  if (!relay.secret) {
    logLimited("udpRelayFail", "RELAY_SECRET belum diisi");
    return false;
  }
  try {
    const sock = connect({ hostname: relay.host, port: relay.port, secureTransport: relay.tls ? "on" : "off" });
    const writer = sock.writable.getWriter();
    await writer.write(new TextEncoder().encode(
      "udp " + header.addressRemote + " " + header.portRemote + " " + relay.secret + "\n"
    ));
    state.udpPrefixed = true; // relay memakai framing berpanjang seperti VLESS UDP
    state.udpRelay = { sock: sock, writer: writer };
    udpRelayPipe(state, webSocket, sock);
    counters.udpRelayUsed++;
    return true;
  } catch (err) {
    logLimited("udpRelayFail", String(err && err.message));
    return false;
  }
}

function udpRelaySend(state, payload) {
  const relay = state.udpRelay;
  if (!relay || state.cancelled) return;
  const frame = new Uint8Array(2 + payload.length);
  frame[0] = (payload.length >> 8) & 0xff;
  frame[1] = payload.length & 0xff;
  frame.set(payload, 2);
  relay.writer.write(frame).catch(function (err) {
    logLimited("udpRelayFail", String(err && err.message));
  });
}

// Balasan relay -> datagram VLESS UDP ke klien (header 2 byte + [2B panjang][datagram]).
function udpRelayPipe(state, webSocket, sock) {
  let buf = new Uint8Array(0);
  sock.readable
    .pipeTo(new WritableStream({
      write(chunk) {
        state.lastRemoteData = Date.now();
        buf = concatBytes(buf, toBytes(chunk));
        for (;;) {
          if (buf.length < 2) return;
          const length = (buf[0] << 8) | buf[1];
          if (!length || length > MAX_UDP_DATAGRAM) {
            buf = new Uint8Array(0);
            return;
          }
          if (buf.length < 2 + length) return;
          const payload = buf.subarray(2, 2 + length);
          buf = buf.subarray(2 + length);
          if (webSocket.readyState === WS_OPEN) sendVlessPayload(state, webSocket, payload);
        }
      },
      close() {},
      abort() {},
    }))
    .catch(function (err) {
      logLimited("udpRelayFail", String(err && err.message));
    })
    .then(function () {
      closeUdpRelay(state);
    });
}

// Datagram dari klien: framing [2B panjang][payload]; kalau dua byte pertama bukan panjang yang
// masuk akal, seluruh buffer dianggap satu datagram polos (sebagian klien mengirim begitu).
// Buffer-nya terpisah dari jalur DNS supaya keduanya bisa hidup di koneksi yang sama.
function splitUdpDatagrams(state, bytes) {
  state.udpRelayBuf = concatBytes(state.udpRelayBuf || new Uint8Array(0), bytes);
  const out = [];
  for (;;) {
    if (state.udpRelayBuf.length < 2) break;
    const length = (state.udpRelayBuf[0] << 8) | state.udpRelayBuf[1];
    if (!length || length > MAX_UDP_DATAGRAM) {
      if (state.udpRelayBuf.length) out.push(state.udpRelayBuf);
      state.udpRelayBuf = new Uint8Array(0);
      break;
    }
    if (state.udpRelayBuf.length < 2 + length) break;
    out.push(state.udpRelayBuf.subarray(2, 2 + length));
    state.udpRelayBuf = state.udpRelayBuf.subarray(2 + length);
  }
  return out;
}

function closeUdpRelay(state) {
  const relay = state.udpRelay;
  if (!relay) return;
  state.udpRelay = null;
  try { relay.writer.releaseLock(); } catch (e) {}
  try { relay.sock.close(); } catch (e) {}
}

function toBytes(chunk) {
  if (typeof chunk === "string") return new TextEncoder().encode(chunk);
  if (chunk instanceof Uint8Array) return chunk;
  return new Uint8Array(chunk);
}

function concatBytes(first, second) {
  const out = new Uint8Array(first.length + second.length);
  out.set(first, 0);
  out.set(second, first.length);
  return out;
}

function isUuidAllowed(uuidBytes, env) {
  if (!env) return true;
  const allowlist = env.UUID_ALLOWLIST;
  if (!allowlist) return true;
  const list = allowlist.split(",").map(function (u) { return u.trim().toLowerCase(); }).filter(Boolean);
  if (!list.length) return true;

  // Bangun hex hanya saat allowlist dipakai (tanpa allowlist, koneksi tidak membayar
  // konversi + alokasi apa pun).
  let hex = "";
  for (let i = 0; i < uuidBytes.length; i++) hex += uuidBytes[i].toString(16).padStart(2, "0");
  const dashed = hex.slice(0, 8) + "-" + hex.slice(8, 12) + "-" + hex.slice(12, 16) + "-" + hex.slice(16, 20) + "-" + hex.slice(20);
  return list.indexOf(hex) !== -1 || list.indexOf(dashed) !== -1;
}

async function pipeRemoteToWs(remote, webSocket, state) {
  const batcher = createWsBatcher(webSocket, state);
  try {
    await remote.readable.pipeTo(new WritableStream({
      write(chunk) {
        batcher.push(chunk);
      },
      close() {},
      abort(reason) {
        logLimited("pipeError", "abort: " + reason);
      },
    }));
  } catch (err) {
    logLimited("pipeError", String(err && err.message));
    stopIdleWatch(state);
    shutdownRemote(state, false);
    safeClose(webSocket);
    return;
  }

  batcher.flush();
  stopIdleWatch(state);
  state.remote = null;
  state.remoteWriter = null;
  safeClose(webSocket);
}

// Penggabung potongan socket -> WebSocket. Urutan tetap terjaga (send selalu berurutan) dan
// potongan kecil yang datang berdekatan dikirim dalam satu pesan; dengan WS_BATCH_MS=0
// perilakunya kembali menjadi satu pesan per potongan.
function createWsBatcher(webSocket, state) {
  const limit = state.batchBytes;
  const waitMs = state.batchMs;
  let parts = [];
  let bytes = 0;
  let timer = null;

  function flush() {
    if (!parts.length) return;
    let out;
    if (parts.length === 1) {
      out = parts[0];
    } else {
      out = new Uint8Array(bytes);
      let offset = 0;
      for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
      }
    }
    parts = [];
    bytes = 0;
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
    if (webSocket.readyState === WS_OPEN) webSocket.send(out);
  }

  return {
    push(chunk) {
      state.lastRemoteData = Date.now();
      parts.push(chunk);
      bytes += chunk.length;
      if (!limit || !waitMs || bytes >= limit) {
        flush();
        return;
      }
      if (!timer) timer = setTimeout(flush, waitMs);
    },
    flush: flush,
  };
}

// --- watchdog idle/half-open -------------------------------------------------------
// Klien yang sudah mengirim data tetapi tidak pernah menerima balasan dari target (proxy
// "setengah mati") ditutup rapi setelah IDLE_CLOSE_SECONDS; tanpa ini koneksi menggantung
// sampai CDN yang memutus, dan klien tidak pernah pindah ke proxy lain.
function startIdleWatch(state, webSocket, env) {
  const seconds = Number((env && env.IDLE_CLOSE_SECONDS) || IDLE_CLOSE_DEFAULT);
  if (!(seconds > 0)) return;
  const limit = seconds * 1000;
  state.idleTimer = setInterval(function () {
    if (state.cancelled || !state.clientSent) return;
    const last = state.lastRemoteData || state.openedAt;
    if (Date.now() - last < limit) return;
    logLimited("watchdog", "target tidak menjawab " + seconds + "s — koneksi ditutup");
    stopIdleWatch(state);
    closeUdpRelay(state);
    shutdownRemote(state, false);
    safeClose(webSocket, 1001, "target tidak menjawab");
  }, Math.max(500, Math.min(limit, 15000)));
}

function stopIdleWatch(state) {
  if (!state.idleTimer) return;
  clearInterval(state.idleTimer);
  state.idleTimer = null;
}

// Writer ditahan selama tunnel hidup: menghindari getWriter()/releaseLock() pada setiap
// potongan data dari klien (ongkos CPU yang terasa pada transfer panjang).
async function writeToRemote(state, chunk) {
  if (!state.remoteWriter) state.remoteWriter = state.remote.writable.getWriter();
  await state.remoteWriter.write(chunk);
}

function shutdownRemote(state, graceful) {
  const remote = state.remote;
  const writer = state.remoteWriter;
  state.remote = null;
  state.remoteWriter = null;
  if (!remote) return;
  if (graceful && writer) {
    writer.close().catch(function () {
      try { remote.close(); } catch (e) {}
    });
    return;
  }
  if (writer) {
    try { writer.releaseLock(); } catch (e) {}
  }
  try { remote.close(); } catch (e) {}
}

function safeClose(socket, code, reason) {
  try {
    if (socket.readyState === WS_OPEN || socket.readyState === WS_CLOSING) {
      if (code) socket.close(code, reason);
      else socket.close();
    }
  } catch (e) {}
}
