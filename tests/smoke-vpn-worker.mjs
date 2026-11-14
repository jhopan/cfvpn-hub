// Smoke test vpn-worker (VLESS over WebSocket) — jalankan dengan:
//   nrun node tests/smoke-vpn-worker.mjs
//
// Menjalankan frontend/source/vpn-worker-prem.js lewat `wrangler dev` lokal. Fixture
// sementara hanya menambah satu var: DOH_ENDPOINT diarahkan ke stub DoH lokal, supaya
// uji tidak bergantung jaringan luar. Isi skrip worker sendiri byte-identik dengan repo.
//
// Stub lokal:
//   7301 target dial-langsung — mendeteksi "misroute" saat header VLESS terpecah
//   7302 proxy palsu: menolak SOCKS5 no-auth lalu melayani HTTP CONNECT + echo
//   7303 DoH: POST /dns-query -> jawaban A 93.184.216.34
//   7304 proxy SOCKS5 yang menerima no-auth: mencatat ATYP + alamat tujuan
//   7306 proxy HTTP-only kedua: menguji protokol proxy diingat antar koneksi
//   7308 proxy "setengah mati": handshake sukses lalu tidak pernah mengirim data
//   7309 REST proxy_pool palsu: bisa menyembunyikan kolom bukti (400, dianggap belum ada) —
//        bawaannya KETIGA kolom bukti (`tunnel_ok`, `tls_ok`, `tunnel_host_ok`) hilang; skenario
//        bisa memilih kolom mana yang disembunyikan. Query yang diterima dijawab dengan daftar
//        proxy sungguhan. Tanpa filter negara ia mengembalikan DUA baris berurutan (7316 lalu
//        7302); tabel terpisah "proxy_pool_dead_first" mengembalikan baris pertama
//        127.0.0.1:7307 (tanpa pendengar)
//   7311 proxy HTTP-only yang diam terhadap SOCKS5: uji race protokol
//   7312 proxy yang mengirim 20 potongan 256 B berjarak ~1 ms: uji batching socket->WS
//   7316 proxy HTTP-only ketiga: baris PERTAMA yang dikembalikan stub pool (uji "tercepat dulu")
//
// Skenario:
//   1. DNS (cmd=2 port 53) framing Xray `[2B panjang][query]` -> balasan `00 00` + `[2B][jawaban]`
//   2. DNS framing polos tanpa prefix panjang -> balasan `00 00` + jawaban polos
//   3. Sama seperti (1) tapi header VLESS terpecah 8 byte + sisanya
//   4. Dua datagram dalam satu frame -> dua balasan
//   5. UDP non-53 ditutup cepat (tidak menggantung)
//   6. TCP via proxy (regresi jalur normal)
//   7. Target menutup koneksi -> WebSocket ikut ditutup
//   8. free vs prem identik
//   9. SOCKS5: tujuan IP numerik dikirim ATYP 1/4, bukan domain
//  10. HTTP CONNECT: target IPv6 dikurung siku
//  11. Cache DoH: query sama diulang tidak memanggil DoH lagi (txid tetap diperbarui)
//  12. Proxy HTTP-only: protokol diingat, koneksi kedua tidak mencoba SOCKS5
//  13. Query DNS identik bersamaan: satu panggilan DoH, dua balasan ber-txid sendiri
//  14. UUID di luar UUID_ALLOWLIST ditolak
//  15. Failover: proxy utama mati -> cadangan dipakai
//  16. Proxy utama sehat -> cadangan tidak dipakai
//  17. Cache DNS negatif: NXDOMAIN tidak di-query ulang
//  18. /health melaporkan kondisi isolate (fallback_uses, dns_hits, proxy_memo)
//  19. Cache API: query kedua dilayani cache bersama tanpa DoH (worker DNS_CACHE_MODE=cache)
//  20. DoH endpoint utama mati -> fallback dipakai (worker kedua)
//  21. Semua endpoint DoH mati -> balasan SERVFAIL, bukan diam (worker kedua)
//  22. Watchdog: target diam -> koneksi ditutup, tidak menggantung (worker IDLE_CLOSE_SECONDS=1)
//  23. Failover pool: daftar dari proxy_pool ditunggu lalu dipakai (worker FALLBACK_POOL=on)
//  23b. Path /rotate & /pool: worker memilih proxy sendiri (statis dan dari pool)
//  23c. Path /SG: pool difilter negara (country=in.(SG)) sebelum dipilih acak
//  23d. Path /XX: selector negara gagal-tertutup, bukan pindah ke proxy negara lain
//  23e. Semua kolom bukti belum ada (400): urutan 1..3 ditolak, pool tetap terisi lewat
//       urutan ke-4 (ping), dan worker tidak mengulang percobaan urutan itu di pengambilan
//       berikutnya (worker keenam)
//  23f. Pool "tercepat dulu": /ALL memakai baris PERTAMA pool (7316) dan tidak menyentuh baris
//       kedua (7302) selama yang teratas sehat
//  23g. Baris pertama pool mati (127.0.0.1:7307) -> jalur cadangan tetap sampai baris kedua
//       (7302) dan echo jalan; worker terpisah supaya cache pool kunci "all" bersih
//  23h. `tunnel_host_ok` (bukti host scanner) ada -> urutan 1 (empat tingkat) langsung dipakai,
//       tanpa satu pun 400 (worker kesepuluh)
//  23i. `tunnel_host_ok` belum ada (400): worker jatuh ke urutan 2 (tunnel_ok + tls_ok + ping),
//       bukan ke urutan ping saja, lalu mengingatnya (worker kesebelas)
//  23j. `tls_ok` & `tunnel_host_ok` belum ada (400): worker jatuh ke urutan 3
//       (tunnel_ok + ping), bukan ke urutan ping saja, lalu mengingatnya (worker kesembilan)
//  24. Early data lewat query ?ed= tanpa mengirim pesan WS
//  25. Protokol belum diketahui: SOCKS5 & HTTP CONNECT dicoba paralel (bukan berurutan)
//  26. Batching WS aktif: potongan kecil digabung jadi sedikit pesan
//  27. Batching dimatikan (WS_BATCH_MS=0): satu pesan per potongan (pembanding)
//  28. Log dibatasi: 3 kegagalan proxy -> 1 baris log, counter /health tetap naik
//  29. UDP non-DNS lewat relay memang jalan di prem (header "udp <alamat> <port> <rahasia>" ke
//      relay, balasan datang) — pembanding untuk tier Free
//  30. Tier Free: binding RELAY_SERVER_UDP diabaikan -> UDP non-DNS ditutup cepat, tidak ada
//      satu pun lalu lintas relay (relay tidak mencatat sesi ke port tujuan itu)
//
// Port worker bisa diganti lewat SMOKE_PORT (bawaan 8787; worker lain memakai port+1..+11).
import net from "node:net";
import http from "node:http";
import dgram from "node:dgram";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";

const ROOT = path.resolve(import.meta.dirname, "..");
const SOURCE = path.join(ROOT, "frontend", "source", "vpn-worker-prem.js");
const SOURCE_FREE = path.join(ROOT, "frontend", "source", "vpn-worker-free.js");
const WRANGLER = path.join(ROOT, "node_modules", "wrangler", "bin", "wrangler.js");
const UUID_HEX = "14df7aee041645a8a651e69de188deca";
const PORT = Number(process.env.SMOKE_PORT || 8787);
const PORT_DOH = PORT + 1;
const PORT_IDLE = PORT + 2;
const PORT_POOL = PORT + 3;
const PORT_RELAY = PORT + 4;
const PORT_ORDER = PORT + 5;
const PORT_TOKEN = PORT + 6; // uji gerbang /health (HEALTH_TOKEN)
const PORT_FREE = PORT + 7; // worker dari berkas tier Free (relay UDP diabaikan)
const PORT_POOL_DEAD = PORT + 8; // worker pool dengan baris TERATAS mati (tabel pool terpisah)
const PORT_POOL_TLS = PORT + 9; // worker pool saat tls_ok & tunnel_host_ok belum ada
const PORT_POOL_HOST = PORT + 10; // worker pool dengan skema LENGKAP (semua kolom bukti ada)
const PORT_POOL_HOST_MISSING = PORT + 11; // worker pool saat tunnel_host_ok belum ada
// Target IPv6 tetap untuk uji (2001:db8::1) — ditulis apa adanya supaya uji tidak memakai
// parser yang sedang diuji.
const IPV6_TARGET = "2001:db8::1";
const IPV6_BYTES = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const hex = (b) => Buffer.from(b).toString("hex");

const S = {
  raw: { opens: 0, all: Buffer.alloc(0) },
  proxy: { socks5: 0, http: 0, closes: 0, connectLines: [], byPort: {}, echoed: false, closeAfterEcho: false },
  socks: { greeting: 0, requests: [], closes: 0, echoed: false },
  silent: { handshakes: 0 },
  pool: { requests: [], orderRejected: 0, missing: ["tunnel_ok", "tls_ok", "tunnel_host_ok"] },
  race: { socksSilent: 0, http: 0, closes: 0, echoed: false },
  udp: { messages: 0, last: "" },
  stream: { chunks: 0, }, 
  doh: { requests: [], answers: 0, answerLength: 0 },
};

function reset() {
  S.raw.opens = 0;
  S.raw.all = Buffer.alloc(0);
  S.proxy.socks5 = 0;
  S.proxy.http = 0;
  S.proxy.closes = 0;
  S.proxy.connectLines = [];
  S.proxy.byPort = {};
  S.proxy.echoed = false;
  S.proxy.closeAfterEcho = false;
  S.socks.greeting = 0;
  S.socks.requests = [];
  S.socks.closes = 0;
  S.socks.echoed = false;
  S.silent.handshakes = 0;
  S.pool.requests = [];
  S.race.socksSilent = 0;
  S.race.http = 0;
  S.race.closes = 0;
  S.race.echoed = false;
  S.stream.chunks = 0;
  S.doh.requests = [];
  S.doh.answers = 0;
}

function listen(port, handler) {
  return new Promise((resolve, reject) => {
    const server = net.createServer(handler);
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolve(server));
  });
}

const startRaw = () =>
  listen(7301, (sock) => {
    S.raw.opens++;
    sock.on("error", () => {});
    sock.on("data", (d) => { S.raw.all = Buffer.concat([S.raw.all, d]); });
  });

const startProxy = (port = 7302) =>
  listen(port, (sock) => {
    let phase = "greeting";
    sock.on("error", () => {});
    sock.on("close", () => S.proxy.closes++);
    sock.on("data", (d) => {
      if (phase === "greeting") {
        if (d[0] === 0x05) {
          S.proxy.socks5++;
          sock.write(Buffer.from([0x05, 0x01])); // butuh auth -> worker harus fallback
          return;
        }
        phase = "tunnel";
        S.proxy.http++;
        S.proxy.byPort[port] = (S.proxy.byPort[port] || 0) + 1;
        S.proxy.connectLines.push(d.toString("latin1").split("\r\n")[0]);
        sock.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        return;
      }
      if (!S.proxy.echoed) {
        S.proxy.echoed = true;
        sock.write(Buffer.concat([Buffer.from([0x55, 0x66]), d]));
        if (S.proxy.closeAfterEcho) sock.end();
      }
    });
  });

// --- stub proxy SOCKS5 yang menerima no-auth: mencatat ATYP + alamat yang diminta ---
const startSocks = () =>
  listen(7304, (sock) => {
    let phase = "greeting";
    let buf = Buffer.alloc(0);
    sock.on("error", () => {});
    sock.on("close", () => S.socks.closes++);
    sock.on("data", (d) => {
      buf = Buffer.concat([buf, d]);
      if (phase === "greeting") {
        if (buf.length < 3) return;
        if (buf[0] !== 0x05) { sock.destroy(); return; }
        S.socks.greeting++;
        sock.write(Buffer.from([0x05, 0x00])); // tanpa auth
        buf = buf.subarray(3);
        phase = "connect";
      }
      if (phase === "connect") {
        if (buf.length < 4) return;
        const atyp = buf[3];
        let need;
        if (atyp === 1) need = 10;
        else if (atyp === 4) need = 22;
        else if (atyp === 3) {
          if (buf.length < 5) return;
          need = 5 + buf[4] + 2;
        } else { sock.destroy(); return; }
        if (buf.length < need) return;
        S.socks.requests.push({ atyp: atyp, request: buf.subarray(0, need).toString("hex") });
        buf = buf.subarray(need);
        phase = "tunnel";
        sock.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
      }
      if (phase === "tunnel" && buf.length) {
        if (!S.socks.echoed) {
          S.socks.echoed = true;
          sock.write(Buffer.concat([Buffer.from([0x55, 0x66]), buf]));
        }
        buf = Buffer.alloc(0);
      }
    });
  });

// --- stub DoH: menjawab setiap query dengan A record tetap ---
// Nama yang diawali "nx" dijawab NXDOMAIN (rcode 3) supaya cache negatif bisa diuji.
function questionName(query) {
  const labels = [];
  let i = 12;
  while (i < query.length && query[i] !== 0) {
    labels.push(query.subarray(i + 1, i + 1 + query[i]).toString("ascii"));
    i += query[i] + 1;
  }
  return labels.join(".");
}

function dnsAnswerFor(query) {
  const txid = query.subarray(0, 2);
  let i = 12;
  while (i < query.length && query[i] !== 0) i += query[i] + 1;
  const question = query.subarray(12, i + 5);
  if (questionName(query).startsWith("nx")) {
    return Buffer.concat([
      txid,
      Buffer.from([0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
      question,
    ]);
  }
  return Buffer.concat([
    txid,
    Buffer.from([0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]),
    question,
    Buffer.from([0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 93, 184, 216, 34]),
  ]);
}

// --- stub pool proxy (meniru REST proxy_pool Supabase) --------------------------------
// Tanpa filter negara, tabel mengembalikan DUA baris BERURUTAN seperti urutan pool asli
// (tercepat dulu): tabel "proxy_pool" -> 7316 lalu 7302, tabel "proxy_pool_dead_first" ->
// 127.0.0.1:7307 (tanpa pendengar) lalu 7302. Yang pertama membuktikan "baris teratas dipakai,
// baris kedua tidak disentuh", yang kedua membuktikan jalur cadangan tetap sampai ke baris kedua
// saat kandidat teratas mati. Alamat mati sengaja port lokal tanpa pendengar (pola uji failover
// statis di skenario 15/23): SYN ke TEST-NET-1 (192.0.2.1) bisa menggantung puluhan detik,
// sehingga pencatatan kegagalan proxy utama di /health tidak sempat terlihat di jendela uji.
// Kolom bukti (`tunnel_ok` dari edge, `tls_ok` dari host scanner, `tunnel_host_ok` dari host
// scanner) ditambahkan lewat SQL manual, jadi stub bisa MENYEMBUNYIKAN kolom mana pun (balas 400
// seperti PostgREST) dan hanya menjawab query yang tidak menyebutnya. Bawaannya KETIGA kolom
// hilang: skema terlama yang harus tetap jalan. `S.pool.missing` diganti per skenario (bukan
// global selamanya) supaya rantai mundur empat tingkat bisa diuji satu per satu.
const POOL_TABLE_DEAD_FIRST = "proxy_pool_dead_first";
const POOL_FAST_PORT = 7316; // baris pertama tabel "proxy_pool" (proxy HTTP-only + echo)
const POOL_DEAD_PORT = 7307; // baris pertama tabel "proxy_pool_dead_first" (tidak ada pendengar)
const startPoolStub = () =>
  new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      const url = req.url || "";
      S.pool.requests.push(url);
      const order = (url.match(/[?&]order=([^&]*)/) || [])[1] || "";
      const missing = (S.pool.missing || []).filter((col) => new RegExp("(^|,)" + col + "\\.").test(order));
      if (missing.length) {
        S.pool.orderRejected++;
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ code: "42703", message: "column proxy_pool." + missing[0] + " does not exist" }));
        return;
      }
      // Jawab sesuai filter + tabel: tanpa filter -> dua baris tercepat-dulu, SG -> "7306",
      // negara lain -> kosong. Yang kosong dipakai untuk membuktikan selector negara
      // gagal-tertutup; tabel dead-first dipakai worker terpisah supaya cache pool per-filter
      // (kunci "all") milik worker itu benar-benar bersih.
      const table = (url.match(/\/rest\/v1\/([^?]*)/) || [])[1] || "";
      const filter = (url.match(/country=in\.\(([^)]*)\)/) || [])[1];
      const rows = filter
        ? (/SG/.test(filter) ? [{ ip: "127.0.0.1", port: 7306 }] : [])
        : (table === POOL_TABLE_DEAD_FIRST
            ? [{ ip: "127.0.0.1", port: POOL_DEAD_PORT }, { ip: "127.0.0.1", port: 7302 }]
            : [{ ip: "127.0.0.1", port: POOL_FAST_PORT }, { ip: "127.0.0.1", port: 7302 }]);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(rows));
    });
    server.once("error", reject);
    server.listen(7309, "127.0.0.1", () => resolve(server));
  });

// --- stub proxy "setengah mati": handshake sukses, lalu tidak pernah mengirim apa pun ---
const startSilentProxy = () =>
  listen(7308, (sock) => {
    let phase = "greeting";
    let buf = Buffer.alloc(0);
    sock.on("error", () => {});
    sock.on("data", (d) => {
      buf = Buffer.concat([buf, d]);
      if (phase === "greeting") {
        if (buf.length < 3) return;
        S.silent.handshakes++;
        sock.write(Buffer.from([0x05, 0x00]));
        buf = buf.subarray(3);
        phase = "connect";
      }
      if (phase === "connect") {
        if (buf.length < 4) return;
        const atyp = buf[3];
        let need;
        if (atyp === 1) need = 10;
        else if (atyp === 4) need = 22;
        else if (atyp === 3) {
          if (buf.length < 5) return;
          need = 5 + buf[4] + 2;
        } else { sock.destroy(); return; }
        if (buf.length < need) return;
        buf = buf.subarray(need);
        phase = "silent";
        sock.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        // sengaja tidak mengirim data apa pun setelah ini
      }
    });
  });

// --- stub proxy HTTP CONNECT yang DIAM kalau dikirimi SOCKS5 (port 7311) ---------------
// Dipakai menguji race protokol: kalau worker mencoba SOCKS5 lebih dulu (berurutan), ia harus
// menunggu timeout; dengan race, jalur HTTP CONNECT langsung jalan.
const startRaceProxy = () =>
  listen(7311, (sock) => {
    let phase = "first";
    sock.on("error", () => {});
    sock.on("close", () => S.race.closes++);
    sock.on("data", (d) => {
      if (phase === "first") {
        if (d[0] === 0x05) {
          S.race.socksSilent++; // sengaja tidak dibalas
          return;
        }
        phase = "tunnel";
        S.race.http++;
        sock.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        return;
      }
      if (!S.race.echoed) {
        S.race.echoed = true;
        sock.write(Buffer.concat([Buffer.from([0x55, 0x66]), d]));
      }
    });
  });

// --- stub proxy yang mengirim banyak potongan kecil (port 7312) ------------------------
// Dipakai mengukur batching socket->WS: 20 tulisan berjarak ~1 ms.
const startStreamProxy = () =>
  listen(7312, (sock) => {
    let phase = "first";
    sock.on("error", () => {});
    sock.on("data", (d) => {
      if (phase !== "first") return;
      if (d[0] === 0x05) return;
      phase = "stream";
      sock.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      let sent = 0;
      const timer = setInterval(() => {
        sent++;
        S.stream.chunks++;
        try {
          sock.write(Buffer.alloc(256, 0x41));
        } catch (err) {}
        if (sent >= 20) clearInterval(timer);
      }, 1);
    });
  });

// --- uji relay UDP: UDP echo + proses relay asli (proxy-relay/udp-relay.mjs) -------------
const startUdpEcho = () =>
  new Promise((resolve, reject) => {
    const sock = dgram.createSocket("udp4");
    sock.on("error", reject);
    sock.on("message", (msg, from) => {
      S.udp.messages++;
      S.udp.last = msg.toString("utf8");
      sock.send(Buffer.concat([Buffer.from("UDP:"), msg]), from.port, from.address);
    });
    sock.bind(7314, "127.0.0.1", () => resolve(sock));
  });

function startRelay() {
  const child = spawn(process.execPath, [path.join(ROOT, "proxy-relay", "udp-relay.mjs")], {
    env: { ...process.env, RELAY_HOST: "127.0.0.1", RELAY_PORT: "7313", RELAY_SECRET: "uji", RELAY_IDLE_MS: "5000" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let out = "";
  child.stdout.on("data", (d) => { out += d.toString(); });
  child.stderr.on("data", (d) => { out += d.toString(); });
  return { child, getOut: () => out };
}

const startDoh = () =>
  new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      const chunks = [];
      req.on("data", (d) => chunks.push(d));
      req.on("end", () => {
        const body = Buffer.concat(chunks);
        S.doh.requests.push({
          method: req.method,
          url: req.url,
          contentType: req.headers["content-type"],
          length: body.length,
          txid: body.length >= 2 ? hex(body.subarray(0, 2)) : null,
        });
        if (req.method !== "POST" || req.url !== "/dns-query") {
          res.writeHead(405);
          res.end();
          return;
        }
        S.doh.answers++;
        const answer = dnsAnswerFor(body);
        S.doh.answerLength = answer.length;
        S.doh.requests[S.doh.requests.length - 1].answerLength = answer.length;
        res.writeHead(200, { "Content-Type": "application/dns-message" });
        res.end(answer);
      });
    });
    server.once("error", reject);
    server.listen(7303, "127.0.0.1", () => resolve(server));
  });

// `source` opsional: tier Free memakai berkas vpn-worker-free.js, sisanya prem.
function makeFixture(dir, vars, source = SOURCE) {
  const src = fs.readFileSync(source, "utf8");
  fs.writeFileSync(path.join(dir, "worker.local.mjs"), src);
  const lines = Object.entries(vars).map(([key, value]) => `${key} = "${value}"`).join("\n");
  fs.writeFileSync(
    path.join(dir, "wrangler.toml"),
    `name = "vpn-worker-smoke"\nmain = "worker.local.mjs"\ncompatibility_date = "2024-05-12"\n\n[vars]\n${lines}\n`
  );
}

function startWorker(dir, port) {
  const child = spawn(process.execPath, [WRANGLER, "dev", "--port", String(port), "--ip", "127.0.0.1"], {
    cwd: dir,
    env: { ...process.env, WRANGLER_SEND_METRICS: "false", CI: "1", NO_COLOR: "1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let out = "";
  child.stdout.on("data", (d) => { out += d.toString(); });
  child.stderr.on("data", (d) => { out += d.toString(); });
  return { child, getOut: () => out };
}

function killTree(child) {
  try {
    if (process.platform === "win32") spawnSync("taskkill", ["/pid", String(child.pid), "/T", "/F"]);
    else child.kill("SIGKILL");
  } catch {}
}

async function waitPort(port, timeoutMs) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    const ok = await new Promise((res) => {
      const s = net.connect(port, "127.0.0.1");
      s.on("connect", () => { s.destroy(); res(true); });
      s.on("error", () => res(false));
    });
    if (ok) return true;
    await sleep(400);
  }
  return false;
}

async function until(fn, timeoutMs = 3000, pollMs = 50) {
  const t0 = Date.now();
  for (;;) {
    if (fn()) return true;
    if (Date.now() - t0 > timeoutMs) return false;
    await sleep(pollMs);
  }
}

// atyp: 1 = IPv4, 2 = domain (bawaan), 3 = IPv6 — sama seperti VLESS.
function frame({ cmd, host = "dns.local", port, payload, atyp = 2, uuid = UUID_HEX }) {
  let address;
  if (atyp === 1) {
    address = Buffer.from([0x01, ...host.split(".").map(Number)]);
  } else if (atyp === 3) {
    address = Buffer.concat([Buffer.from([0x03]), Buffer.from(IPV6_BYTES)]);
  } else {
    const hostBytes = Buffer.from(host, "utf8");
    address = Buffer.concat([Buffer.from([0x02, hostBytes.length]), hostBytes]);
  }
  return Buffer.concat([
    Buffer.from([0x00]),
    Buffer.from(uuid, "hex"),
    Buffer.from([0x00]),
    Buffer.from([cmd]),
    Buffer.from([(port >> 8) & 0xff, port & 0xff]),
    address,
    Buffer.from(payload),
  ]);
}

function dnsQuery(id, name) {
  const labels = name.split(".").flatMap((l) => [Buffer.from([l.length]), Buffer.from(l, "ascii")]);
  return Buffer.concat([
    Buffer.from([(id >> 8) & 0xff, id & 0xff, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
    ...labels,
    Buffer.from([0x00]),
    Buffer.from([0x00, 0x01, 0x00, 0x01]),
  ]);
}

const prefixed = (message) => Buffer.concat([Buffer.from([(message.length >> 8) & 0xff, message.length & 0xff]), message]);

function openWs(wsPath, port = PORT) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${port}${wsPath}`);
    const chunks = [];
    let closed = false;
    let settled = false;
    ws.binaryType = "arraybuffer";
    const timer = setTimeout(() => {
      if (!settled) { settled = true; reject(new Error("ws open timeout")); }
    }, 8000);
    ws.addEventListener("close", () => { closed = true; });
    ws.addEventListener("open", () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ ws, received: () => Buffer.concat(chunks), messages: () => chunks.length, isClosed: () => closed });
    });
    ws.addEventListener("error", () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new Error("ws error"));
    });
    ws.addEventListener("message", (e) => chunks.push(Buffer.from(e.data)));
  });
}

// ---- skenario ----

// mode: "prefixed" | "raw" | "split" | "two"
async function scenarioDns(mode) {
  const rawBefore = S.raw.opens;
  S.doh.requests = [];
  S.doh.answers = 0;
  S.doh.answerLength = 0;

  // Nama pertanyaan unik per mode: cache DoH per-isolate tidak boleh menyembunyikan
  // panggilan DoH yang sedang diuji di skenario ini.
  const q1 = dnsQuery(0x1111, `dns-${mode}.local`);
  const q2 = dnsQuery(0x2222, `dns-${mode}-2.local`);
  let payload;
  if (mode === "raw") payload = q1;
  else if (mode === "two") payload = Buffer.concat([prefixed(q1), prefixed(q2)]);
  else payload = prefixed(q1);

  const f = frame({ cmd: 2, port: 53, payload });
  const { ws, received } = await openWs("/1.2.3.4:5678", PORT);

  if (mode === "split") {
    ws.send(f.subarray(0, 8));
    await sleep(300);
    ws.send(f.subarray(8));
  } else {
    ws.send(f);
  }

  const expectedCount = mode === "two" ? 2 : 1;
  await until(() => received().length > 0 && S.doh.answers >= expectedCount, 6000);
  await until(() => false, 400); // beri waktu balasan kedua tiba
  const got = received();
  ws.close();

  const dohTxids = S.doh.requests.map((r) => r.txid).sort().join(",");
  const dohOk =
    S.doh.requests.length === expectedCount &&
    S.doh.requests.every((r) => r.method === "POST" && r.contentType === "application/dns-message") &&
    (mode === "two" ? dohTxids === "1111,2222" : S.doh.requests[0].txid === "1111");

  const headerOk = got.length >= 2 && got[0] === 0x00 && got[1] === 0x00;
  let bodyOk = false;
  let detail = "";
  const skipPrefix = mode === "raw" ? 0 : 2;
  if (headerOk && got.length >= 2 + skipPrefix + 12) {
    if (mode === "raw") {
      bodyOk = got.subarray(2, 4).toString("hex") === "1111" && got.length === 2 + S.doh.answerLength;
      detail = `jawaban polos ${got.length - 2} byte (harap ${S.doh.answerLength})`;
    } else {
      const len1 = (got[2] << 8) | got[3];
      const a1txid = got.subarray(4, 6).toString("hex");
      if (mode === "two") {
        // Beberapa query dalam satu frame dikerjakan paralel, jadi urutan datagram balasan
        // tidak dijamin — sama seperti UDP asli; klien mencocokkan lewat txid + pertanyaan.
        const off = 4 + len1;
        const len2 = (got[off] << 8) | got[off + 1];
        const a2txid = got.subarray(off + 2, off + 4).toString("hex");
        bodyOk = [a1txid, a2txid].sort().join(",") === "1111,2222" && len1 > 0 && len2 > 0;
        detail = `len1=${len1} txid1=${a1txid} len2=${len2} txid2=${a2txid} (urutan bebas)`;
      } else {
        bodyOk = a1txid === "1111" && len1 > 0;
        detail = `len=${len1} txid=${a1txid}`;
      }
    }
  }

  const names = { prefixed: "DNS framing Xray (panjang 2B)", raw: "DNS framing polos", split: "DNS header terpecah 8 + sisanya", two: "dua datagram DNS satu frame" };
  return {
    name: `UDP/DNS: ${names[mode]}`,
    pass: headerOk && bodyOk && dohOk && S.raw.opens === rawBefore,
    detail: `headerVLESS=${hex(got.subarray(0, 2))} ${detail} doh=${JSON.stringify(S.doh.requests)} rawDial=${S.raw.opens - rawBefore}`,
  };
}

async function scenarioUdpOtherPort() {
  const f = frame({ cmd: 2, port: 4444, payload: Buffer.from([1, 2, 3, 4]) });
  const { ws, isClosed } = await openWs("/1.2.3.4:5678");
  ws.send(f);
  const closed = await until(() => isClosed(), 3000);
  try { ws.close(); } catch {}
  return { name: "UDP port non-53 ditutup cepat", pass: closed, detail: `wsTertutup=${closed}` };
}

async function scenarioTcp() {
  const payload = Buffer.from("PING");
  const f = frame({ cmd: 1, host: "example.com", port: 80, payload });
  const { ws, received } = await openWs("/127.0.0.1:7302", PORT);
  ws.send(f);

  await until(() => received().length >= 8, 8000);
  const got = received();
  const expected = Buffer.concat([Buffer.from([0x00, 0x00, 0x55, 0x66]), payload]);
  const matchOk = got.length >= expected.length && got.subarray(0, expected.length).equals(expected);
  const connectOk = S.proxy.connectLines.some((l) => l.includes("CONNECT example.com:80"));

  const closesBefore = S.proxy.closes;
  ws.close();
  const leakOk = await until(() => S.proxy.closes > closesBefore, 2500);

  return {
    name: "TCP via proxy (cmd=1) — regresi jalur normal",
    pass: matchOk && connectOk && leakOk,
    detail: `resp=${hex(got.subarray(0, 8))} respOk=${matchOk} connect=${JSON.stringify(S.proxy.connectLines)} connectOk=${connectOk} socks5Ditolak=${S.proxy.socks5 > 0} socketTutup=${leakOk}`,
  };
}

async function scenarioRemoteClose() {
  S.proxy.closeAfterEcho = true;
  S.proxy.echoed = false;
  const f = frame({ cmd: 1, host: "example.com", port: 80, payload: Buffer.from("PING") });
  const { ws, received, isClosed } = await openWs("/127.0.0.1:7302", PORT);
  ws.send(f);
  await until(() => received().length >= 8, 8000);
  const closedByWorker = await until(() => isClosed(), 2500);
  S.proxy.closeAfterEcho = false;
  return { name: "target menutup koneksi -> WebSocket ikut ditutup", pass: closedByWorker, detail: `wsTertutup=${closedByWorker}` };
}

// Proxy SOCKS5 yang menerima no-auth: alamat tujuan berupa IP numerik harus dikirim sebagai
// ATYP 1 (IPv4) / 4 (IPv6), bukan domain — proxy yang menolak literal IP berbentuk domain
// akan gagal kalau salah.
async function scenarioSocks5Numeric() {
  const payload = Buffer.from("PING");
  const cases = [
    { label: "IPv4", atyp: 1, host: "1.2.3.4", port: 80, expect: "05010001010203040050" },
    { label: "IPv6", atyp: 3, host: IPV6_TARGET, port: 443, expect: "05010004" + Buffer.from(IPV6_BYTES).toString("hex") + "01bb" },
  ];
  const details = [];
  let pass = true;

  for (const item of cases) {
    S.socks.requests = [];
    S.socks.echoed = false;
    const { ws, received } = await openWs("/127.0.0.1:7304", PORT);
    ws.send(frame({ cmd: 1, atyp: item.atyp, host: item.host, port: item.port, payload }));
    await until(() => received().length >= 8, 8000);
    const got = received();
    ws.close();

    const request = S.socks.requests.length ? S.socks.requests[0].request : "";
    const atypOk = S.socks.requests.length === 1 && S.socks.requests[0].atyp === (item.atyp === 3 ? 4 : 1);
    const bytesOk = request === item.expect;
    const echoOk = got.length >= 8 && got.subarray(0, 4).toString("hex") === "00005566";
    pass = pass && atypOk && bytesOk && echoOk;
    details.push(`${item.label}: atyp=${S.socks.requests.length ? S.socks.requests[0].atyp : "-"} req=${request} harap=${item.expect} echo=${echoOk}`);
  }

  return { name: "SOCKS5: tujuan IP numerik dikirim ATYP 1/4 (bukan domain)", pass: pass, detail: details.join(" | ") };
}

// Target IPv6 lewat HTTP CONNECT (proxy yang menolak SOCKS5): authority wajib dikurung siku.
async function scenarioHttpConnectIpv6() {
  const payload = Buffer.from("PING");
  const before = S.proxy.connectLines.length;
  S.proxy.echoed = false;
  const { ws, received } = await openWs("/127.0.0.1:7302", PORT);
  ws.send(frame({ cmd: 1, atyp: 3, host: IPV6_TARGET, port: 443, payload }));
  await until(() => received().length >= 8, 8000);
  const got = received();
  ws.close();

  const lines = S.proxy.connectLines.slice(before);
  // Alamat IPv6 datang sebagai 16 byte di header VLESS, jadi yang dikirim ke proxy adalah
  // bentuk panjangnya — tetap harus dikurung siku.
  const lineOk = lines.some((line) => line === "CONNECT [2001:db8:0:0:0:0:0:1]:443 HTTP/1.1");
  const echoOk = got.length >= 8 && got.subarray(0, 4).toString("hex") === "00005566";
  return { name: "HTTP CONNECT: target IPv6 dikurung siku", pass: lineOk && echoOk, detail: `lines=${JSON.stringify(lines)} echo=${echoOk}` };
}

// Cache DoH: pertanyaan yang sama diulang tidak boleh memanggil DoH lagi, dan txid balasan
// harus mengikuti pertanyaan yang baru.
async function scenarioDnsCache() {
  S.doh.requests = [];
  S.doh.answers = 0;
  const name = "cache-uji.local";
  const { ws, received } = await openWs("/1.2.3.4:5678", PORT);

  ws.send(frame({ cmd: 2, port: 53, payload: prefixed(dnsQuery(0x3333, name)) }));
  await until(() => S.doh.answers >= 1 && received().length > 4, 8000);
  await until(() => false, 300);
  const first = received();
  const len1 = first.length >= 4 ? (first[2] << 8) | first[3] : 0;
  const dohAfterFirst = S.doh.requests.length;

  ws.send(frame({ cmd: 2, port: 53, payload: prefixed(dnsQuery(0x4444, name)) }));
  await until(() => received().length >= 4 + len1 + 2, 8000);
  await until(() => false, 300);
  const all = received();
  ws.close();

  const second = all.subarray(4 + len1);
  const len2 = second.length >= 4 ? (second[0] << 8) | second[1] : 0;
  const txid2 = second.length >= 4 ? second.subarray(2, 4).toString("hex") : "";
  const pass = dohAfterFirst === 1 && S.doh.requests.length === 1 && len2 === len1 && txid2 === "4444";
  return { name: "DNS cache: query sama diulang tidak memanggil DoH lagi", pass: pass, detail: `dohSetelahPertama=${dohAfterFirst} dohTotal=${S.doh.requests.length} len1=${len1} len2=${len2} txid2=${txid2}` };
}

// Satu koneksi TCP uji lewat proxy: kirim frame cmd=1, tunggu echo, ukur waktu dan hitung
// percobaan SOCKS5 yang terjadi selama koneksi itu.
async function connectTcpViaProxy(proxyPath, port) {
  const payload = Buffer.from("PING");
  const socksBefore = S.proxy.socks5;
  S.proxy.echoed = false;
  S.socks.echoed = false;
  const started = Date.now();
  const { ws, received } = await openWs(proxyPath, PORT);
  ws.send(frame({ cmd: 1, host: "example.com", port: port, payload }));
  const ok = await until(() => received().length >= 8, 10000);
  const ms = Date.now() - started;
  try { ws.close(); } catch {}
  return { ok: ok, ms: ms, socks5: S.proxy.socks5 - socksBefore };
}

// Proxy yang cuma bisa HTTP CONNECT: setelah protokolnya diketahui, koneksi berikutnya tidak
// lagi membayar satu koneksi + satu round trip SOCKS5.
async function scenarioProxyProtocolMemo() {
  const first = await connectTcpViaProxy("/127.0.0.1:7306", 80);
  const second = await connectTcpViaProxy("/127.0.0.1:7306", 80);
  const pass = first.ok && second.ok && first.socks5 === 1 && second.socks5 === 0;
  return {
    name: "Proxy HTTP-only: protokol diingat, koneksi kedua tak coba SOCKS5",
    pass: pass,
    detail: `pertama: socks5=${first.socks5} echo=${first.ok} ${first.ms}ms · kedua: socks5=${second.socks5} echo=${second.ok} ${second.ms}ms`,
  };
}

// Dua query identik yang dikirim bersamaan (satu frame) harus berbagi satu panggilan DoH,
// tapi masing-masing tetap menerima balasan dengan txid-nya sendiri.
async function scenarioDnsCoalesce() {
  S.doh.requests = [];
  S.doh.answers = 0;
  const name = "coalesce-uji.local";
  const { ws, received } = await openWs("/1.2.3.4:5678", PORT);
  ws.send(frame({ cmd: 2, port: 53, payload: Buffer.concat([prefixed(dnsQuery(0x7777, name)), prefixed(dnsQuery(0x8888, name))]) }));
  await until(() => S.doh.answers >= 1, 8000);
  await until(() => false, 400);
  const got = received();
  ws.close();

  const len1 = got.length >= 4 ? (got[2] << 8) | got[3] : 0;
  const txid1 = got.subarray(4, 6).toString("hex");
  const off = 4 + len1;
  const len2 = got.length >= off + 4 ? (got[off] << 8) | got[off + 1] : 0;
  const txid2 = got.length >= off + 4 ? got.subarray(off + 2, off + 4).toString("hex") : "";
  const pass = S.doh.requests.length === 1 && [txid1, txid2].sort().join(",") === "7777,8888" && len1 > 0 && len2 > 0;
  return {
    name: "Query DNS identik bersamaan: satu panggilan DoH, dua balasan",
    pass: pass,
    detail: `doh=${S.doh.requests.length} txid=${txid1},${txid2} len=${len1},${len2}`,
  };
}

// UUID_ALLOWLIST diisi di fixture: UUID yang diizinkan harus jalan (semua skenario lain),
// yang di luar daftar harus diputus.
async function scenarioUuidBlocked() {
  const { ws, received, isClosed } = await openWs("/127.0.0.1:7302", PORT);
  ws.send(frame({ cmd: 1, host: "example.com", port: 80, payload: Buffer.from("PING"), uuid: "ff".repeat(16) }));
  const closed = await until(() => isClosed(), 4000);
  await until(() => false, 200);
  const silent = received().length === 0;
  try { ws.close(); } catch {}
  return { name: "UUID di luar UUID_ALLOWLIST ditolak", pass: closed && silent, detail: `wsTertutup=${closed} tanpaData=${silent}` };
}

// Endpoint DoH utama sengaja mati: worker harus memakai env.DOH_FALLBACK.
async function scenarioDohFallback(port) {
  S.doh.requests = [];
  S.doh.answers = 0;
  const { ws, received } = await openWs("/1.2.3.4:5678", port);
  ws.send(frame({ cmd: 2, port: 53, payload: prefixed(dnsQuery(0x5555, "fallback-uji.local")) }));
  const answered = await until(() => S.doh.answers >= 1 && received().length > 6, 10000);
  await until(() => false, 300);
  const got = received();
  ws.close();
  const txid = got.length >= 6 ? got.subarray(4, 6).toString("hex") : "";
  return {
    name: "DoH: endpoint utama mati -> pakai endpoint fallback",
    pass: answered && S.doh.requests.length === 1 && txid === "5555",
    detail: `doh=${JSON.stringify(S.doh.requests)} txid=${txid}`,
  };
}

// Semua endpoint DoH mati: harus ada balasan SERVFAIL supaya klien gagal cepat, bukan diam.
async function scenarioDohServfail(port, dohStub) {
  dohStub.close();
  await sleep(300);
  const { ws, received } = await openWs("/1.2.3.4:5678", port);
  ws.send(frame({ cmd: 2, port: 53, payload: prefixed(dnsQuery(0x6666, "servfail-uji.local")) }));
  const answered = await until(() => received().length > 4, 12000);
  await until(() => false, 300);
  const got = received();
  ws.close();

  const len = got.length >= 4 ? (got[2] << 8) | got[3] : 0;
  const answer = got.subarray(4, 4 + len);
  const qr = answer.length > 2 ? (answer[2] & 0x80) !== 0 : false;
  const rcode = answer.length > 3 ? answer[3] & 0x0f : -1;
  const txid = answer.length >= 2 ? answer.subarray(0, 2).toString("hex") : "";
  return {
    name: "DoH: semua endpoint gagal -> balasan SERVFAIL (tidak menggantung)",
    pass: answered && qr && rcode === 2 && txid === "6666",
    detail: `len=${len} qr=${qr} rcode=${rcode} txid=${txid}`,
  };
}

// Proxy utama mati (tidak ada yang listen di 7307): worker harus pindah ke cadangan dari
// env.FALLBACK_PROXIES dan tetap melayani, bukan menutup koneksi.
async function scenarioFailover() {
  const payload = Buffer.from("PING");
  const before = S.proxy.connectLines.length;
  S.proxy.echoed = false;
  const { ws, received } = await openWs("/127.0.0.1:7307", PORT);
  ws.send(frame({ cmd: 1, host: "example.com", port: 80, payload }));
  const echoed = await until(() => received().length >= 8, 15000);
  const got = received();
  try { ws.close(); } catch {}

  const lines = S.proxy.connectLines.slice(before);
  const viaFallback = lines.some((line) => line.includes("CONNECT example.com:80"));
  const echoOk = got.length >= 4 && got.subarray(0, 4).toString("hex") === "00005566";
  return {
    name: "Failover: proxy utama mati -> cadangan dipakai",
    pass: echoed && echoOk && viaFallback,
    detail: `echo=${echoOk} cadanganConnect=${JSON.stringify(lines)}`,
  };
}

// Kebalikannya: selama proxy utama sehat, cadangan tidak boleh ikut dipakai.
async function scenarioNoFailoverWhenHealthy() {
  const before = S.proxy.connectLines.length;
  const res = await connectTcpViaProxy("/127.0.0.1:7304", 80);
  const lines = S.proxy.connectLines.slice(before);
  return {
    name: "Proxy utama sehat -> cadangan tidak dipakai",
    pass: res.ok && lines.length === 0,
    detail: `echo=${res.ok} connectBaru=${lines.length}`,
  };
}

// NXDOMAIN di-cache singkat: query kedua tidak boleh memanggil DoH lagi dan tetap NXDOMAIN.
async function scenarioDnsNegativeCache() {
  S.doh.requests = [];
  S.doh.answers = 0;
  const name = "nx-cache-uji.local";
  const { ws, received } = await openWs("/1.2.3.4:5678", PORT);

  ws.send(frame({ cmd: 2, port: 53, payload: prefixed(dnsQuery(0x9999, name)) }));
  await until(() => S.doh.answers >= 1 && received().length > 4, 8000);
  await until(() => false, 300);
  const first = received();
  const len1 = first.length >= 4 ? (first[2] << 8) | first[3] : 0;
  // Balasan pertama: header VLESS 2B + len 2B, jadi byte rcode ada di indeks 7.
  const rcode1 = first.length >= 8 ? first[7] & 0x0f : -1;
  const dohAfterFirst = S.doh.requests.length;

  ws.send(frame({ cmd: 2, port: 53, payload: prefixed(dnsQuery(0xaaaa, name)) }));
  await until(() => received().length >= 4 + len1 + 2, 8000);
  await until(() => false, 300);
  const all = received();
  ws.close();

  const second = all.subarray(4 + len1);
  const rcode2 = second.length >= 6 ? second[5] & 0x0f : -1;
  const txid2 = second.length >= 4 ? second.subarray(2, 4).toString("hex") : "";
  const pass = rcode1 === 3 && rcode2 === 3 && dohAfterFirst === 1 && S.doh.requests.length === 1 && txid2 === "aaaa";
  return {
    name: "Cache DNS negatif: NXDOMAIN tidak di-query ulang",
    pass: pass,
    detail: `rcode=${rcode1},${rcode2} doh=${S.doh.requests.length} txid2=${txid2}`,
  };
}

// Worker dengan DNS_CACHE_MODE=cache: cache memori dimatikan, jadi query kedua hanya bisa
// dilayani lapisan Cache API. Kalau Cache API tidak jalan, test ini gagal (2 panggilan DoH).
async function scenarioDnsSharedCache(port) {
  S.doh.requests = [];
  S.doh.answers = 0;
  const name = "shared-cache-uji.local";
  const { ws, received } = await openWs("/1.2.3.4:5678", port);

  ws.send(frame({ cmd: 2, port: 53, payload: prefixed(dnsQuery(0xbbbb, name)) }));
  await until(() => S.doh.answers >= 1 && received().length > 4, 10000);
  await until(() => false, 800); // beri waktu penulisan Cache API selesai
  const first = received();
  const len1 = first.length >= 4 ? (first[2] << 8) | first[3] : 0;

  ws.send(frame({ cmd: 2, port: 53, payload: prefixed(dnsQuery(0xcccc, name)) }));
  await until(() => received().length >= 4 + len1 + 2, 10000);
  await until(() => false, 400);
  const all = received();
  ws.close();

  const second = all.subarray(4 + len1);
  const txid2 = second.length >= 4 ? second.subarray(2, 4).toString("hex") : "";
  return {
    name: "Cache API: query kedua dilayani cache bersama (tanpa DoH)",
    pass: S.doh.requests.length === 1 && txid2 === "cccc",
    detail: `doh=${S.doh.requests.length} txid2=${txid2}`,
  };
}

// Failover dari pool (bukan daftar statis): daftar cadangan diambil dari REST proxy_pool,
// dan koneksi pertama yang gagal harus MENUNGGU daftar itu — bukan menutup lebih dulu.
async function scenarioPoolFailover(port) {
  const payload = Buffer.from("PING");
  S.pool.requests = [];
  S.proxy.echoed = false;
  const before = S.proxy.connectLines.length;
  const { ws, received } = await openWs("/127.0.0.1:7307", port);
  ws.send(frame({ cmd: 1, host: "example.com", port: 80, payload }));
  const echoed = await until(() => received().length >= 8, 15000);
  const got = received();
  try { ws.close(); } catch {}

  const lines = S.proxy.connectLines.slice(before);
  const echoOk = got.length >= 4 && got.subarray(0, 4).toString("hex") === "00005566";
  return {
    name: "Failover pool: daftar proxy_pool ditunggu lalu dipakai",
    pass: echoed && echoOk && lines.length > 0 && S.pool.requests.length >= 1,
    detail: `echo=${echoOk} poolReq=${S.pool.requests.length} cadanganConnect=${JSON.stringify(lines)}`,
  };
}

// Proxy yang handshake-nya sukses tapi tidak pernah mengirim data: watchdog harus menutup
// koneksi (worker dengan IDLE_CLOSE_SECONDS=1), bukan menggantung.
async function scenarioWatchdog(port) {
  const payload = Buffer.from("PING");
  const { ws, received, isClosed } = await openWs("/127.0.0.1:7308", port);
  const started = Date.now();
  ws.send(frame({ cmd: 1, host: "example.com", port: 80, payload }));
  const closed = await until(() => isClosed(), 8000);
  const ms = Date.now() - started;
  const bytes = received().length;
  try { ws.close(); } catch {}
  return {
    name: "Watchdog: target diam -> koneksi ditutup (tidak menggantung)",
    pass: closed && ms < 6000 && bytes <= 2 && S.silent.handshakes >= 1,
    detail: `tertutup=${closed} ${ms}ms data=${bytes}B handshake=${S.silent.handshakes}`,
  };
}

async function scenarioHealth(port) {
  const res = await fetch("http://127.0.0.1:" + port + "/health");
  const body = await res.json();
  const ok = res.status === 200 && body.ok === true && typeof body.fallback_uses === "number" &&
    body.fallback_uses >= 1 && typeof body.dns_mode === "string" && body.dns_hits &&
    typeof body.dns_hits.memory === "number" && typeof body.proxy_memo === "number" &&
    typeof body.version === "string" && body.counters && typeof body.counters.proxyFail === "number" &&
    body.log_emitted && typeof body.log_emitted === "object";
  return { name: "/health melaporkan kondisi isolate", pass: ok, detail: JSON.stringify(body).slice(0, 240) };
}

// Early data lewat query `?ed=` (bukan header): klien tidak mengirim pesan WS apa pun,
// seluruh frame pertama ada di URL.
async function scenarioEarlyDataQuery() {
  S.doh.requests = [];
  S.doh.answers = 0;
  const payload = frame({ cmd: 2, port: 53, payload: prefixed(dnsQuery(0xeded, "ed-uji.local")) });
  const encoded = Buffer.from(payload).toString("base64").replace(/\+/g, "-").replace(/\//g, "_");
  const { ws, received } = await openWs("/1.2.3.4:5678?ed=" + encoded, PORT);

  const answered = await until(() => received().length > 2, 8000);
  await until(() => false, 300);
  const got = received();
  try { ws.close(); } catch {}
  const txid = got.length >= 6 ? got.subarray(4, 6).toString("hex") : "";
  return {
    name: "Early data lewat query ?ed= (tanpa pesan WS)",
    pass: answered && txid === "eded" && S.doh.requests.length === 1,
    detail: `jawaban=${answered} txid=${txid} doh=${S.doh.requests.length}`,
  };
}

// Protokol proxy belum diketahui: SOCKS5 dan HTTP CONNECT jalan bersamaan, jadi proxy
// HTTP-only yang diam terhadap SOCKS5 tidak lagi memakan waktu probe 2,5 detik.
async function scenarioProxyRace() {
  S.race.socksSilent = 0;
  S.race.http = 0;
  S.race.closes = 0;
  S.race.echoed = false;
  const started = Date.now();
  const { ws, received } = await openWs("/127.0.0.1:7311", PORT);
  ws.send(frame({ cmd: 1, host: "example.com", port: 80, payload: Buffer.from("PING") }));
  const echoed = await until(() => received().length >= 8, 8000);
  const ms = Date.now() - started;
  try { ws.close(); } catch {}
  await until(() => false, 300);

  const fast = ms < 2200; // berurutan: minimal 2,5 s (probe SOCKS5) sebelum fallback
  return {
    name: "Protokol belum diketahui: SOCKS5 & HTTP dicoba paralel",
    pass: echoed && S.race.socksSilent >= 1 && S.race.http >= 1 && fast,
    detail: `echo=${echoed} ${ms}ms socks5Diam=${S.race.socksSilent} httpConnect=${S.race.http} soketKalahDitutup=${S.race.closes}`,
  };
}

// Batching socket->WS: 20 potongan 256 B dari target dikirim sebagai berapa pesan WS?
async function scenarioBatching(port, expectBatched) {
  S.stream.chunks = 0;
  S.race.echoed = false;
  const { ws, received, messages } = await openWs("/127.0.0.1:7312", port);
  ws.send(frame({ cmd: 1, host: "example.com", port: 80, payload: Buffer.from("PING") }));
  const total = 2 + 20 * 256; // header VLESS 2 B + 20 potongan
  await until(() => received().length >= total, 8000);
  await until(() => false, 400);
  const bytes = received().length;
  const count = messages();
  try { ws.close(); } catch {}

  // Ambang absolut (count >= 15) rapuh: workerd boleh menggabungkan beberapa tulis 1 ms jadi
  // satu read, jadi jumlah pesan WS bisa kecil di kedua worker. Yang deterministik adalah
  // arahnya - batching hanya bisa MENGGABUNG pesan, tidak menambah - jadi worker yang batching
  // mati tidak boleh mengirim lebih sedikit pesan daripada worker yang batching hidup.
  const pass = bytes === total && (expectBatched ? count <= 14 : count >= Math.max(2, S.batchOnCount || 0));
  if (expectBatched) S.batchOnCount = count;
  return {
    name: expectBatched ? "Batching WS aktif: potongan digabung" : "Batching dimatikan (WS_BATCH_MS=0): satu pesan per potongan (pembanding)",
    pass: pass,
    detail: `pesan=${count} byte=${bytes} (harap ${total})`,
  };
}

// Log dibatasi: tiga kejadian berturut-turut harus menghasilkan SATU baris log; hitungannya
// bisa dilihat di /health (counters vs log_emitted), jadi tidak perlu membaca stdout worker.
async function scenarioLogGate(port) {
  for (let i = 0; i < 3; i++) {
    const { ws, isClosed } = await openWs("/127.0.0.1:7302", port);
    ws.send(frame({ cmd: 2, port: 4444, payload: Buffer.from([1, 2, 3, 4]) }));
    await until(() => isClosed(), 3000);
    try { ws.close(); } catch {}
  }
  await sleep(300);

  const health = await (await fetch("http://127.0.0.1:" + port + "/health")).json();
  const seen = health.counters ? health.counters.udpUnsupported : -1;
  const emitted = health.log_emitted ? health.log_emitted.udpUnsupported : -1;
  return {
    name: "Log dibatasi: 3 kejadian -> 1 baris log (counter tetap 3)",
    pass: seen >= 3 && emitted === 1,
    detail: `kejadian=${seen} barisLog=${emitted} versi=${health.version}`,
  };
}

// Mux (cmd=3): header VLESS tanpa alamat, lalu frame New/Keep/End; tiap sub-koneksi punya
// tunnel sendiri ke proxy.
async function scenarioMux(port) {
  const payload = Buffer.from("PING");
  S.proxy.echoed = false;
  const closesBefore = S.proxy.closes;
  const { ws, received } = await openWs("/127.0.0.1:7302", port);
  ws.send(Buffer.concat([muxVlessHeader(), muxFrameNew(1, "example.com", 80, payload)]));

  const gotKeep = await until(() => {
    const parsed = parseMuxFrames(received().subarray(2));
    return parsed.frames.some((frame) => frame.status === 2 && frame.data.length >= 6);
  }, 8000);
  const all = received();
  const headerOk = all.length >= 2 && all[0] === 0x00 && all[1] === 0x00;
  const frames = parseMuxFrames(all.subarray(2)).frames;
  const keep = frames.find((frame) => frame.status === 2);
  const dataOk = !!keep && keep.id === 1 && keep.data.subarray(0, 2).toString("hex") === "5566" &&
    keep.data.subarray(2).toString("utf8") === "PING";

  ws.send(muxFrameEnd(1));
  const closed = await until(() => S.proxy.closes > closesBefore, 3000);

  // Sesi kedua di koneksi mux yang SAMA: klien Xray membuka koneksi utama sekali lalu
  // memakainya untuk banyak permintaan, jadi ini jalur yang paling sering dipakai.
  S.proxy.echoed = false;
  const beforeSecond = received().length;
  ws.send(muxFrameNew(2, "example.com", 80, Buffer.from("PING2")));
  const secondOk = await until(() => {
    const parsed = parseMuxFrames(received().subarray(2));
    return parsed.frames.some((frame) => frame.id === 2 && frame.status === 2 && frame.data.length >= 7);
  }, 8000);
  const frames2 = parseMuxFrames(received().subarray(2)).frames.filter((frame) => frame.id === 2);
  const secondData = frames2.find((frame) => frame.status === 2);
  const secondDataOk = !!secondData && secondData.data.subarray(0, 2).toString("hex") === "5566" &&
    secondData.data.subarray(2).toString("utf8") === "PING2";
  ws.send(muxFrameEnd(2));
  try { ws.close(); } catch {}

  return {
    name: "Mux (cmd=3): frame New/Keep/End diteruskan lewat proxy",
    pass: gotKeep && headerOk && dataOk && closed && secondOk && secondDataOk,
    detail: `keep=${gotKeep} header=${headerOk} data=${dataOk} soketDitutup=${closed} sesi2=${secondOk} data2=${secondDataOk} frames=${JSON.stringify(frames.map((f) => ({ id: f.id, status: f.status, len: f.data.length })))}`,
  };
}

// --- klien mux.cool minimal (untuk regresi lokal jalur mux) ------------------------------
// Header VLESS cmd=3 tanpa alamat, lalu frame: [2B metaLen][meta][2B dataLen][data].
function muxVlessHeader() {
  return Buffer.concat([Buffer.from([0x00]), Buffer.from(UUID_HEX, "hex"), Buffer.from([0x00, 0x03])]);
}

function muxFrameNew(id, host, port, data) {
  const hostBytes = Buffer.from(host, "utf8");
  const meta = Buffer.concat([
    Buffer.from([(id >> 8) & 0xff, id & 0xff, 0x01, 0x01, 0x01, (port >> 8) & 0xff, port & 0xff, 0x02, hostBytes.length]),
    hostBytes,
  ]);
  return Buffer.concat([
    Buffer.from([(meta.length >> 8) & 0xff, meta.length & 0xff]),
    meta,
    Buffer.from([(data.length >> 8) & 0xff, data.length & 0xff]),
    data,
  ]);
}

function muxFrameKeep(id, data) {
  const meta = Buffer.from([(id >> 8) & 0xff, id & 0xff, 0x02, 0x01]);
  return Buffer.concat([
    Buffer.from([(meta.length >> 8) & 0xff, meta.length & 0xff]),
    meta,
    Buffer.from([(data.length >> 8) & 0xff, data.length & 0xff]),
    data,
  ]);
}

function muxFrameEnd(id) {
  const meta = Buffer.from([(id >> 8) & 0xff, id & 0xff, 0x03, 0x00]);
  return Buffer.concat([Buffer.from([0x00, 0x04]), meta]);
}

// Urai frame mux dari buffer (kembalikan daftar frame + sisa byte).
function parseMuxFrames(buf) {
  const frames = [];
  let offset = 0;
  while (buf.length - offset >= 2) {
    const metaLen = (buf[offset] << 8) | buf[offset + 1];
    if (metaLen < 4 || metaLen > 512 || buf.length - offset < 2 + metaLen) break;
    const meta = buf.subarray(offset + 2, offset + 2 + metaLen);
    const frame = { id: (meta[0] << 8) | meta[1], status: meta[2], opt: meta[3], data: Buffer.alloc(0) };
    let consumed = 2 + metaLen;
    if (frame.opt & 0x01) {
      if (buf.length - offset < consumed + 2) break;
      const dataLen = (buf[offset + consumed] << 8) | buf[offset + consumed + 1];
      if (buf.length - offset < consumed + 2 + dataLen) break;
      frame.data = buf.subarray(offset + consumed + 2, offset + consumed + 2 + dataLen);
      consumed += 2 + dataLen;
    }
    frames.push(frame);
    offset += consumed;
  }
  return { frames: frames, rest: buf.subarray(offset) };
}

// UDP non-DNS lewat relay: worker -> relay (TCP) -> UDP echo -> balik lagi sebagai datagram VLESS.
async function scenarioUdpRelay(port, relayLog) {
  S.udp.messages = 0;
  S.udp.last = "";
  const payload = Buffer.from("PINGUDP");
  const datagram = prefixed(payload);
  const { ws, received } = await openWs("/127.0.0.1:7302", port);
  ws.send(frame({ cmd: 2, host: "127.0.0.1", port: 7314, payload: datagram }));

  const answered = await until(() => {
    const got = received();
    if (got.length < 4) return false;
    const len = (got[2] << 8) | got[3];
    return got.length >= 4 + len;
  }, 10000);
  await until(() => false, 300);
  const got = received();
  const len = got.length >= 4 ? (got[2] << 8) | got[3] : 0;
  const answer = got.subarray(4, 4 + len).toString("utf8");
  try { ws.close(); } catch {}

  const headerOk = got.length >= 2 && got[0] === 0x00 && got[1] === 0x00;
  const health = await (await fetch("http://127.0.0.1:" + port + "/health")).json().catch(() => ({}));
  return {
    name: "UDP non-DNS lewat relay (worker -> relay TCP -> UDP)",
    pass: answered && headerOk && answer === "UDP:PINGUDP" && S.udp.messages >= 1,
    detail: `jawaban=${JSON.stringify(answer)} header=${headerOk} udpEcho=${S.udp.messages} counters=${JSON.stringify(health.counters)} logRelay=${JSON.stringify((relayLog() || "").slice(-200))}`,
  };
}

// Tier Free: `udpRelayConfig(env)` langsung `return null`, jadi binding RELAY_SERVER_UDP
// diabaikan walau ada. UDP non-DNS harus ditutup cepat TANPA satu pun lalu lintas relay —
// pembandingnya skenario prem di atas, yang memang mengirim header relay dan dicatat relay
// lewat baris "sesi ... -> <alamat>:<port>".
async function scenarioFreeTierRelayBlocked(port, relayLog) {
  const logBefore = relayLog() || "";
  S.udp.messages = 0;
  S.udp.last = "";
  const payload = Buffer.from("PINGUDP");
  const { ws, received, isClosed } = await openWs("/127.0.0.1:7302", port);
  ws.send(frame({ cmd: 2, host: "127.0.0.1", port: 5353, payload: prefixed(payload) }));
  const closed = await until(() => isClosed(), 5000);
  await until(() => false, 400); // beri jendela kalau balasan menyusul
  const got = received();
  const udpEcho = S.udp.messages;
  try { ws.close(); } catch {}

  const penuh = relayLog() || "";
  const delta = penuh.slice(logBefore.length);
  // Header relay berisi "udp 127.0.0.1 5353 <rahasia>", dan sesi sukses tercatat sebagai
  // "-> 127.0.0.1:5353". Keduanya tidak boleh muncul — di delta maupun di seluruh log.
  const relayMenyentuh = /127\.0\.0\.1:5353/.test(penuh);
  const premSesi7314 = /-> 127\.0\.0\.1:7314/.test(penuh);
  const health = await (await fetch("http://127.0.0.1:" + port + "/health")).json().catch(() => ({}));
  const counters = (health && health.counters) || {};
  return {
    name: "Tier Free: relay UDP diabaikan, UDP non-DNS ditutup tanpa lalu lintas relay",
    pass:
      closed &&
      got.length === 0 &&
      udpEcho === 0 &&
      !relayMenyentuh &&
      premSesi7314 &&
      counters.udpUnsupported >= 1 &&
      !counters.udpRelayUsed,
    detail:
      `wsTertutup=${closed} byteBalasan=${got.length} udpEcho=${udpEcho} ` +
      `relaySentuh5353=${relayMenyentuh} premKirimHeaderRelay=${premSesi7314} ` +
      `counters=${JSON.stringify({ udpUnsupported: counters.udpUnsupported, udpRelayUsed: counters.udpRelayUsed })} ` +
      `deltaLogRelay=${JSON.stringify(delta.slice(-200))}`,
  };
}

// Path ajaib "/rotate": worker memilih proxy sendiri (daftar statis FALLBACK_PROXIES).
async function scenarioRotateStatic(port) {
  const payload = Buffer.from("PING");
  S.proxy.echoed = false;
  const before = S.proxy.connectLines.length;
  const { ws, received } = await openWs("/rotate", port);
  ws.send(frame({ cmd: 1, host: "example.com", port: 80, payload }));
  const echoed = await until(() => received().length >= 8, 10000);
  const got = received();
  try { ws.close(); } catch {}
  const lines = S.proxy.connectLines.slice(before);
  const echoOk = got.length >= 4 && got.subarray(0, 4).toString("hex") === "00005566";
  const health = await (await fetch("http://127.0.0.1:" + port + "/health")).json().catch(() => ({}));
  const used = health.counters ? health.counters.rotateUsed : -1;
  return {
    name: "Path /rotate: worker memilih proxy sendiri (daftar statis)",
    pass: echoed && echoOk && used >= 1,
    detail: `echo=${echoOk} rotateUsed=${used} connect=${JSON.stringify(lines)}`,
  };
}

// Path ajaib "/rotate" dengan pool panel (REST proxy_pool palsu di 7309).
async function scenarioRotatePool(port) {
  const payload = Buffer.from("PING");
  S.pool.requests = [];
  S.proxy.echoed = false;
  const { ws, received } = await openWs("/ALL", port);
  ws.send(frame({ cmd: 1, host: "example.com", port: 80, payload }));
  const echoed = await until(() => received().length >= 8, 10000);
  const got = received();
  try { ws.close(); } catch {}
  const echoOk = got.length >= 4 && got.subarray(0, 4).toString("hex") === "00005566";
  const health = await (await fetch("http://127.0.0.1:" + port + "/health")).json().catch(() => ({}));
  const used = health.counters ? health.counters.rotateUsed : -1;
  const paths = Array.isArray(health.rotate_paths) ? health.rotate_paths.join(",") : "";
  // Worker ini tidak punya FALLBACK_PROXIES, jadi echo yang sukses membuktikan proxy datang
  // dari pool. Jumlah request REST tidak diwajibkan: daftarnya di-cache 120 detik per isolate.
  return {
    name: "Path /ALL (=/rotate): proxy diambil dari pool panel",
    pass: echoed && echoOk && used >= 1 && paths.includes("rotate"),
    detail: `echo=${echoOk} rotateUsed=${used} poolReq=${S.pool.requests.length} paths=${paths}`,
  };
}

// Path "/SG": pool difilter negara, jadi proxy yang dipakai harus berasal dari baris SG
// (stub pool mengembalikan 7306 untuk country=in.(SG); tanpa filter negara 7316 lalu 7302).
async function scenarioRotateCountry(port) {
  const payload = Buffer.from("PING");
  S.pool.requests = [];
  S.proxy.byPort = {};
  S.proxy.echoed = false;
  const { ws, received } = await openWs("/SG", port);
  ws.send(frame({ cmd: 1, host: "example.com", port: 80, payload }));
  const echoed = await until(() => received().length >= 8, 12000);
  const got = received();
  try { ws.close(); } catch {}

  const echoOk = got.length >= 4 && got.subarray(0, 4).toString("hex") === "00005566";
  const health = await (await fetch("http://127.0.0.1:" + port + "/health")).json().catch(() => ({}));
  const used = health.counters ? health.counters.rotateUsed : -1;
  const sgUsed = (S.proxy.byPort[7306] || 0) >= 1;
  const query = S.pool.requests.find((url) => /country=in\.\(SG\)/.test(url || "")) || "";
  return {
    name: "Path /SG: pool difilter negara (country=in.(SG))",
    pass: echoed && echoOk && used >= 1 && sgUsed && !!query,
    detail: `echo=${echoOk} rotateUsed=${used} byPort=${JSON.stringify(S.proxy.byPort)} query=${JSON.stringify(String(query).slice(0, 110))}`,
  };
}

// Path "/XX": pool tidak punya baris XX, dan daftar statis tidak boleh dipakai untuk selector
// negara -> worker harus gagal-tertutup (tidak ada data sama sekali), bukan menyambung lewat
// proxy negara lain. byPort harus tetap kosong: tidak ada tipe proxy yang dihubungi.
async function scenarioCountryClosed(port) {
  const payload = Buffer.from("PING");
  S.pool.requests = [];
  S.proxy.byPort = {};
  S.proxy.echoed = false;
  const healthOf = async () => await (await fetch("http://127.0.0.1:" + port + "/health")).json().catch(() => ({}));
  const before = await healthOf();
  const { ws, received } = await openWs("/XX", port);
  ws.send(frame({ cmd: 1, host: "example.com", port: 80, payload }));
  const echoed = await until(() => received().length > 0, 6000);
  const got = received();
  try { ws.close(); } catch {}
  const after = await healthOf();

  const delta = (key) => Number((after.counters || {})[key] || 0) - Number((before.counters || {})[key] || 0);
  const empty = delta("rotateEmpty");
  const used = delta("rotateUsed");
  const touched = Object.keys(S.proxy.byPort).length;
  const query = S.pool.requests.find((u) => /country=in\.\(XX\)/.test(u || "")) || "";
  return {
    name: "Path /XX: selector negara gagal-tertutup (tanpa cadangan lintas negara)",
    pass: !echoed && got.length === 0 && empty >= 1 && used === 0 && touched === 0 && !!query,
    detail: `echo=${echoed} bytes=${got.length} rotateEmpty=+${empty} rotateUsed=+${used} proxyDihubungi=${touched} query=${JSON.stringify(String(query).slice(0, 90))}`,
  };
}

// Kolom bukti (`tunnel_ok` dari edge, `tls_ok` dan `tunnel_host_ok` dari host scanner)
// ditambahkan ke tabel proxy_pool lewat SQL manual, jadi worker harus tetap hidup saat kolomnya
// BELUM ada: stub pool membalas 400 setiap query yang menyebut kolom hilang dan hanya menjawab
// urutan yang lebih tua. Worker harus tetap mendapat daftar proxy (echo jalan), lalu MENGINGAT
// urutan yang diterima sehingga pengambilan pool berikutnya tidak lagi membayar percobaan yang
// sudah terbukti gagal.
//
// Empat skenario di bawah memakai satu runner: fase 1 memakai kunci cache "all" yang masih
// perawan di isolate itu (jadi rantai urutan benar-benar disusuri dari atas), fase 2 memakai
// kunci negara "SG" sehingga bukan cache pool — yang diuji di sana adalah INGATAN isolate
// (langsung urutan yang sudah diterima, tanpa 400 lagi). Urutan pool tidak pernah menggagalkan
// pengambilan pool: echo di kedua fase adalah buktinya.
// Urutan query dibaca dari pencatatan stub, bukan dari log worker: regex diberi anchor `&`/akhir
// supaya urutan 1 tidak ikut terhitung sebagai urutan 2/3 (semuanya memuat "ping").
const POOL_TIER_ORDERS = [
  /order=tunnel_ok\.desc\.nullslast,tls_ok\.desc\.nullslast,tunnel_host_ok\.desc\.nullslast,ping\.asc\.nullslast(&|$)/,
  /order=tunnel_ok\.desc\.nullslast,tls_ok\.desc\.nullslast,ping\.asc\.nullslast(&|$)/,
  /order=tunnel_ok\.desc\.nullslast,ping\.asc\.nullslast(&|$)/,
  /order=ping\.asc\.nullslast(&|$)/,
];

// Indeks urutan (0..3 = urutan 1..4 di worker) untuk tiap query pool yang dicatat stub.
// -1 = tidak dikenali, jadi perbandingan urutan pasti gagal (bukan lolos diam-diam).
function poolOrderTiers(urls) {
  return (urls || []).map((url) => POOL_TIER_ORDERS.findIndex((re) => re.test(String(url || ""))));
}

function sameNumbers(left, right) {
  return left.length === right.length && left.every((value, i) => value === right[i]);
}

// expectTier: indeks urutan yang HARUS diterima (0 = urutan 1 empat tingkat, 3 = ping saja).
async function scenarioPoolOrder(port, name, expectTier) {
  const payload = Buffer.from("PING");
  const connectOnce = async (selector) => {
    S.proxy.echoed = false;
    const { ws, received } = await openWs(selector, port);
    ws.send(frame({ cmd: 1, host: "example.com", port: 80, payload }));
    const echoed = await until(() => received().length >= 8, 12000);
    const got = received();
    try { ws.close(); } catch {}
    return echoed && got.length >= 4 && got.subarray(0, 4).toString("hex") === "00005566";
  };
  const healthOf = async () => await (await fetch("http://127.0.0.1:" + port + "/health")).json().catch(() => ({}));
  const before = await healthOf();

  // Fase 1: urutan 1..expectTier+1 harus dicoba BERURUTAN, ditolak sebanyak expectTier, lalu
  // urutan expectTier+1 diterima.
  S.pool.requests = [];
  const rejectedBefore = S.pool.orderRejected;
  const allEcho = await connectOnce("/ALL");
  const allTiers = poolOrderTiers(S.pool.requests);
  const allRejected = S.pool.orderRejected - rejectedBefore;
  const mid = await healthOf();

  // Fase 2: kunci baru (/SG) -> langsung urutan yang sudah diingat, tanpa satu pun 400.
  S.pool.requests = [];
  const sgEcho = await connectOnce("/SG");
  const sgTiers = poolOrderTiers(S.pool.requests);

  const after = await healthOf();
  // counters.poolOrder naik sekali untuk tiap urutan yang ditolak (lewat gate log) + sekali saat
  // akhirnya turun ke urutan yang lebih tua; urutan 1 yang langsung diterima tidak menaikkannya.
  const order = (snap) => Number((snap.counters || {}).poolOrder || 0);
  const fase1Memo = order(mid) - order(before);
  const fase2Memo = order(after) - order(mid);
  const used = after.counters ? after.counters.rotateUsed : -1;
  const expectSteps = Array.from({ length: expectTier + 1 }, (_, i) => i);
  const expectMemo = expectTier === 0 ? 0 : expectTier + 1;
  return {
    name: name,
    pass: allEcho && sgEcho && sameNumbers(allTiers, expectSteps) && allRejected === expectTier &&
      sameNumbers(sgTiers, [expectTier]) && fase1Memo === expectMemo && fase2Memo === 0 &&
      used >= 2,
    detail: `echo=${allEcho},${sgEcho} rotateUsed=${used} poolOrder fase1=+${fase1Memo}` +
      `(harap +${expectMemo}) fase2=+${fase2Memo} ` +
      `fase1(/ALL): urutan=${JSON.stringify(allTiers)} harap ${JSON.stringify(expectSteps)} ` +
      `ditolak=${allRejected} · fase2(/SG): urutan=${JSON.stringify(sgTiers)} harap [${expectTier}] ` +
      `poolCache=${JSON.stringify(after.pool_cache)}`,
  };
}

// 23h: skema terbaru — ketiga kolom bukti ada (`tunnel_host_ok` sudah ditambahkan lewat SQL
// manusia). Urutan 1 (empat tingkat) harus dipakai sejak pengambilan pool pertama, tanpa 400.
async function scenarioPoolOrderComplete(port) {
  return await scenarioPoolOrder(port,
    "Pool: semua kolom bukti ada -> urutan 1 (tunnel_ok,tls_ok,tunnel_host_ok,ping) dipakai", 0);
}

// 23i: `tunnel_host_ok` (bukti tunnel dari host scanner) BELUM ada, `tunnel_ok` dan `tls_ok`
// sudah. Worker harus mendarat di urutan 2 (tunnel_ok + tls_ok + ping): dua bukti terkuat tetap
// dipakai mengurutkan, tidak kehilangan pool dan tidak turun ke ping saja.
async function scenarioPoolOrderHostMissing(port) {
  return await scenarioPoolOrder(port,
    "Pool: tunnel_host_ok belum ada (400) -> urutan 2 (tunnel_ok,tls_ok,ping) dipakai lalu diingat", 1);
}

// 23j: `tls_ok` dan `tunnel_host_ok` BELUM ada (skema sebelum host scanner mengisi keduanya):
// urutan 1 dan 2 ditolak 400, worker mendarat di urutan 3 (tunnel_ok + ping). Bukti edge tetap
// dipakai mengurutkan — bukan turun sampai ping saja.
async function scenarioPoolOrderTlsMissing(port) {
  return await scenarioPoolOrder(port,
    "Pool: tls_ok & tunnel_host_ok belum ada (400) -> urutan 3 (tunnel_ok,ping) dipakai lalu diingat", 2);
}

// 23e: skema terlama — KETIGA kolom bukti belum ada (bawaan stub): urutan 1, 2, dan 3 ditolak
// 400, worker mendarat di urutan 4 (ping) dan tetap mendapat daftar proxy.
async function scenarioPoolOrderFallback(port) {
  return await scenarioPoolOrder(port,
    "Pool: semua kolom bukti belum ada (400) -> urutan 4 (ping) dipakai lalu diingat", 3);
}

// "Tercepat dulu": stub pool (tabel "proxy_pool") mengembalikan 7316 sebagai baris PERTAMA lalu
// 7302. Worker rotate harus memakai baris pertama itu — proxy yang lebih lambat di daftar tidak
// boleh disentuh selama yang teratas sehat. Buktinya hitungan per porta (byPort) + echo yang
// tetap jalan lewat HTTP CONNECT (connectLines mencatat "CONNECT ... HTTP/1.1").
async function scenarioRotateFastestFirst(port) {
  const payload = Buffer.from("PING");
  const healthOf = async () => await (await fetch("http://127.0.0.1:" + port + "/health")).json().catch(() => ({}));
  S.proxy.byPort = {};
  S.proxy.echoed = false;
  const linesBefore = S.proxy.connectLines.length;
  const before = await healthOf();
  const { ws, received } = await openWs("/ALL", port);
  ws.send(frame({ cmd: 1, host: "example.com", port: 80, payload }));
  const echoed = await until(() => received().length >= 8, 12000);
  const got = received();
  try { ws.close(); } catch {}
  const after = await healthOf();

  const delta = (key) => Number((after.counters || {})[key] || 0) - Number((before.counters || {})[key] || 0);
  const echoOk = got.length >= 4 && got.subarray(0, 4).toString("hex") === "00005566";
  const used = delta("rotateUsed");
  const fastest = S.proxy.byPort[POOL_FAST_PORT] || 0; // baris pertama: harus dipakai
  const second = S.proxy.byPort[7302] || 0; // baris kedua: 0 selama yang teratas sehat
  const lines = S.proxy.connectLines.slice(linesBefore);
  const httpLine = lines.some((line) => /^CONNECT .* HTTP\/1\./.test(line));
  return {
    name: "Pool tercepat dulu: /ALL memakai baris pertama (7316), baris kedua (7302) tidak disentuh",
    pass: echoed && echoOk && used >= 1 && fastest >= 1 && second === 0 && httpLine,
    detail: `echo=${echoOk} rotateUsed=+${used} byPort=${JSON.stringify(S.proxy.byPort)} connect=${JSON.stringify(lines)}`,
  };
}

// Jalur cadangan tidak hilang karena "tercepat dulu": worker ini memakai tabel pool terpisah
// ("proxy_pool_dead_first") yang baris PERTAMAnya mati (127.0.0.1:7307 — tidak ada pendengar),
// baris kedua 7302 hidup. Echo yang sukses lewat 7302 membuktikan kandidat berikutnya dari
// daftar yang sama tetap dicoba. Worker terpisah = isolate dan cache pool (kunci "all") bersih:
// daftar pertama yang dilihatnya memang baris mati di depan, bukan daftar dari skenario lain.
async function scenarioRotateFastestFailover(port) {
  const payload = Buffer.from("PING");
  const healthOf = async () => await (await fetch("http://127.0.0.1:" + port + "/health")).json().catch(() => ({}));
  S.proxy.byPort = {};
  S.proxy.echoed = false;
  const linesBefore = S.proxy.connectLines.length;
  const before = await healthOf();
  const { ws, received } = await openWs("/ALL", port);
  ws.send(frame({ cmd: 1, host: "example.com", port: 80, payload }));
  const echoed = await until(() => received().length >= 8, 15000);
  const got = received();
  // Kandidat pertama (mati) bisa baru menyerah setelah timeout probe-nya (greeting SOCKS5
  // 2500 ms, jalur HTTP sampai PROXY_HANDSHAKE_TIMEOUT), jadi counter proxyFail tidak muncul
  // seketika — jalur cadangan (hedge) biasanya menang lebih dulu. Tunggu di situ selama WS
  // masih terbuka supaya percobaan yang menggantung itu tidak dibatalkan oleh penutupan klien.
  const baseFail = Number((before.counters || {}).proxyFail || 0);
  let after = await healthOf();
  for (let i = 0; i < 56 && Number((after.counters || {}).proxyFail || 0) <= baseFail; i++) {
    await sleep(250);
    after = await healthOf();
  }
  try { ws.close(); } catch {}

  const delta = (key) => Number((after.counters || {})[key] || 0) - Number((before.counters || {})[key] || 0);
  const echoOk = got.length >= 4 && got.subarray(0, 4).toString("hex") === "00005566";
  const used = delta("rotateUsed");
  const failed = delta("proxyFail"); // kandidat pertama (mati) memang dicoba lalu gagal
  const fallbackUsed = Number(after.fallback_uses || 0) - Number(before.fallback_uses || 0);
  const second = S.proxy.byPort[7302] || 0; // kandidat kedua: jalur yang harus dipakai
  const notInList = S.proxy.byPort[POOL_FAST_PORT] || 0; // 7316 bukan bagian tabel ini -> tetap 0
  const dead = S.proxy.byPort[POOL_DEAD_PORT] || 0; // port mati tidak punya stub -> tetap 0
  const lines = S.proxy.connectLines.slice(linesBefore);
  const httpLine = lines.some((line) => /^CONNECT .* HTTP\/1\./.test(line));
  return {
    name: "Pool tercepat gagal: kandidat pertama mati -> echo tetap lewat kandidat kedua (7302)",
    pass: echoed && echoOk && used >= 1 && second >= 1 && notInList === 0 && dead === 0 &&
      failed >= 1 && fallbackUsed >= 1 && httpLine,
    detail: `echo=${echoOk} rotateUsed=+${used} proxyFail=+${failed} fallback_uses=+${fallbackUsed} ` +
      `byPort=${JSON.stringify(S.proxy.byPort)} connect=${JSON.stringify(lines)}`,
  };
}

// Gerbang /health: dengan env.HEALTH_TOKEN, /health menutup hitungan internal kecuali token
// dikirim lewat ?token= atau header x-health-token. Tanpa env, endpoint tetap terbuka (uji lain
// memakainya bebas).
async function scenarioHealthToken(port, token) {
  const statusOf = async (path, headers) => {
    const res = await fetch("http://127.0.0.1:" + port + path, { headers: headers || {} });
    return { status: res.status, body: await res.text().catch(() => "") };
  };
  const closed = await statusOf("/health");
  const viaQuery = await statusOf("/health?token=" + encodeURIComponent(token));
  const viaHeader = await statusOf("/health", { "x-health-token": token });
  const wrong = await statusOf("/health?token=salah");
  const myip = await statusOf("/myip");
  let parsed = {};
  try { parsed = JSON.parse(viaQuery.body); } catch {}
  const pass = closed.status === 401 && wrong.status === 401
    && viaQuery.status === 200 && viaHeader.status === 200
    && parsed && parsed.ok === true && myip.status === 200;
  return {
    name: "Gerbang /health: mati tanpa HEALTH_TOKEN, 401 tanpa token, 200 dengan token",
    detail: "closed=" + closed.status + " salah=" + wrong.status + " query=" + viaQuery.status
      + " header=" + viaHeader.status + " myip=" + myip.status + " ok=" + Boolean(parsed && parsed.ok === true),
    pass,
  };
}

function tierCheck() {
  const prem = fs.readFileSync(SOURCE, "utf8").split("\n");
  const free = fs.readFileSync(SOURCE_FREE, "utf8").split("\n");
  const beda = prem.filter((line, i) => line !== free[i]);
  const hanyaKonstanta = beda.length === 1 && /^const TIER_FREE = /.test(beda[0]);
  return {
    name: "vpn-worker-free.js = turunan prem (beda hanya konstanta TIER_FREE)",
    pass: hanyaKonstanta,
    detail: "beda=" + beda.length + " " + JSON.stringify(beda.slice(0, 3)),
  };
}

const stubs = [];
const results = [];
const workdirs = [];
const workers = [];

try {
  if (!fs.existsSync(WRANGLER)) throw new Error(`wrangler tidak ada di ${WRANGLER} — jalankan npm install dulu`);
  const dohStub = await startDoh();
  const udpEcho = await startUdpEcho();
  const relay = startRelay();
  stubs.push(await startRaw(), await startProxy(), await startProxy(7306), await startProxy(POOL_FAST_PORT), await startSocks(), await startSilentProxy(), await startRaceProxy(), await startStreamProxy(), await startPoolStub(), udpEcho, dohStub);

  workdirs.push(fs.mkdtempSync(path.join(os.tmpdir(), "vpn-smoke-")));
  makeFixture(workdirs[0], {
    DOH_ENDPOINT: "http://127.0.0.1:7303/dns-query",
    UUID_ALLOWLIST: UUID_HEX, // semua frame uji memakai UUID ini; skenario negatif pakai UUID lain
    FALLBACK_PROXIES: "127.0.0.1:7302", // failover diuji tanpa menyentuh Supabase
    FALLBACK_POOL: "off",
  });
  reset();
  workers.push(startWorker(workdirs[0], PORT));

  if (!(await waitPort(PORT, 120000))) {
    throw new Error("wrangler dev tidak siap pada port " + PORT + "\n" + workers[0].getOut().slice(-1500));
  }

  results.push(await scenarioDns("prefixed"));
  results.push(await scenarioDns("raw"));
  results.push(await scenarioDns("split"));
  results.push(await scenarioDns("two"));
  results.push(await scenarioUdpOtherPort());
  results.push(await scenarioTcp());
  results.push(await scenarioRemoteClose());
  results.push(await scenarioSocks5Numeric());
  results.push(await scenarioHttpConnectIpv6());
  results.push(await scenarioDnsCache());
  results.push(await scenarioProxyProtocolMemo());
  results.push(await scenarioDnsCoalesce());
  results.push(await scenarioUuidBlocked());
  results.push(await scenarioRotateStatic(PORT));
  results.push(await scenarioFailover());
  results.push(await scenarioNoFailoverWhenHealthy());
  results.push(await scenarioDnsNegativeCache());
  results.push(await scenarioEarlyDataQuery());
  results.push(await scenarioProxyRace());
  results.push(await scenarioBatching(PORT, true));
  results.push(await scenarioMux(PORT));
  results.push(await scenarioHealth(PORT));

  // Worker kedua: endpoint DoH utama sengaja mati supaya jalur fallback dan SERVFAIL teruji,
  // dan cache DNS memori dimatikan supaya lapisan Cache API benar-benar terpakai.
  workdirs.push(fs.mkdtempSync(path.join(os.tmpdir(), "vpn-smoke-doh-")));
  makeFixture(workdirs[1], {
    DOH_ENDPOINT: "http://127.0.0.1:7305/dns-query",
    DOH_FALLBACK: "http://127.0.0.1:7303/dns-query",
    DNS_CACHE_MODE: "cache",
    FALLBACK_POOL: "off",
  });
  workers.push(startWorker(workdirs[1], PORT_DOH));
  if (!(await waitPort(PORT_DOH, 120000))) {
    throw new Error("wrangler dev (uji DoH) tidak siap pada port " + PORT_DOH + "\n" + workers[1].getOut().slice(-1500));
  }
  results.push(await scenarioDnsSharedCache(PORT_DOH));
  results.push(await scenarioDohFallback(PORT_DOH));
  results.push(await scenarioDohServfail(PORT_DOH, dohStub));

  // Worker ketiga: watchdog idle diuji dengan IDLE_CLOSE_SECONDS=1 (klien default 180 detik,
  // jadi skenario lain tidak terpengaruh).
  workdirs.push(fs.mkdtempSync(path.join(os.tmpdir(), "vpn-smoke-idle-")));
  makeFixture(workdirs[2], {
    DOH_ENDPOINT: "http://127.0.0.1:7303/dns-query",
    IDLE_CLOSE_SECONDS: "1",
    WS_BATCH_MS: "0", // dipakai pembanding uji batching
    FALLBACK_POOL: "off",
  });
  workers.push(startWorker(workdirs[2], PORT_IDLE));
  if (!(await waitPort(PORT_IDLE, 120000))) {
    throw new Error("wrangler dev (uji watchdog) tidak siap pada port " + PORT_IDLE + "\n" + workers[2].getOut().slice(-1500));
  }
  results.push(await scenarioWatchdog(PORT_IDLE));
  results.push(await scenarioBatching(PORT_IDLE, false));
  results.push(await scenarioLogGate(PORT_IDLE));

  // Worker keempat: failover dari pool (REST proxy_pool palsu di 7309, tanpa daftar statis).
  workdirs.push(fs.mkdtempSync(path.join(os.tmpdir(), "vpn-smoke-pool-")));
  makeFixture(workdirs[3], {
    DOH_ENDPOINT: "http://127.0.0.1:7303/dns-query",
    FALLBACK_POOL: "on",
    FALLBACK_POOL_URL: "http://127.0.0.1:7309",
  });
  workers.push(startWorker(workdirs[3], PORT_POOL));
  if (!(await waitPort(PORT_POOL, 120000))) {
    throw new Error("wrangler dev (uji pool) tidak siap pada port " + PORT_POOL + "\n" + workers[3].getOut().slice(-1500));
  }
  results.push(await scenarioPoolFailover(PORT_POOL));
  results.push(await scenarioRotatePool(PORT_POOL));
  results.push(await scenarioRotateCountry(PORT_POOL));
  results.push(await scenarioCountryClosed(PORT_POOL));
  // Baris pertama pool (7316) yang harus dipakai, bukan baris kedua (7302): "tercepat dulu".
  results.push(await scenarioRotateFastestFirst(PORT_POOL));

  // Worker kelima: relay UDP (proses proxy-relay/udp-relay.mjs di atas) untuk UDP non-DNS.
  workers.push(relay); // ikut dimatikan di finally via killTree
  if (!(await waitPort(7313, 30000))) {
    throw new Error("relay UDP tidak siap di port 7313\n" + relay.getOut().slice(-800));
  }
  workdirs.push(fs.mkdtempSync(path.join(os.tmpdir(), "vpn-smoke-relay-")));
  makeFixture(workdirs[4], {
    DOH_ENDPOINT: "http://127.0.0.1:7303/dns-query",
    RELAY_SERVER_UDP: "127.0.0.1",
    RELAY_SERVER_PORT: "7313",
    RELAY_SECRET: "uji",
    FALLBACK_POOL: "off",
  });
  workers.push(startWorker(workdirs[4], PORT_RELAY));
  if (!(await waitPort(PORT_RELAY, 120000))) {
    throw new Error("wrangler dev (uji relay UDP) tidak siap pada port " + PORT_RELAY + "\n" + workers[workers.length - 1].getOut().slice(-1500));
  }
  results.push(await scenarioUdpRelay(PORT_RELAY, () => relay.getOut()));

  // Worker kedelapan: berkas tier Free dengan env relay yang SAMA seperti worker prem di atas.
  // Buktinya jadi bermakna: setup relay identik, yang berbeda cuma sumber worker.
  const freeDir = fs.mkdtempSync(path.join(os.tmpdir(), "vpn-smoke-free-"));
  workdirs.push(freeDir);
  makeFixture(freeDir, {
    DOH_ENDPOINT: "http://127.0.0.1:7303/dns-query",
    RELAY_SERVER_UDP: "127.0.0.1",
    RELAY_SERVER_PORT: "7313",
    RELAY_SECRET: "uji",
    FALLBACK_POOL: "off",
  }, SOURCE_FREE);
  const freeWorker = startWorker(freeDir, PORT_FREE);
  workers.push(freeWorker);
  if (!(await waitPort(PORT_FREE, 120000))) {
    throw new Error("wrangler dev (uji tier Free) tidak siap pada port " + PORT_FREE + "\n" + freeWorker.getOut().slice(-1500));
  }
  results.push(await scenarioFreeTierRelayBlocked(PORT_FREE, () => relay.getOut()));

  // Worker keenam: urutan pool saat KETIGA kolom bukti belum ada (bawaan stub). Isolate harus
  // bersih supaya percobaan 400 -> ulangi benar-benar terjadi di skenario 23e, bukan tersembunyi
  // di ingatan worker pool yang sudah jalan sebelumnya.
  const orderDir = fs.mkdtempSync(path.join(os.tmpdir(), "vpn-smoke-order-"));
  workdirs.push(orderDir);
  makeFixture(orderDir, {
    DOH_ENDPOINT: "http://127.0.0.1:7303/dns-query",
    FALLBACK_POOL: "on",
    FALLBACK_POOL_URL: "http://127.0.0.1:7309",
  });
  const orderWorker = startWorker(orderDir, PORT_ORDER);
  workers.push(orderWorker);
  if (!(await waitPort(PORT_ORDER, 120000))) {
    throw new Error("wrangler dev (uji urutan pool) tidak siap pada port " + PORT_ORDER + "\n" + orderWorker.getOut().slice(-1500));
  }
  results.push(await scenarioPoolOrderFallback(PORT_ORDER));

  // Worker kesembilan: skema tengah — `tls_ok` dan `tunnel_host_ok` (dua bukti dari host
  // scanner) belum ada sementara `tunnel_ok` sudah. Stub menyembunyikan keduanya HANYA selama
  // worker ini dipakai, lalu dikembalikan ke bawaan (ketiga kolom hilang) supaya skenario
  // sesudahnya tetap menguji skema terlama.
  const tlsDir = fs.mkdtempSync(path.join(os.tmpdir(), "vpn-smoke-order-tls-"));
  workdirs.push(tlsDir);
  makeFixture(tlsDir, {
    DOH_ENDPOINT: "http://127.0.0.1:7303/dns-query",
    FALLBACK_POOL: "on",
    FALLBACK_POOL_URL: "http://127.0.0.1:7309",
  });
  S.pool.missing = ["tls_ok", "tunnel_host_ok"];
  const tlsWorker = startWorker(tlsDir, PORT_POOL_TLS);
  workers.push(tlsWorker);
  if (!(await waitPort(PORT_POOL_TLS, 120000))) {
    throw new Error("wrangler dev (uji urutan pool tanpa tls_ok & tunnel_host_ok) tidak siap pada port " + PORT_POOL_TLS + "\n" + tlsWorker.getOut().slice(-1500));
  }
  results.push(await scenarioPoolOrderTlsMissing(PORT_POOL_TLS));
  S.pool.missing = ["tunnel_ok", "tls_ok", "tunnel_host_ok"];

  // Worker kesepuluh: skema TERBARU — ketiga kolom bukti ada (`tunnel_host_ok` sudah ditambahkan
  // lewat SQL manual). Stub tidak menyembunyikan apa pun selama worker ini dipakai, jadi urutan 1
  // (empat tingkat) harus langsung diterima pada pengambilan pool pertama isolate ini.
  const hostDir = fs.mkdtempSync(path.join(os.tmpdir(), "vpn-smoke-order-host-"));
  workdirs.push(hostDir);
  makeFixture(hostDir, {
    DOH_ENDPOINT: "http://127.0.0.1:7303/dns-query",
    FALLBACK_POOL: "on",
    FALLBACK_POOL_URL: "http://127.0.0.1:7309",
  });
  S.pool.missing = [];
  const hostWorker = startWorker(hostDir, PORT_POOL_HOST);
  workers.push(hostWorker);
  if (!(await waitPort(PORT_POOL_HOST, 120000))) {
    throw new Error("wrangler dev (uji urutan pool skema lengkap) tidak siap pada port " + PORT_POOL_HOST + "\n" + hostWorker.getOut().slice(-1500));
  }
  results.push(await scenarioPoolOrderComplete(PORT_POOL_HOST));

  // Worker kesebelas: `tunnel_host_ok` belum ada, `tunnel_ok` & `tls_ok` sudah -> urutan 2.
  const hostMissingDir = fs.mkdtempSync(path.join(os.tmpdir(), "vpn-smoke-order-host-missing-"));
  workdirs.push(hostMissingDir);
  makeFixture(hostMissingDir, {
    DOH_ENDPOINT: "http://127.0.0.1:7303/dns-query",
    FALLBACK_POOL: "on",
    FALLBACK_POOL_URL: "http://127.0.0.1:7309",
  });
  S.pool.missing = ["tunnel_host_ok"];
  const hostMissingWorker = startWorker(hostMissingDir, PORT_POOL_HOST_MISSING);
  workers.push(hostMissingWorker);
  if (!(await waitPort(PORT_POOL_HOST_MISSING, 120000))) {
    throw new Error("wrangler dev (uji urutan pool tanpa tunnel_host_ok) tidak siap pada port " + PORT_POOL_HOST_MISSING + "\n" + hostMissingWorker.getOut().slice(-1500));
  }
  results.push(await scenarioPoolOrderHostMissing(PORT_POOL_HOST_MISSING));
  S.pool.missing = ["tunnel_ok", "tls_ok", "tunnel_host_ok"];

  // Worker terpisah untuk pool dengan baris TERATAS mati (FALLBACK_TABLE sendiri). Isolate-nya
  // sendiri supaya cache pool kunci "all" di sini benar-benar bersih: daftar pertama yang
  // dipakai skenario ini memang memuat baris mati di depan, bukan daftar dari worker lain.
  const deadDir = fs.mkdtempSync(path.join(os.tmpdir(), "vpn-smoke-pool-dead-"));
  workdirs.push(deadDir);
  makeFixture(deadDir, {
    DOH_ENDPOINT: "http://127.0.0.1:7303/dns-query",
    FALLBACK_POOL: "on",
    FALLBACK_POOL_URL: "http://127.0.0.1:7309",
    FALLBACK_TABLE: POOL_TABLE_DEAD_FIRST,
  });
  const deadWorker = startWorker(deadDir, PORT_POOL_DEAD);
  workers.push(deadWorker);
  if (!(await waitPort(PORT_POOL_DEAD, 120000))) {
    throw new Error("wrangler dev (uji pool tercepat-gagal) tidak siap pada port " + PORT_POOL_DEAD + "\n" + deadWorker.getOut().slice(-1500));
  }
  results.push(await scenarioRotateFastestFailover(PORT_POOL_DEAD));

  // Worker ketujuh: /health digerbang HEALTH_TOKEN.
  const tokenDir = fs.mkdtempSync(path.join(os.tmpdir(), "vpn-smoke-token-"));
  workdirs.push(tokenDir);
  const healthToken = "rahasia-health";
  makeFixture(tokenDir, {
    DOH_ENDPOINT: "http://127.0.0.1:7303/dns-query",
    FALLBACK_POOL: "off",
    HEALTH_TOKEN: healthToken,
  });
  const tokenWorker = startWorker(tokenDir, PORT_TOKEN);
  workers.push(tokenWorker);
  if (!(await waitPort(PORT_TOKEN, 120000))) {
    throw new Error("wrangler dev (uji health token) tidak siap pada port " + PORT_TOKEN + "\n" + tokenWorker.getOut().slice(-1500));
  }
  results.push(await scenarioHealthToken(PORT_TOKEN, healthToken));

  results.push(tierCheck());
} catch (err) {
  results.push({ name: "setup", pass: false, detail: err.message });
} finally {
  for (const w of workers) killTree(w.child);
  await sleep(1000);
  for (const s of stubs) s.close();
  for (const dir of workdirs) {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
  }
}

let failed = 0;
for (const r of results) {
  if (!r.pass) failed++;
  console.log(`[${r.pass ? "PASS" : "FAIL"}] ${r.name}\n    ${r.detail}`);
}
console.log(failed === 0 ? "\nSEMUA SKENARIO PASS" : `\n${failed} skenario GAGAL`);
process.exit(failed === 0 ? 0 : 1);
