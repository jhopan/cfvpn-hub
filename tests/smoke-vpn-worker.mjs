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
//   7309 REST proxy_pool palsu: mengembalikan satu baris {ip,port} untuk uji failover pool
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
//
// Port worker bisa diganti lewat SMOKE_PORT (bawaan 8787; worker lain memakai port+1..+3).
import net from "node:net";
import http from "node:http";
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
// Target IPv6 tetap untuk uji (2001:db8::1) — ditulis apa adanya supaya uji tidak memakai
// parser yang sedang diuji.
const IPV6_TARGET = "2001:db8::1";
const IPV6_BYTES = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const hex = (b) => Buffer.from(b).toString("hex");

const S = {
  raw: { opens: 0, all: Buffer.alloc(0) },
  proxy: { socks5: 0, http: 0, closes: 0, connectLines: [], echoed: false, closeAfterEcho: false },
  socks: { greeting: 0, requests: [], closes: 0, echoed: false },
  silent: { handshakes: 0 },
  pool: { requests: [] },
  doh: { requests: [], answers: 0, answerLength: 0 },
};

function reset() {
  S.raw.opens = 0;
  S.raw.all = Buffer.alloc(0);
  S.proxy.socks5 = 0;
  S.proxy.http = 0;
  S.proxy.closes = 0;
  S.proxy.connectLines = [];
  S.proxy.echoed = false;
  S.proxy.closeAfterEcho = false;
  S.socks.greeting = 0;
  S.socks.requests = [];
  S.socks.closes = 0;
  S.socks.echoed = false;
  S.silent.handshakes = 0;
  S.pool.requests = [];
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
// Mengembalikan satu baris {ip,port} yang menunjuk ke proxy HTTP-only 7302, supaya jalur
// failover dari pool bisa diuji tanpa menyentuh Supabase.
const startPoolStub = () =>
  new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      S.pool.requests.push(req.url);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify([{ ip: "127.0.0.1", port: 7302 }]));
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

function makeFixture(dir, vars) {
  const src = fs.readFileSync(SOURCE, "utf8");
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
      resolve({ ws, received: () => Buffer.concat(chunks), isClosed: () => closed });
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
    typeof body.dns_mode === "string" && body.dns_hits && typeof body.dns_hits.memory === "number" &&
    typeof body.proxy_memo === "number";
  return { name: "/health melaporkan kondisi isolate", pass: ok, detail: JSON.stringify(body).slice(0, 220) };
}

function tierCheck() {
  const prem = fs.readFileSync(SOURCE);
  const free = fs.readFileSync(SOURCE_FREE);
  return { name: "vpn-worker-free.js identik dengan vpn-worker-prem.js", pass: prem.equals(free), detail: `prem=${prem.length}B free=${free.length}B` };
}

const stubs = [];
const results = [];
const workdirs = [];
const workers = [];

try {
  if (!fs.existsSync(WRANGLER)) throw new Error(`wrangler tidak ada di ${WRANGLER} — jalankan npm install dulu`);
  const dohStub = await startDoh();
  stubs.push(await startRaw(), await startProxy(), await startProxy(7306), await startSocks(), await startSilentProxy(), await startPoolStub(), dohStub);

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
  results.push(await scenarioFailover());
  results.push(await scenarioNoFailoverWhenHealthy());
  results.push(await scenarioDnsNegativeCache());
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
    FALLBACK_POOL: "off",
  });
  workers.push(startWorker(workdirs[2], PORT_IDLE));
  if (!(await waitPort(PORT_IDLE, 120000))) {
    throw new Error("wrangler dev (uji watchdog) tidak siap pada port " + PORT_IDLE + "\n" + workers[2].getOut().slice(-1500));
  }
  results.push(await scenarioWatchdog(PORT_IDLE));

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
