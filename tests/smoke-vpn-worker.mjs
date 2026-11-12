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
const PORT = 8787;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const hex = (b) => Buffer.from(b).toString("hex");

const S = {
  raw: { opens: 0, all: Buffer.alloc(0) },
  proxy: { socks5: 0, http: 0, closes: 0, connectLines: [], echoed: false, closeAfterEcho: false },
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

const startProxy = () =>
  listen(7302, (sock) => {
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

// --- stub DoH: menjawab setiap query dengan A record tetap ---
function dnsAnswerFor(query) {
  const txid = query.subarray(0, 2);
  let i = 12;
  while (i < query.length && query[i] !== 0) i += query[i] + 1;
  const question = query.subarray(12, i + 5);
  return Buffer.concat([
    txid,
    Buffer.from([0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]),
    question,
    Buffer.from([0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 93, 184, 216, 34]),
  ]);
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

function makeFixture(dir) {
  const src = fs.readFileSync(SOURCE, "utf8");
  fs.writeFileSync(path.join(dir, "worker.local.mjs"), src);
  fs.writeFileSync(
    path.join(dir, "wrangler.toml"),
    'name = "vpn-worker-smoke"\nmain = "worker.local.mjs"\ncompatibility_date = "2024-05-12"\n\n[vars]\nDOH_ENDPOINT = "http://127.0.0.1:7303/dns-query"\n'
  );
}

function startWorker(dir) {
  const child = spawn(process.execPath, [WRANGLER, "dev", "--port", String(PORT), "--ip", "127.0.0.1"], {
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

function frame({ cmd, host = "dns.local", port, payload }) {
  const hostBytes = Buffer.from(host, "utf8");
  return Buffer.concat([
    Buffer.from([0x00]),
    Buffer.from(UUID_HEX, "hex"),
    Buffer.from([0x00]),
    Buffer.from([cmd]),
    Buffer.from([(port >> 8) & 0xff, port & 0xff]),
    Buffer.from([0x02, hostBytes.length]),
    hostBytes,
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

function openWs(wsPath) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`ws://127.0.0.1:${PORT}${wsPath}`);
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

  const q1 = dnsQuery(0x1111, "example.com");
  const q2 = dnsQuery(0x2222, "example.org");
  let payload;
  if (mode === "raw") payload = q1;
  else if (mode === "two") payload = Buffer.concat([prefixed(q1), prefixed(q2)]);
  else payload = prefixed(q1);

  const f = frame({ cmd: 2, port: 53, payload });
  const { ws, received } = await openWs("/1.2.3.4:5678");

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

  const dohOk =
    S.doh.requests.length === expectedCount &&
    S.doh.requests.every((r) => r.method === "POST" && r.contentType === "application/dns-message") &&
    S.doh.requests[0].txid === "1111" &&
    (mode === "two" ? S.doh.requests[1].txid === "2222" : true) &&
    (mode === "raw"
      ? S.doh.requests[0].length === q1.length
      : S.doh.requests[0].length === q1.length);

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
      bodyOk = a1txid === "1111" && len1 > 0;
      if (mode === "two") {
        const off = 4 + len1;
        const len2 = (got[off] << 8) | got[off + 1];
        const a2txid = got.subarray(off + 2, off + 4).toString("hex");
        bodyOk = bodyOk && a2txid === "2222" && len2 > 0;
        detail = `len1=${len1} txid1=${a1txid} len2=${len2} txid2=${a2txid}`;
      } else {
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
  const { ws, received } = await openWs("/127.0.0.1:7302");
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
  const { ws, received, isClosed } = await openWs("/127.0.0.1:7302");
  ws.send(f);
  await until(() => received().length >= 8, 8000);
  const closedByWorker = await until(() => isClosed(), 2500);
  S.proxy.closeAfterEcho = false;
  return { name: "target menutup koneksi -> WebSocket ikut ditutup", pass: closedByWorker, detail: `wsTertutup=${closedByWorker}` };
}

function tierCheck() {
  const prem = fs.readFileSync(SOURCE);
  const free = fs.readFileSync(SOURCE_FREE);
  return { name: "vpn-worker-free.js identik dengan vpn-worker-prem.js", pass: prem.equals(free), detail: `prem=${prem.length}B free=${free.length}B` };
}

const stubs = [];
const results = [];
let workdir = null;
let worker = null;

try {
  if (!fs.existsSync(WRANGLER)) throw new Error(`wrangler tidak ada di ${WRANGLER} — jalankan npm install dulu`);
  stubs.push(await startRaw(), await startProxy(), await startDoh());

  workdir = fs.mkdtempSync(path.join(os.tmpdir(), "vpn-smoke-"));
  makeFixture(workdir);
  reset();
  worker = startWorker(workdir);

  if (!(await waitPort(PORT, 120000))) {
    throw new Error("wrangler dev tidak siap pada port " + PORT + "\n" + worker.getOut().slice(-1500));
  }

  results.push(await scenarioDns("prefixed"));
  results.push(await scenarioDns("raw"));
  results.push(await scenarioDns("split"));
  results.push(await scenarioDns("two"));
  results.push(await scenarioUdpOtherPort());
  results.push(await scenarioTcp());
  results.push(await scenarioRemoteClose());
  results.push(tierCheck());
} catch (err) {
  results.push({ name: "setup", pass: false, detail: err.message });
} finally {
  if (worker) { killTree(worker.child); await sleep(1000); }
  for (const s of stubs) s.close();
  if (workdir) { try { fs.rmSync(workdir, { recursive: true, force: true }); } catch {} }
}

let failed = 0;
for (const r of results) {
  if (!r.pass) failed++;
  console.log(`[${r.pass ? "PASS" : "FAIL"}] ${r.name}\n    ${r.detail}`);
}
console.log(failed === 0 ? "\nSEMUA SKENARIO PASS" : `\n${failed} skenario GAGAL`);
process.exit(failed === 0 ? 0 : 1);
