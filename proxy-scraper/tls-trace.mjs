// Verifikasi tingkat-2 untuk scraper: buka tunnel lewat proxy, lalu **bungkus socket dengan TLS**
// ke www.cloudflare.com/cdn-cgi/trace. Cek ringan (proxy-check.mjs) hanya membuktikan port **80**;
// proxy yang memblokir/mengacak 443 tetap lolos di sana padahal worker memakai 443 untuk TLS-nya.
//
// Jejak yang diambil sekaligus dua: (a) bukti TLS benar-benar jalan lewat proxy, (b) `loc=` dari
// Cloudflare = **negara keluar yang sebenarnya** (bukan tebakan dari tabel IP) dan `ip=` = IP
// keluar (mendeteksi proxy transparan/hijack).
//
// Tidak dipakai di cron-worker: `socket.startTls()` di workerd tidak menerima SNI, jadi TLS ke
// hostname lain lewat tunnel tidak bisa dibentuk dari Worker. Di Node bisa, dan di sinilah
// (scraper) verifikasi tambahan itu memang dijalankan.
import net from "node:net";
import tls from "node:tls";
import {
  buildSocks5Connect,
  buildSocks5Greeting,
  concatBytes,
  parseHttpConnectReply,
  parseSocks5Greeting,
  parseSocks5Reply,
  socks5BindLength,
  toText,
} from "../cron-worker/src/tunnel.js";

const TRACE_HOST = "www.cloudflare.com";
const TRACE_PATH = "/cdn-cgi/trace";
const CONNECT_TIMEOUT_MS = 4000;
const TLS_TIMEOUT_MS = 6000;
const READ_TIMEOUT_MS = 6000;
const MAX_BYTES = 65536;

function withTimeout(promise, ms, label) {
  let timer = null;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(label + ": timeout")), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

// Kumpulkan byte sampai predikat puas, socket ditutup, atau waktu habis. mengembalikan teks.
function readUntil(sock, isDone, timeoutMs) {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const finish = (err) => {
      cleanup();
      if (err) reject(err);
      else resolve(buf.toString("latin1"));
    };
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length > MAX_BYTES) return finish(new Error("balasan terlalu besar"));
      if (isDone(buf.toString("latin1"))) finish(null);
    };
    const onEnd = () => finish(null);
    const onErr = (err) => finish(err);
    const timer = setTimeout(() => finish(new Error("timeout baca")), timeoutMs);
    function cleanup() {
      clearTimeout(timer);
      sock.off("data", onData);
      sock.off("end", onEnd);
      sock.off("error", onErr);
    }
    sock.on("data", onData);
    sock.on("end", onEnd);
    sock.on("error", onErr);
  });
}

// Buka tunnel: HTTP CONNECT dulu, kalau ditolak/aneh coba SOCKS5. Mengembalikan socket polos.
async function openTunnel(host, port, timeoutMs) {
  const errors = [];
  for (const protocol of ["http-connect", "socks5"]) {
    const sock = net.connect({ host, port: Number(port) });
    sock.on("error", () => {});
    try {
      await withTimeout(new Promise((resolve, reject) => {
        sock.once("connect", resolve);
        sock.once("error", reject);
      }), timeoutMs, protocol + " connect");

      if (protocol === "http-connect") {
        sock.write(`CONNECT ${TRACE_HOST}:443 HTTP/1.1\r\nHost: ${TRACE_HOST}:443\r\nUser-Agent: Mozilla/5.0\r\n\r\n`);
        const head = await readUntil(sock, (t) => t.includes("\r\n\r\n"), timeoutMs);
        const reply = parseHttpConnectReply(head.split("\r\n\r\n")[0] + "\r\n\r\n");
        if (!reply.ok) throw new Error("CONNECT ditolak (" + reply.status + ")");
      } else {
        sock.write(Buffer.from(buildSocks5Greeting()));
        const greeting = await readUntil(sock, (t) => t.length >= 2, timeoutMs);
        parseSocks5Greeting(new Uint8Array(Buffer.from(greeting, "latin1").subarray(0, 2)));
        sock.write(Buffer.from(buildSocks5Connect(TRACE_HOST, 443)));
        const reply = await readUntil(sock, (t) => t.length >= 4, timeoutMs);
        const parsed = parseSocks5Reply(new Uint8Array(Buffer.from(reply, "latin1").subarray(0, 4)));
        const extra = parsed.atyp === 0x03 ? 1 : 0;
        const need = 4 + extra + socks5BindLength(parsed.atyp, extra ? 3 : undefined);
        if (reply.length < need) await readUntil(sock, (t) => t.length >= need, timeoutMs);
      }
      return { sock, protocol };
    } catch (err) {
      errors.push(protocol + ": " + err.message);
      sock.destroy();
    }
  }
  throw new Error(errors.join(" | "));
}

// parseTrace memecah balasan cdn-cgi/trace (baris k=v) menjadi peta + field yang dipakai.
export function parseTrace(text) {
  const fields = new Map();
  for (const line of String(text || "").split("\n")) {
    const at = line.indexOf("=");
    if (at > 0) fields.set(line.slice(0, at).trim(), line.slice(at + 1).trim());
  }
  const loc = (fields.get("loc") || "").toUpperCase();
  return {
    fields,
    country: /^[A-Z]{2}$/.test(loc) ? loc : null,
    exitIp: fields.get("ip") || null,
    colo: fields.get("colo") || null,
  };
}

// tlsTrace memverifikasi TLS lewat proxy dan mengembalikan negara/IP keluar.
export async function tlsTrace(host, port, options = {}) {
  const timeoutMs = options.timeoutMs || CONNECT_TIMEOUT_MS;
  const started = Date.now();
  let sock = null;
  let secure = null;
  try {
    const tunnel = await openTunnel(host, port, timeoutMs);
    sock = tunnel.sock;
    const connectMs = Date.now() - started;

    secure = tls.connect({ socket: sock, servername: TRACE_HOST, rejectUnauthorized: true });
    secure.on("error", () => {});
    await withTimeout(new Promise((resolve, reject) => {
      secure.once("secureConnect", resolve);
      secure.once("error", reject);
    }), TLS_TIMEOUT_MS, "tls handshake");
    const tlsMs = Date.now() - started;

    secure.write(`GET ${TRACE_PATH} HTTP/1.0\r\nHost: ${TRACE_HOST}\r\nUser-Agent: Mozilla/5.0\r\n\r\n`);
    const body = await readUntil(secure, (t) => /(^|\n)warp=/.test(t) || /(^|\n)loc=/.test(t) && t.includes("\n") && t.split("\n").filter((l) => l.includes("=")).length >= 6, READ_TIMEOUT_MS);
    const parsed = parseTrace(toText(body));
    const fields = parsed.fields;
    for (const line of toText(body).split("\n")) {
      const at = line.indexOf("=");
      if (at > 0) fields.set(line.slice(0, at).trim(), line.slice(at + 1).trim());
    }
    const loc = (fields.get("loc") || "").toUpperCase();
    return {
      ok: true,
      protocol: tunnel.protocol,
      connectMs,
      tlsMs,
      ms: Date.now() - started,
      country: /^[A-Z]{2}$/.test(loc) ? loc : null,
      exitIp: fields.get("ip") || null,
      colo: fields.get("colo") || null,
      detail: "tls ok",
    };
  } catch (err) {
    return { ok: false, ms: Date.now() - started, detail: String(err && err.message ? err.message : err) };
  } finally {
    if (secure) secure.destroy();
    if (sock) sock.destroy();
  }
}