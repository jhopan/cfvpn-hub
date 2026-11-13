// Relay UDP untuk CFVPN Hub — jembatan TCP -> UDP.
//
// Kenapa ada: Cloudflare Workers tidak punya UDP keluar, jadi worker meneruskan datagram
// klien (VLESS cmd=2 / XUDP) ke proses ini lewat TCP, dan proses ini yang benar-benar
// mengirim UDP ke tujuan. Worker tetap yang menangani VLESS, DoH, dan jalur TCP.
//
// Protokol (satu koneksi TCP = satu sesi UDP ke SATU tujuan):
//   klien  -> relay : "udp <alamat> <port> <rahasia>\n"   (header, sekali)
//   dua arah        : [2B panjang BE][payload]            (satu datagram per frame)
// Balasan dari tujuan dikirim balik dengan framing yang sama. Koneksi ditutup kalau tidak
// ada trafik selama IDLE_MS (bawaan 60 s) supaya soket UDP tidak menumpuk.
//
// Jalankan:
//   RELAY_SECRET=rahasia-panjang node udp-relay.mjs                 # dengar 0.0.0.0:7300
//   RELAY_PORT=443 RELAY_TLS=1 RELAY_CERT=fullchain.pem RELAY_KEY=privkey.pem node udp-relay.mjs
//
// Tanpa RELAY_SECRET proses menolak jalan (relay terbuka = alat refleksi UDP untuk siapa pun).
import net from "node:net";
import tls from "node:tls";
import dgram from "node:dgram";
import fs from "node:fs";

const PORT = Number(process.env.RELAY_PORT || 7300);
const HOST = process.env.RELAY_HOST || "0.0.0.0";
const SECRET = process.env.RELAY_SECRET || "";
const IDLE_MS = Number(process.env.RELAY_IDLE_MS || 60000);
const MAX_DATAGRAM = Number(process.env.RELAY_MAX_DATAGRAM || 8192);
const IDLE_SWEEP_MS = 15000;
const USE_TLS = process.env.RELAY_TLS === "1";

if (!SECRET) {
  console.error("RELAY_SECRET wajib diisi — relay terbuka bisa dipakai orang lain untuk refleksi UDP.");
  process.exit(1);
}

const stats = { connections: 0, denied: 0, datagramsIn: 0, datagramsOut: 0, errors: 0 };

// Satu sesi yang bermasalah tidak boleh menjatuhkan seluruh relay: catat, lalu lanjut.
process.on("uncaughtException", (err) => {
  stats.errors++;
  console.error("uncaught:", (err && err.message) || err);
});
process.on("unhandledRejection", (err) => {
  stats.errors++;
  console.error("unhandled:", (err && err.message) || err);
});

function log(...args) {
  console.log(new Date().toISOString(), ...args);
}

// Satu koneksi TCP = satu sesi: soket UDP sendiri supaya balasan tujuan bisa dipetakan balik.
function handleConnection(sock, peer) {
  stats.connections++;
  let udp = null;
  let udpReady = false;
  const pending = [];
  let target = null;
  let targetPort = 0;
  let buffer = Buffer.alloc(0);
  let lastSeen = Date.now();
  let authed = false;

  const close = (reason) => {
    if (udp) {
      try { udp.close(); } catch (e) {}
      udp = null;
    }
    try { sock.destroy(); } catch (e) {}
    if (reason) log("tutup " + peer + ": " + reason);
  };

  const sendFrame = (payload) => {
    const head = Buffer.alloc(2);
    head.writeUInt16BE(payload.length, 0);
    sock.write(Buffer.concat([head, payload]));
    stats.datagramsOut++;
  };

  // Kirim satu datagram ke tujuan; kalau soket UDP belum siap, tahan dulu.
  const sendDatagram = (payload) => {
    if (!udp || !target) return;
    if (!udpReady) {
      pending.push(payload);
      return;
    }
    udp.send(payload, targetPort, target, (err) => {
      if (err) {
        stats.errors++;
        close("udp send gagal: " + err.message);
      }
    });
  };

  sock.setTimeout(0);
  sock.on("error", (err) => {
    stats.errors++;
    close("error: " + err.message);
  });
  sock.on("close", () => close());

  sock.on("data", (chunk) => {
    lastSeen = Date.now();
    buffer = Buffer.concat([buffer, chunk]);

    if (!authed) {
      const newline = buffer.indexOf(0x0a);
      if (newline === -1) {
        if (buffer.length > 512) close("header terlalu panjang");
        return;
      }
      const line = buffer.subarray(0, newline).toString("utf8").trim();
      buffer = buffer.subarray(newline + 1);
      const parts = line.split(" ");
      if (parts.length !== 4 || parts[0] !== "udp") return close("header tidak dikenal");
      if (parts[3] !== SECRET) {
        stats.denied++;
        return close("rahasia salah");
      }
      target = parts[1];
      targetPort = Number(parts[2]);
      if (!target || !targetPort || targetPort < 1 || targetPort > 65535) return close("tujuan tidak valid");

      udp = dgram.createSocket(target.indexOf(":") === -1 ? "udp4" : "udp6");
      udp.on("error", (err) => {
        stats.errors++;
        close("udp error: " + err.message);
      });
      udp.on("message", (msg) => {
        if (msg.length > MAX_DATAGRAM) return;
        sendFrame(msg);
      });
      // Soket UDP baru bisa dipakai setelah 'listening'; datagram yang datang lebih dulu
      // ditahan supaya tidak melempar ERR_SOCKET_DGRAM_NOT_RUNNING (pernah menjatuhkan relay).
      udp.on("listening", () => {
        udpReady = true;
        while (pending.length) sendDatagram(pending.shift());
      });
      udp.bind(0);
      authed = true;
      log("sesi " + peer + " -> " + target + ":" + targetPort);
    }

    while (authed && buffer.length >= 2) {
      const length = buffer.readUInt16BE(0);
      if (length === 0 || length > MAX_DATAGRAM) return close("panjang datagram aneh: " + length);
      if (buffer.length < 2 + length) return;
      const payload = buffer.subarray(2, 2 + length);
      buffer = buffer.subarray(2 + length);
      stats.datagramsIn++;
      sendDatagram(payload);
    }
  });

  // Sweep idle: tanpa ini sesi yang ditinggal klien menahan soket UDP selamanya.
  const sweeper = setInterval(() => {
    if (Date.now() - lastSeen > IDLE_MS) {
      clearInterval(sweeper);
      close("idle");
    }
  }, IDLE_SWEEP_MS);
  sock.on("close", () => clearInterval(sweeper));
}

const server = USE_TLS
  ? tls.createServer({ cert: fs.readFileSync(process.env.RELAY_CERT || "cert.pem"), key: fs.readFileSync(process.env.RELAY_KEY || "key.pem") }, (sock) => handleConnection(sock, sock.remoteAddress))
  : net.createServer((sock) => handleConnection(sock, sock.remoteAddress));

server.on("error", (err) => {
  console.error("server error:", err.message);
  process.exit(1);
});

server.listen(PORT, HOST, () => {
  log("relay UDP siap di " + HOST + ":" + PORT + (USE_TLS ? " (TLS)" : "") + ", idle " + IDLE_MS + " ms");
});

setInterval(() => {
  log("statistik: " + JSON.stringify(stats));
}, 300000).unref();
