// Uji bagian murni probe tunnel cron-worker (cron-worker/src/tunnel.js) tanpa runtime Worker:
// pembuat pesan SOCKS5, parser balasan SOCKS5/CONNECT, deteksi "HTTP/1." (termasuk balasan yang
// terpecah antar chunk), deteksi kolom hilang dari error PostgREST, dan urutan percobaan probe
// (HTTP CONNECT dulu, SOCKS5 sebagai cadangan) memakai soket palsu.
//
//   nrun node --test tests/cron-tunnel.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import {
  buildSocks5Connect,
  buildSocks5Greeting,
  concatBytes,
  hasHttp10Reply,
  indexOfCrlfCrlf,
  isMissingColumnError,
  parseHttpConnectReply,
  parseSocks5Greeting,
  parseSocks5Reply,
  probeTunnel,
  socks5BindLength,
} from "../cron-worker/src/tunnel.js";

const enc = (text) => new TextEncoder().encode(text);

test("greeting SOCKS5: versi 5, satu metode, no-auth", () => {
  assert.deepEqual(Array.from(buildSocks5Greeting()), [0x05, 0x01, 0x00]);
  assert.equal(parseSocks5Greeting(new Uint8Array([0x05, 0x00])), 0x00);
});

test("greeting SOCKS5: versi asing dan permintaan auth ditolak", () => {
  assert.throws(() => parseSocks5Greeting(new Uint8Array([0x04, 0x00])), /bukan SOCKS5/);
  assert.throws(() => parseSocks5Greeting(new Uint8Array([0x05, 0xff])), /butuh auth/);
  assert.throws(() => parseSocks5Greeting(new Uint8Array([0x05])), /terpotong/);
});

test("permintaan CONNECT SOCKS5: IPv4, nama domain, dan port big-endian", () => {
  assert.deepEqual(Array.from(buildSocks5Connect("1.2.3.4", 80)), [0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x50]);

  const name = Array.from(enc("example.com"));
  assert.deepEqual(
    Array.from(buildSocks5Connect("example.com", 8080)),
    [0x05, 0x01, 0x00, 0x03, name.length, ...name, 8080 >> 8, 8080 & 0xff],
  );

  assert.throws(() => buildSocks5Connect("example.com", 0), /port tidak sah/);
  assert.throws(() => buildSocks5Connect("example.com", 65536), /port tidak sah/);
  assert.throws(() => buildSocks5Connect("1.2.3.999", 80), /IPv4 tidak sah/);
  assert.throws(() => buildSocks5Connect("2001:db8::1", 80), /IPv6/);
});

test("balasan SOCKS5: sukses, ditolak, terpotong, ATYP tidak dikenal", () => {
  const ok = parseSocks5Reply(new Uint8Array([0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90]));
  assert.deepEqual(ok, { reply: 0x00, atyp: 0x01 });
  assert.equal(socks5BindLength(ok.atyp), 6);
  assert.equal(socks5BindLength(0x03, 9), 11);
  assert.equal(socks5BindLength(0x04), 18);

  assert.throws(() => parseSocks5Reply(new Uint8Array([0x05, 0x05, 0x00, 0x01])), /ditolak/);
  assert.throws(() => parseSocks5Reply(new Uint8Array([0x04, 0x00, 0x00, 0x01])), /bukan SOCKS5/);
  assert.throws(() => parseSocks5Reply(new Uint8Array([0x05, 0x00])), /terpotong/);
  assert.throws(() => socks5BindLength(0x09), /ATYP tidak dikenal/);
  assert.throws(() => socks5BindLength(0x03), /panjang/);
});

test("deteksi HTTP/1.: utuh, terpecah antar chunk, dan tidak lengkap", () => {
  assert.equal(hasHttp10Reply("HTTP/1.0 200 OK\r\n\r\n"), true);
  assert.equal(hasHttp10Reply("HTTP/1.1 301 Moved Permanently\r\n"), true);

  assert.equal(hasHttp10Reply("HTTP/1"), false);
  assert.equal(hasHttp10Reply("HTT"), false);
  assert.equal(hasHttp10Reply("HTTP/2 200 OK"), false);
  assert.equal(hasHttp10Reply(""), false);

  // Balasan terpecah: penanda "HTTP/1." baru lengkap setelah potongan kedua menempel.
  let acc = concatBytes(new Uint8Array(0), enc("HTT"));
  assert.equal(hasHttp10Reply(acc), false);
  acc = concatBytes(acc, enc("P/1.0 200 OK\r"));
  assert.equal(hasHttp10Reply(acc), true);

  // Pemisah header: -1 selama "\r\n\r\n" belum lengkap (balasan menggantung di chunk pertama).
  assert.equal(indexOfCrlfCrlf(enc("HTTP/1.0 200 OK\r\n\r\nbody")), 15);
  assert.equal(indexOfCrlfCrlf(enc("HTTP/1.0 200 OK\r\n")), -1);
  assert.equal(indexOfCrlfCrlf(new Uint8Array(0)), -1);
});

test("balasan HTTP CONNECT: 200 diterima, 407/502 ditolak, sampah bukan proxy HTTP", () => {
  assert.deepEqual(parseHttpConnectReply("HTTP/1.1 200 Connection established\r\n\r\n"), { ok: true, status: 200 });
  assert.deepEqual(parseHttpConnectReply(enc("HTTP/1.0 200 OK\r\n\r\n")), { ok: true, status: 200 });
  assert.equal(parseHttpConnectReply("HTTP/1.0 407 Proxy Authentication Required\r\n\r\n").ok, false);
  assert.equal(parseHttpConnectReply("HTTP/1.1 502 Bad Gateway\r\n\r\n").status, 502);
  assert.throws(() => parseHttpConnectReply("\u0005\u0000\u0000"), /bukan HTTP proxy/);
});

test("kolom hilang terdeteksi dari kode/pesan PostgREST, error lain tidak", () => {
  assert.equal(isMissingColumnError({
    code: "PGRST204",
    message: "Could not find the 'tunnel_ok' column of 'proxy_pool' in the schema cache",
  }), true);
  assert.equal(isMissingColumnError({
    message: "Could not find the 'tunnel_ms' column of 'proxy_pool' in the schema cache",
  }), true);
  assert.equal(isMissingColumnError({ status: 400, message: "column proxy_pool.tunnel_ok does not exist" }), true);
  // Bentuk yang benar-benar dikembalikan PostgREST/Supabase saat skema sudah termuat: kode 42703
  // DAN tanpa field status. Dulu bentuk ini tidak dikenali sehingga siklus cron berhenti dengan
  // "gagal memuat proxy_pool" (terjadi di produksi 14 Nov).
  assert.equal(isMissingColumnError({
    code: "42703",
    details: null,
    hint: null,
    message: "column proxy_pool.tunnel_checked does not exist",
  }), true);
  assert.equal(isMissingColumnError({ code: "42703", message: "column proxy_pool.tunnel_checked does not exist" }), true);

  assert.equal(isMissingColumnError({ code: "23514", message: "new row violates check constraint" }), false);
  assert.equal(isMissingColumnError({ status: 400, message: 'invalid input syntax for type integer: "abc"' }), false);
  assert.equal(isMissingColumnError({ status: 401, message: "JWT expired" }), false);
  assert.equal(isMissingColumnError(null), false);
  assert.equal(isMissingColumnError(undefined), false);
});

// Soket palsu: balasan sudah diantre sebelum dibaca, tulisannya direkam supaya urutan percobaan
// probe bisa diperiksa tanpa koneksi nyata.
function fakeSocket(chunks) {
  const writes = [];
  const socket = {
    writes,
    closed: false,
    readable: new ReadableStream({
      start(controller) {
        for (const chunk of chunks) controller.enqueue(chunk);
        controller.close();
      },
    }),
    writable: new WritableStream({
      write(chunk) {
        writes.push(new TextDecoder().decode(chunk));
      },
    }),
    close() {
      socket.closed = true;
    },
  };
  return socket;
}

test("probeTunnel: HTTP CONNECT dicoba dulu, SOCKS5 dipakai kalau CONNECT ditolak", async () => {
  const dialed = [];
  const sockets = [];
  const connectFn = async (address) => {
    dialed.push(address.hostname + ":" + address.port);
    const socket = dialed.length === 1
      ? fakeSocket([enc("HTTP/1.1 501 Not Implemented\r\n\r\n")])
      : fakeSocket([
        new Uint8Array([0x05, 0x00]),
        new Uint8Array([0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90]),
        enc("HTTP/1.0 200 OK\r\n\r\n<html>"),
      ]);
    sockets.push(socket);
    return socket;
  };

  const res = await probeTunnel("127.0.0.1", 1080, connectFn, { timeoutMs: 1000 });
  assert.equal(res.ok, true);
  assert.equal(res.protocol, "socks5");
  assert.match(res.detail, /^HTTP\/1\.0 200 OK/);
  assert.deepEqual(dialed, ["127.0.0.1:1080", "127.0.0.1:1080"]);
  assert.match(sockets[0].writes.join(""), /^CONNECT example\.com:80 HTTP\/1\.1/);
  assert.ok(sockets[1].writes.join("").endsWith("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"));
  assert.equal(sockets[0].closed, true);
  assert.equal(sockets[1].closed, true);
});

test("probeTunnel: tunnel CONNECT yang langsung tembus tidak mencoba SOCKS5", async () => {
  const dialed = [];
  const connectFn = async (address) => {
    dialed.push(address.hostname + ":" + address.port);
    return fakeSocket([enc("HTTP/1.1 200 Connection established\r\n\r\nHTTP/1.0 200 OK\r\n\r\n<html>")]);
  };

  const res = await probeTunnel("10.0.0.1", 8080, connectFn, { timeoutMs: 1000 });
  assert.equal(res.ok, true);
  assert.equal(res.protocol, "http-connect");
  assert.equal(dialed.length, 1);
});

test("probeTunnel: proxy SOCKS5-only tidak menghabiskan timeout CONNECT (gagal cepat)", async () => {
  const dialed = [];
  const connectFn = async (address) => {
    dialed.push(address.hostname + ":" + address.port);
    return dialed.length === 1
      // Proxy SOCKS5 membalas byte 0x05 lalu menahan koneksi (tanpa "\r\n\r\n").
      ? fakeSocket([new Uint8Array([0x05, 0xff])])
      : fakeSocket([
        new Uint8Array([0x05, 0x00]),
        new Uint8Array([0x05, 0x00, 0x00, 0x03, 11]),
        enc("example.com"),
        new Uint8Array([0x00, 0x50]),
        enc("HTTP/1.1 200 OK\r\n\r\n"),
      ]);
  };

  const started = Date.now();
  const res = await probeTunnel("198.51.100.7", 1080, connectFn, { timeoutMs: 5000 });
  assert.equal(res.ok, true);
  assert.equal(res.protocol, "socks5");
  assert.match(res.detail, /^HTTP\/1\.1 200 OK/);
  assert.deepEqual(dialed, ["198.51.100.7:1080", "198.51.100.7:1080"]);
  assert.ok(Date.now() - started < 3000, "percobaan CONNECT harus gagal cepat, bukan menunggu timeout");
});

test("probeTunnel: kedua handshake gagal -> ok false dengan alasan tiap percobaan", async () => {
  const dialed = [];
  const connectFn = async (address) => {
    dialed.push(address.hostname + ":" + address.port);
    return fakeSocket([enc("bukan proxy\r\n\r\n")]);
  };

  const res = await probeTunnel("192.0.2.1", 9, connectFn, { timeoutMs: 500 });
  assert.equal(res.ok, false);
  assert.equal(res.protocol, null);
  assert.equal(dialed.length, 2);
  assert.match(res.detail, /http-connect: bukan HTTP proxy/);
  assert.match(res.detail, /socks5: bukan SOCKS5/);
  assert.equal(typeof res.ms, "number");
});
