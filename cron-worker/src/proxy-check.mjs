// Pengecekan proxy tanpa API eksternal: buka tunnel SOCKS5/HTTP CONNECT lewat proxy,
// lalu minta satu halaman HTTP kecil. Dipakai cron-worker (Cloudflare) dan diuji di Node
// lewat tests/check-proxy.mjs (fungsi `connect` disuntikkan, jadi bisa dites di luar workerd).
//
// checkProxy(host, port, connectFn, {timeoutMs}) -> {alive, protocol, ms, detail}

const PROBE_HOST = "cp.cloudflare.com";
const PROBE_PORT = 80;
const PROBE_PATH = "/generate_204";
const PROBE_REQUEST = "GET " + PROBE_PATH + " HTTP/1.0\r\nHost: " + PROBE_HOST + "\r\nConnection: close\r\n\r\n";
const MAX_REPLY_HEADER = 8192;

function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function timeoutPromise(ms, label) {
  return new Promise(function (_, rej) {
    setTimeout(function () { rej(new Error(label + ": timeout")); }, ms);
  });
}

// Pembungkus reader yang menyimpan sisa byte antar pembacaan: tanpa ini, byte yang
// datang dalam satu chunk bersama data lain (mis. BND.ADDR pada balasan SOCKS5) hilang.
class ChunkReader {
  constructor(reader) {
    this.reader = reader;
    this.buf = new Uint8Array(0);
  }

  async fill(deadline, label) {
    const remain = deadline - Date.now();
    if (remain <= 0) throw new Error(label + ": timeout");
    const res = await Promise.race([this.reader.read(), timeoutPromise(remain, label)]);
    if (res.done) throw new Error(label + ": tertutup");
    if (!res.value || !res.value.length) return;
    this.buf = concat(this.buf, res.value);
  }

  async read(n, deadline, label) {
    while (this.buf.length < n) await this.fill(deadline, label);
    const out = this.buf.slice(0, n);
    this.buf = this.buf.slice(n);
    return out;
  }

  async readUntilCrlfCrlf(deadline, label) {
    for (;;) {
      for (let i = 0; i + 3 < this.buf.length; i++) {
        if (this.buf[i] === 13 && this.buf[i + 1] === 10 && this.buf[i + 2] === 13 && this.buf[i + 3] === 10) {
          const head = this.buf.slice(0, i + 4);
          this.buf = this.buf.slice(i + 4);
          return head;
        }
      }
      if (this.buf.length > MAX_REPLY_HEADER) throw new Error(label + ": header terlalu besar");
      await this.fill(deadline, label);
    }
  }

  cancel() {
    try { this.reader.cancel(); } catch (e) {}
  }
}

async function openSocks5(sock, deadline) {
  const writer = sock.writable.getWriter();
  const reader = new ChunkReader(sock.readable.getReader());
  try {
    await writer.write(new Uint8Array([0x05, 0x01, 0x00]));
    const greeting = await reader.read(2, deadline, "socks5-greeting");
    if (greeting[0] !== 0x05) throw new Error("bukan SOCKS5");
    if (greeting[1] !== 0x00) throw new Error("butuh auth (" + greeting[1] + ")");

    const target = new TextEncoder().encode(PROBE_HOST);
    const req = new Uint8Array(5 + target.length + 2);
    req[0] = 0x05;
    req[1] = 0x01;
    req[2] = 0x00;
    req[3] = 0x03;
    req[4] = target.length;
    req.set(target, 5);
    req[5 + target.length] = (PROBE_PORT >> 8) & 0xff;
    req[6 + target.length] = PROBE_PORT & 0xff;
    await writer.write(req);

    const reply = await reader.read(4, deadline, "socks5-reply");
    if (reply[1] !== 0x00) throw new Error("CONNECT ditolak (" + reply[1] + ")");
    const atyp = reply[3];
    let bindLength;
    if (atyp === 0x01) bindLength = 4 + 2;
    else if (atyp === 0x04) bindLength = 16 + 2;
    else if (atyp === 0x03) {
      const labelLength = await reader.read(1, deadline, "socks5-bind-len");
      bindLength = labelLength[0] + 2;
    } else throw new Error("ATYP " + atyp);
    await reader.read(bindLength, deadline, "socks5-bind");
    return { writer: writer, reader: reader };
  } catch (err) {
    reader.cancel();
    try { writer.releaseLock(); } catch (e) {}
    throw err;
  }
}

async function openHttpConnect(sock, deadline) {
  const writer = sock.writable.getWriter();
  const reader = new ChunkReader(sock.readable.getReader());
  try {
    const req = "CONNECT " + PROBE_HOST + ":" + PROBE_PORT + " HTTP/1.1\r\n" +
      "Host: " + PROBE_HOST + ":" + PROBE_PORT + "\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
    await writer.write(new TextEncoder().encode(req));

    const head = new TextDecoder().decode(await reader.readUntilCrlfCrlf(deadline, "http-connect"));
    const status = head.match(/^HTTP\/1\.[01]\s+(\d{3})/);
    if (!status) throw new Error("bukan HTTP proxy");
    if (Number(status[1]) !== 200) throw new Error("CONNECT ditolak (" + status[1] + ")");
    return { writer: writer, reader: reader };
  } catch (err) {
    reader.cancel();
    try { writer.releaseLock(); } catch (e) {}
    throw err;
  }
}

async function probeHttp(tunnel, deadline) {
  await tunnel.writer.write(new TextEncoder().encode(PROBE_REQUEST));
  let buf = new Uint8Array(0);
  while (buf.length < 24) {
    const remain = deadline - Date.now();
    if (remain <= 0) break;
    try {
      await tunnel.reader.fill(deadline, "probe-http");
    } catch (e) {
      break;
    }
    buf = concat(buf, tunnel.reader.buf);
    tunnel.reader.buf = new Uint8Array(0);
  }
  const text = new TextDecoder().decode(buf.slice(0, 64));
  // 2xx/3xx dari target = tunnel benar-benar jalan. Balasan 407/502 dari proxy itu sendiri
  // (butuh auth / gagal dial) tidak dihitung hidup.
  if (!/^HTTP\/1\.[01]\s+[23]\d\d/.test(text)) throw new Error("bukan respons target: " + JSON.stringify(text.slice(0, 24)));
  return text.split("\r\n")[0];
}

export async function checkProxy(host, port, connectFn, options) {
  const opts = options || {};
  const timeoutMs = opts.timeoutMs || 6000;
  const socksTimeoutMs = opts.socksTimeoutMs || timeoutMs;
  const httpTimeoutMs = opts.httpTimeoutMs || timeoutMs;
  const probeTimeoutMs = opts.probeTimeoutMs || timeoutMs;
  const attempts = [];

  for (const [label, opener, stageTimeout] of [["socks5", openSocks5, socksTimeoutMs], ["http", openHttpConnect, httpTimeoutMs]]) {
    // Deadline sendiri per percobaan/tahap: kandidat mati harus gagal cepat, kalau tidak
    // biaya verifikasi massal membengkak (14 ribu kandidat x 12 detik tidak mungkin).
    const started = Date.now();
    let sock = null;
    let tunnel = null;
    try {
      sock = await connectFn({ hostname: host, port: port });
      tunnel = await opener(sock, started + stageTimeout);
      const status = await probeHttp(tunnel, Date.now() + probeTimeoutMs);
      tunnel.reader.cancel();
      try { tunnel.writer.releaseLock(); } catch (e) {}
      sock.close();
      return { alive: true, protocol: label, ms: Date.now() - started, detail: status };
    } catch (err) {
      attempts.push(label + ": " + err.message);
      try { if (tunnel) tunnel.reader.cancel(); } catch (e) {}
      try { if (sock) sock.close(); } catch (e) {}
    }
  }

  return { alive: false, protocol: null, ms: timeoutMs, detail: attempts.join(" | ") };
}
