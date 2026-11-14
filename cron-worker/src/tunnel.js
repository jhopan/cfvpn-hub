// Probe tunnel nyata untuk satu baris `proxy_pool`: koneksi TCP ke proxy, handshake HTTP
// CONNECT dulu (fallback SOCKS5), lalu satu permintaan "GET / HTTP/1.0" ke example.com.
// Baris dianggap tembus hanya kalau balasan target memuat "HTTP/1." — bukti paket benar-benar
// diteruskan proxy, bukan sekadar port terbuka (status `is_active`/`ping` dari penyedia daftar
// sudah terbukti bisa hidup di proxy yang 0/3 tembus koneksi TCP nyata dari edge).
//
// Berkas ini sengaja TIDAK meng-import `cloudflare:sockets` (modul itu hanya ada di workerd),
// jadi seluruh logikanya dapat diuji di Node lewat tests/cron-tunnel.test.mjs: pembuat pesan
// SOCKS5, parser balasan SOCKS5/CONNECT, deteksi "HTTP/1.", dan deteksi kolom hilang dari error
// PostgREST. Fungsi `connect` disuntikkan sebagai parameter.
//
//   probeTunnel(host, port, connectFn, { timeoutMs }) -> { ok, protocol, ms, detail }

const PROBE_HOST = "example.com";
const PROBE_PORT = 80;
const PROBE_REQUEST = "GET / HTTP/1.0\r\nHost: " + PROBE_HOST + "\r\n\r\n";
const CONNECT_REQUEST = "CONNECT " + PROBE_HOST + ":" + PROBE_PORT + " HTTP/1.1\r\n" +
  "Host: " + PROBE_HOST + ":" + PROBE_PORT + "\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
const MAX_HEAD_BYTES = 8192;
const MAX_REPLY_BYTES = 8192;
const EMPTY = new Uint8Array(0);

const STATUS_LINE = /^HTTP\/1\.[01]\s+(\d{3})/;

function decoder() {
  return new TextDecoder();
}

// Balasan bisa datang terpecah antar chunk TCP, jadi byte dikumpulkan dulu sebelum diperiksa.
export function concatBytes(a, b) {
  if (!a || !a.length) return b instanceof Uint8Array ? b : new Uint8Array(b || 0);
  if (!b || !b.length) return a;
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

export function toText(bytes) {
  return typeof bytes === "string" ? bytes : decoder().decode(bytes);
}

// ------------------------------------------------------------------ SOCKS5 (RFC 1928) -----

// Tawaran metode: versi 5, satu metode, no-auth (0x00).
export function buildSocks5Greeting() {
  return new Uint8Array([0x05, 0x01, 0x00]);
}

// Balasan metode: VER METHOD. Method 0x00 = lanjut tanpa auth, 0xFF = tidak ada metode cocok.
export function parseSocks5Greeting(bytes) {
  if (!bytes || bytes.length < 2) throw new Error("balasan greeting SOCKS5 terpotong");
  if (bytes[0] !== 0x05) throw new Error("bukan SOCKS5 (versi " + bytes[0] + ")");
  if (bytes[1] !== 0x00) throw new Error("proxy butuh auth (metode " + bytes[1] + ")");
  return bytes[1];
}

// Permintaan CONNECT: VER CMD RSV ATYP DST.ADDR DST.PORT. IPv4 pakai ATYP 0x01, selain itu
// nama domain (ATYP 0x03). IPv6 literal tidak didukung (pool berisi ip:port IPv4).
export function buildSocks5Connect(host, port) {
  const portNumber = Number(port);
  if (!Number.isInteger(portNumber) || portNumber < 1 || portNumber > 65535) {
    throw new Error("port tidak sah: " + port);
  }
  const name = String(host);
  if (name.indexOf(":") !== -1) throw new Error("IPv6 belum didukung SOCKS5 di sini");
  const ipv4 = name.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  let atyp;
  let address;
  if (ipv4) {
    address = new Uint8Array(4);
    for (let i = 0; i < 4; i++) {
      const part = Number(ipv4[i + 1]);
      if (part > 255) throw new Error("alamat IPv4 tidak sah: " + name);
      address[i] = part;
    }
    atyp = 0x01;
  } else {
    address = new TextEncoder().encode(name);
    if (!address.length || address.length > 255) throw new Error("nama domain tidak sah: " + name);
    atyp = 0x03;
  }
  const prefix = atyp === 0x03 ? new Uint8Array([0x05, 0x01, 0x00, atyp, address.length]) : new Uint8Array([0x05, 0x01, 0x00, atyp]);
  const req = new Uint8Array(prefix.length + address.length + 2);
  req.set(prefix, 0);
  req.set(address, prefix.length);
  req[req.length - 2] = (portNumber >> 8) & 0xff;
  req[req.length - 1] = portNumber & 0xff;
  return req;
}

// Balasan permintaan: VER REP RSV ATYP BND.ADDR BND.PORT. REP 0x00 = sukses.
export function parseSocks5Reply(bytes) {
  if (!bytes || bytes.length < 4) throw new Error("balasan SOCKS5 terpotong");
  if (bytes[0] !== 0x05) throw new Error("bukan SOCKS5 (versi " + bytes[0] + ")");
  if (bytes[1] !== 0x00) throw new Error("CONNECT ditolak (REP " + bytes[1] + ")");
  return { reply: bytes[1], atyp: bytes[3] };
}

// Sisa byte BND.ADDR + BND.PORT yang harus dibuang setelah header 4 byte. Untuk ATYP 0x03
// panjang nama ada di byte tambahan (`lengthByte`).
export function socks5BindLength(atyp, lengthByte) {
  if (atyp === 0x01) return 4 + 2;
  if (atyp === 0x04) return 16 + 2;
  if (atyp === 0x03) {
    if (!Number.isInteger(lengthByte)) throw new Error("ATYP 3 tanpa byte panjang");
    return lengthByte + 2;
  }
  throw new Error("ATYP tidak dikenal (" + atyp + ")");
}

// ------------------------------------------------------------------ HTTP -------------------

// Terminator header HTTP; -1 kalau belum lengkap (balasan terpecah).
export function indexOfCrlfCrlf(bytes) {
  for (let i = 0; i + 3 < bytes.length; i++) {
    if (bytes[i] === 13 && bytes[i + 1] === 10 && bytes[i + 2] === 13 && bytes[i + 3] === 10) return i;
  }
  return -1;
}

// Kriteria tembus: balasan memuat "HTTP/1." (HTTP/1.0 atau HTTP/1.1). Balasan yang belum
// lengkap ("HTTP/1", "HTT") sengaja TIDAK dihitung tembus.
export function hasHttp10Reply(data) {
  return toText(data).indexOf("HTTP/1.") !== -1;
}

// Baris status balasan HTTP CONNECT: 200 = tunnel terbuka, selain itu proxy sendiri yang
// menolak (407 butuh auth, 502 gagal dial).
export function parseHttpConnectReply(head) {
  const text = toText(head);
  const match = STATUS_LINE.exec(text);
  if (!match) throw new Error("bukan HTTP proxy: " + JSON.stringify(text.slice(0, 24)));
  const status = Number(match[1]);
  return { ok: status === 200, status: status };
}

// ------------------------------------------------------------------ kolom hilang -----------

// PostgREST menolak kolom yang belum ada di schema cache dengan HTTP 400 + kode PGRST204
// ("Could not find the '<kolom>' column of '<tabel>' in the schema cache"), dan Postgres sendiri
// menjawab 42703 ("column <tabel>.<kolom> does not exist") ketika skema sudah termuat. Dua-duanya
// berarti migrasi kolom tunnel belum dijalankan — bukan alasan menyembunyikan error lain.
export function isMissingColumnError(error) {
  if (!error) return false;
  const code = String(error.code || "");
  if (code === "PGRST204" || code === "42703") return true;
  const message = String(error.message || "");
  if (/could not find .*column/i.test(message)) return true;
  if (/column .*does not exist/i.test(message)) return true;
  return Number(error.status || 0) === 400 && /column/i.test(message);
}

// ------------------------------------------------------------------ runtime probe ----------

function readWithTimeout(promise, ms, label) {
  let timer = null;
  const timeout = new Promise(function (_, reject) {
    timer = setTimeout(function () { reject(new Error(label + ": timeout")); }, ms);
  });
  // Timer selalu dibersihkan: di Node ia menahan event loop, di workerd ia memakan CPU.
  return Promise.race([promise, timeout]).finally(function () { clearTimeout(timer); });
}

// Pembungkus reader yang menyimpan sisa byte antar pembacaan: byte yang datang satu chunk
// bersama data lain (mis. BND.ADDR pada balasan SOCKS5) tidak boleh hilang.
class ByteReader {
  constructor(reader) {
    this.reader = reader;
    this.buf = EMPTY;
  }

  async fill(deadline, label) {
    const remain = deadline - Date.now();
    if (remain <= 0) throw new Error(label + ": timeout");
    const res = await readWithTimeout(this.reader.read(), remain, label);
    if (res.done) throw new Error(label + ": tertutup");
    if (res.value && res.value.length) this.buf = concatBytes(this.buf, res.value);
  }

  async read(n, deadline, label) {
    while (this.buf.length < n) await this.fill(deadline, label);
    const out = this.buf.slice(0, n);
    this.buf = this.buf.slice(n);
    return out;
  }

  // Lihat n byte pertama tanpa memakainya (dipakai untuk gagal cepat pada protokol yang salah).
  async peek(n, deadline, label) {
    while (this.buf.length < n) await this.fill(deadline, label);
    return this.buf.slice(0, n);
  }

  async readUntilCrlfCrlf(deadline, label) {
    for (;;) {
      const at = indexOfCrlfCrlf(this.buf);
      if (at !== -1) {
        const head = this.buf.slice(0, at + 4);
        this.buf = this.buf.slice(at + 4);
        return head;
      }
      if (this.buf.length > MAX_HEAD_BYTES) throw new Error(label + ": header terlalu besar");
      await this.fill(deadline, label);
    }
  }

  cancel() {
    try { this.reader.cancel(); } catch (e) {}
  }
}

async function openHttpConnect(sock, deadline) {
  const writer = sock.writable.getWriter();
  const reader = new ByteReader(sock.readable.getReader());
  try {
    await writer.write(new TextEncoder().encode(CONNECT_REQUEST));
    // Byte pertama harus 'H' ("HTTP/..."): proxy SOCKS5-only membalas byte 0x05 lalu menahan
    // koneksi, dan menunggu "\r\n\r\n" di situ menghabiskan deadline penuh (~6 s) per baris.
    const first = await reader.peek(1, deadline, "http-connect");
    if (first[0] !== 0x48) throw new Error("bukan HTTP proxy (byte pertama " + first[0] + ")");
    const reply = parseHttpConnectReply(await reader.readUntilCrlfCrlf(deadline, "http-connect"));
    if (!reply.ok) throw new Error("CONNECT ditolak (" + reply.status + ")");
    return { writer: writer, reader: reader };
  } catch (err) {
    reader.cancel();
    try { writer.releaseLock(); } catch (e) {}
    throw err;
  }
}

async function openSocks5(sock, deadline) {
  const writer = sock.writable.getWriter();
  const reader = new ByteReader(sock.readable.getReader());
  try {
    await writer.write(buildSocks5Greeting());
    parseSocks5Greeting(await reader.read(2, deadline, "socks5-greeting"));
    await writer.write(buildSocks5Connect(PROBE_HOST, PROBE_PORT));
    const reply = parseSocks5Reply(await reader.read(4, deadline, "socks5-reply"));
    const lengthByte = reply.atyp === 0x03 ? (await reader.read(1, deadline, "socks5-bind-length"))[0] : undefined;
    await reader.read(socks5BindLength(reply.atyp, lengthByte), deadline, "socks5-bind");
    return { writer: writer, reader: reader };
  } catch (err) {
    reader.cancel();
    try { writer.releaseLock(); } catch (e) {}
    throw err;
  }
}

// Kirim permintaan probe lalu tunggu "HTTP/1." pada byte yang terkumpul. Timeout/penutupan
// koneksi diputuskan dari byte yang sudah ada: balasan yang datang penuh lalu langsung ditutup
// (perilaku HTTP/1.0) tetap dihitung tembus.
async function probeHttp(tunnel, deadline) {
  await tunnel.writer.write(new TextEncoder().encode(PROBE_REQUEST));
  let text = toText(tunnel.reader.buf);
  tunnel.reader.buf = EMPTY;
  for (;;) {
    if (hasHttp10Reply(text)) return text.split("\r\n")[0];
    if (text.length > MAX_REPLY_BYTES) throw new Error("balasan terlalu besar");
    try {
      await tunnel.reader.fill(deadline, "probe-http");
    } catch (err) {
      if (hasHttp10Reply(text)) return text.split("\r\n")[0];
      throw err;
    }
    text += toText(tunnel.reader.buf);
    tunnel.reader.buf = EMPTY;
  }
}

// Dua percobaan berurutan, masing-masing dengan deadline sendiri sepanjang `timeoutMs`
// (~6 s): kandidat mati harus gagal cepat, kalau tidak anggaran subrequest/CPU satu siklus
// cron habis di beberapa baris saja.
export async function probeTunnel(host, port, connectFn, options) {
  const opts = options || {};
  const timeoutMs = opts.timeoutMs || 6000;
  const attempts = [];
  const started = Date.now();

  for (const attempt of [{ protocol: "http-connect", open: openHttpConnect }, { protocol: "socks5", open: openSocks5 }]) {
    const attemptStart = Date.now();
    const deadline = attemptStart + timeoutMs;
    let sock = null;
    let tunnel = null;
    try {
      sock = await connectFn({ hostname: host, port: port });
      tunnel = await attempt.open(sock, deadline);
      const line = await probeHttp(tunnel, deadline);
      return { ok: true, protocol: attempt.protocol, ms: Date.now() - attemptStart, detail: line };
    } catch (err) {
      attempts.push(attempt.protocol + ": " + (err && err.message ? err.message : String(err)));
    } finally {
      if (tunnel) {
        tunnel.reader.cancel();
        try { tunnel.writer.releaseLock(); } catch (e) {}
      }
      if (sock) { try { sock.close(); } catch (e) {} }
    }
  }

  return { ok: false, protocol: null, ms: Date.now() - started, detail: attempts.join(" | ") };
}
