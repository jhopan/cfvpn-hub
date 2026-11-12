// CFVPN Hub - VPN Worker (VLESS over WebSocket)
//
// Alur:
//   WebSocket + path /ip:port  -> VLESS tunnel lewat proxy
//   cmd=2 port 53 (DNS)        -> dijawab worker sendiri lewat DoH, tanpa relay UDP
//   cmd=2 port lain (UDP)      -> ditutup cepat (Workers tidak punya UDP keluar)
//   /health                    -> health check JSON
//   /myip                      -> info IP client
//   HTTP biasa                 -> reverse proxy (kamuflase)
//
// Proxy dipakai lewat SOCKS5 dulu, lalu HTTP CONNECT. Protokol dideteksi
// dari respons, bukan dari nomor port (proxy SOCKS5 sering di 443).

import { connect } from "cloudflare:sockets";

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
const MAX_HEADER_BYTES = 4096;

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);

      if (request.headers.get("Upgrade") === "websocket") {
        const m = url.pathname.match(/^\/(.+[:=-]\d+)$/);
        if (m) {
          const prxIP = m[1].replace("-", ":");
          return await websocketHandler(request, prxIP, env);
        }
      }

      if (url.pathname === "/health") {
        return new Response(
          JSON.stringify({ ok: true, colo: request.cf?.colo, ts: Date.now() }),
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

async function websocketHandler(request, prxIP, env) {
  const pair = new WebSocketPair();
  const client = pair[0];
  const webSocket = pair[1];
  webSocket.accept();

  const state = { remote: null, cancelled: false, headerBuf: null, versionBytes: null, udpPrefixed: null, udpBuf: new Uint8Array(0), responseHeaderSent: false };
  const earlyData = request.headers.get("sec-websocket-protocol") || "";

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
        if (!state.cancelled) {
          try { controller.close(); } catch (err) {}
        }
        safeClose(webSocket);
      });
      webSocket.addEventListener("error", function () {
        if (!state.cancelled) {
          try { controller.error(new Error("ws error")); } catch (err) {}
        }
        safeClose(webSocket);
      });
    },
    cancel() {
      state.cancelled = true;
      shutdownRemote(state, false);
    },
  });

  incoming
    .pipeTo(new WritableStream({
      async write(chunk) {
        await handleClientChunk(chunk, state, webSocket, prxIP, env);
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

async function handleClientChunk(chunk, state, webSocket, prxIP, env) {
  if (state.remote) {
    const w = state.remote.writable.getWriter();
    try {
      await w.write(chunk);
    } finally {
      w.releaseLock();
    }
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
    await openRawTunnel(bytes, webSocket, state, prxIP);
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

  if (!isUuidAllowed(header.uuid, env)) {
    safeClose(webSocket);
    return;
  }

  if (header.isUDP) {
    if (header.portRemote !== 53) {
      // Workers tidak punya UDP keluar, dan relay UDP eksternal sudah tidak tersedia,
      // jadi UDP selain DNS ditutup cepat dengan alasan yang jelas (bukan menggantung).
      console.log("udp port " + header.portRemote + " tidak didukung");
      safeClose(webSocket);
      return;
    }
    state.versionBytes = header.version;
    for (const message of takeDnsMessages(state, new Uint8Array(header.rawClientData))) {
      await handleDnsQuery(message, state, webSocket, env);
    }
    return;
  }

  // Cloudflare memblokir connect() ke port HTTP/HTTPS (80/443):
  //   "cannot connect to the specified address. It looks like you might be
  //    trying to connect to a HTTP-based service - consider using fetch"
  // Jadi SEMUA koneksi harus lewat proxy, tidak ada jalur direct.
  await tryViaProxy(header, webSocket, state, prxIP);
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
  let answer;
  try {
    answer = await resolveDoh(message, env);
  } catch (err) {
    console.log("doh gagal: " + (err && err.message));
    return;
  }
  if (state.cancelled || webSocket.readyState !== WS_OPEN) return;
  sendVlessPayload(state, webSocket, answer);
}

function sendVlessPayload(state, webSocket, payload) {
  const parts = [];
  if (!state.responseHeaderSent) {
    state.responseHeaderSent = true;
    parts.push(state.versionBytes || new Uint8Array([0, 0]));
  }
  if (state.udpPrefixed) parts.push(new Uint8Array([(payload.length >> 8) & 0xff, payload.length & 0xff]));
  parts.push(payload);

  let out = new Uint8Array(0);
  for (const part of parts) out = concatBytes(out, part);
  webSocket.send(out);
}

async function resolveDoh(query, env) {
  const endpoint = (env && env.DOH_ENDPOINT) || DOH_ENDPOINT;
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

async function openRawTunnel(bytes, webSocket, state, prxIP) {
  const parts = String(prxIP).split(":");
  const sock = connect({
    hostname: parts[0],
    port: Number(parts[1] || 443),
    secureTransport: "off",
  });
  const w = sock.writable.getWriter();
  await w.write(bytes);
  w.releaseLock();
  state.remote = { readable: sock.readable, writable: sock.writable, close: function () { sock.close(); } };
  pipeRemoteToWs(state.remote, webSocket, null);
}

async function tryViaProxy(header, webSocket, state, prxIP) {
  const parts = String(prxIP).split(":");
  const proxyHost = parts[0];
  const proxyPort = Number(parts[1] || 443);

  try {
    const tunnel = await openProxyTunnel(
      proxyHost, proxyPort, header.addressRemote, header.portRemote, PROXY_HANDSHAKE_TIMEOUT
    );
    const w = tunnel.writable.getWriter();
    await w.write(new Uint8Array(header.rawClientData));
    w.releaseLock();
    state.remote = tunnel;
    pipeRemoteToWs(tunnel, webSocket, header.version);
  } catch (err) {
    console.log("proxy gagal: " + err.message);
    safeClose(webSocket);
  }
}

async function openProxyTunnel(proxyHost, proxyPort, targetHost, targetPort, timeoutMs) {
  const errors = [];
  try {
    return await socks5Tunnel(proxyHost, proxyPort, targetHost, targetPort, timeoutMs);
  } catch (e) {
    errors.push("socks5: " + e.message);
  }
  try {
    return await httpConnectTunnel(proxyHost, proxyPort, targetHost, targetPort, timeoutMs);
  } catch (e) {
    errors.push("http: " + e.message);
  }
  throw new Error(errors.join(" | "));
}

async function socks5Tunnel(proxyHost, proxyPort, targetHost, targetPort, timeoutMs) {
  const sock = connect({ hostname: proxyHost, port: proxyPort, secureTransport: "off" });
  const writer = sock.writable.getWriter();
  const reader = sock.readable.getReader();

  try {
    await writer.write(new Uint8Array([0x05, 0x01, 0x00]));
    const g = await readBytes(reader, 2, timeoutMs, "socks5-greeting");
    if (g.bytes[0] !== 0x05) throw new Error("bukan SOCKS5");
    if (g.bytes[1] !== 0x00) throw new Error("butuh auth");

    const hostBytes = new TextEncoder().encode(targetHost);
    const req = new Uint8Array(5 + hostBytes.length + 2);
    req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x03;
    req[4] = hostBytes.length;
    req.set(hostBytes, 5);
    new DataView(req.buffer).setUint16(5 + hostBytes.length, targetPort);
    await writer.write(req);

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

async function httpConnectTunnel(proxyHost, proxyPort, targetHost, targetPort, timeoutMs) {
  const sock = connect({ hostname: proxyHost, port: proxyPort, secureTransport: "off" });
  const writer = sock.writable.getWriter();
  const reader = sock.readable.getReader();

  try {
    const req = "CONNECT " + targetHost + ":" + targetPort + " HTTP/1.1\r\n" +
      "Host: " + targetHost + ":" + targetPort + "\r\n" +
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

  return { readable: readable, writable: writable, close: function () { sock.close(); } };
}

async function readBytes(reader, n, timeoutMs, label) {
  const chunks = [];
  let total = 0;
  const deadline = Date.now() + timeoutMs;

  while (total < n) {
    const remain = deadline - Date.now();
    if (remain <= 0) throw new Error(label + ": timeout");

    const res = await Promise.race([
      reader.read(),
      new Promise(function (_, rej) { setTimeout(function () { rej(new Error(label + ": timeout")); }, remain); }),
    ]);
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

    const res = await Promise.race([
      reader.read(),
      new Promise(function (_, rej) { setTimeout(function () { rej(new Error(label + ": timeout")); }, remain); }),
    ]);
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
  if (cmd !== 1 && cmd !== 2) return { invalid: "cmd " + cmd };

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

  const uuid = Array.from(view.slice(1, 17)).map(function (b) { return b.toString(16).padStart(2, "0"); }).join("");

  return {
    header: {
      uuid: uuid,
      addressRemote: addressRemote,
      portRemote: portRemote,
      rawClientData: view.slice(total),
      version: new Uint8Array([version, 0]),
      isUDP: cmd === 2,
    },
  };
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

function isUuidAllowed(uuid, env) {
  if (!env) return true;
  const allowlist = env.UUID_ALLOWLIST;
  if (!allowlist) return true;
  const list = allowlist.split(",").map(function (u) { return u.trim().toLowerCase(); }).filter(Boolean);
  if (!list.length) return true;
  const hex = String(uuid || "").toLowerCase();
  const dashed = hex.length === 32
    ? hex.slice(0, 8) + "-" + hex.slice(8, 12) + "-" + hex.slice(12, 16) + "-" + hex.slice(16, 20) + "-" + hex.slice(20)
    : hex;
  return list.indexOf(hex) !== -1 || list.indexOf(dashed) !== -1;
}

async function pipeRemoteToWs(remote, webSocket, responseHeader) {
  let header = responseHeader;

  try {
    await remote.readable.pipeTo(new WritableStream({
      async write(chunk) {
        if (webSocket.readyState !== WS_OPEN) return;
        if (header) {
          const merged = new Uint8Array(header.length + chunk.length);
          merged.set(header, 0);
          merged.set(chunk, header.length);
          webSocket.send(merged);
          header = null;
        } else {
          webSocket.send(chunk);
        }
      },
      close() {},
      abort(reason) {
        console.log("pipe abort: " + reason);
      },
    }));
  } catch (err) {
    console.log("pipe error: " + (err && err.message));
    safeClose(webSocket);
    return;
  }

  // Target sudah menutup koneksi: jangan biarkan WebSocket menggantung.
  safeClose(webSocket);
}

function shutdownRemote(state, graceful) {
  const remote = state.remote;
  state.remote = null;
  if (!remote) return;
  if (graceful) {
    try {
      remote.writable.getWriter().close().catch(function () {
        try { remote.close(); } catch (e) {}
      });
      return;
    } catch (e) {}
  }
  try { remote.close(); } catch (e) {}
}

function safeClose(socket) {
  try {
    if (socket.readyState === WS_OPEN || socket.readyState === WS_CLOSING) socket.close();
  } catch (e) {}
}
