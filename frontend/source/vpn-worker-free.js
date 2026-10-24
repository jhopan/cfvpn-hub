// CFVPN Hub - VPN Worker (VLESS over WebSocket)
//
// Alur:
//   WebSocket + path /ip:port  -> VLESS tunnel lewat proxy
//   /health                    -> health check JSON
//   /myip                      -> info IP client
//   HTTP biasa                 -> reverse proxy (kamuflase)
//
// Proxy dipakai lewat SOCKS5 dulu, lalu HTTP CONNECT. Protokol dideteksi
// dari respons, bukan dari nomor port (proxy SOCKS5 sering di 443).

import { connect } from "cloudflare:sockets";

const DNS_SERVER_ADDRESS = "8.8.8.8";
const DNS_SERVER_PORT = 53;
const RELAY_SERVER_UDP = { host: "udp-relay.hobihaus.space", port: 7300 };

const WS_OPEN = 1;
const WS_CLOSING = 2;
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
  "Access-Control-Max-Age": "86400",
};

const PROXY_HANDSHAKE_TIMEOUT = 8000;

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

  const state = { remote: null, isDNS: false, cancelled: false };
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
    },
  });

  incoming
    .pipeTo(new WritableStream({
      async write(chunk) {
        await handleClientChunk(chunk, state, webSocket, prxIP, env);
      },
    }))
    .catch(function () { safeClose(webSocket); });

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

  const header = readVlessHeader(chunk);

  if (header.hasError) {
    const parts = String(prxIP).split(":");
    const sock = connect({
      hostname: parts[0],
      port: Number(parts[1] || 443),
      secureTransport: "off",
    });
    const w = sock.writable.getWriter();
    await w.write(chunk);
    w.releaseLock();
    state.remote = { readable: sock.readable, writable: sock.writable, closed: sock.closed, close: function () { sock.close(); } };
    pipeRemoteToWs(state.remote, webSocket, null, null);
    return;
  }

  if (!isUuidAllowed(header.uuid, env)) {
    safeClose(webSocket);
    return;
  }

  if (header.isUDP) {
    if (header.portRemote === 53) state.isDNS = true;
    const targetHost = state.isDNS ? DNS_SERVER_ADDRESS : header.addressRemote;
    const targetPort = state.isDNS ? DNS_SERVER_PORT : header.portRemote;
    const sock = await openUdpRelay(targetHost, targetPort, RELAY_SERVER_UDP);
    const w = sock.writable.getWriter();
    await w.write(chunk);
    w.releaseLock();
    state.remote = sock;
    pipeRemoteToWs(sock, webSocket, null, null);
    return;
  }

  if (tryDirect(header, webSocket, state)) return;

  await tryViaProxy(header, webSocket, state, prxIP);
}

function tryDirect(header, webSocket, state) {
  try {
    const isTLS = header.portRemote === 443 || header.portRemote === 8443;
    const sock = connect({
      hostname: header.addressRemote,
      port: header.portRemote,
      secureTransport: isTLS ? "on" : "off",
    });
    state.remote = { readable: sock.readable, writable: sock.writable, closed: sock.closed, close: function () { sock.close(); } };
    const w = sock.writable.getWriter();
    w.write(new Uint8Array(header.rawClientData)).then(function () { w.releaseLock(); }).catch(function () {});
    pipeRemoteToWs(state.remote, webSocket, header.version, null);
    return true;
  } catch (e) {
    return false;
  }
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
    pipeRemoteToWs(tunnel, webSocket, header.version, null);
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

  return { readable: readable, writable: writable, closed: sock.closed, close: function () { sock.close(); } };
}

async function openUdpRelay(targetHost, targetPort, relay) {
  const isTLS = relay.port === 443;
  const sock = connect({ hostname: relay.host, port: relay.port, secureTransport: isTLS ? "on" : "off" });
  const header = new TextEncoder().encode("udp:" + targetHost + ":" + targetPort);
  const sep = new Uint8Array([0x7c]);
  const w = sock.writable.getWriter();
  await w.write(header);
  await w.write(sep);
  w.releaseLock();
  return { readable: sock.readable, writable: sock.writable, closed: sock.closed, close: function () { sock.close(); } };
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

function readVlessHeader(buffer) {
  if (!buffer || buffer.byteLength < 24) return { hasError: true, message: "terlalu pendek" };

  const view = new Uint8Array(buffer);
  const version = view[0];
  const uuid = Array.from(view.slice(1, 17)).map(function (b) { return b.toString(16).padStart(2, "0"); }).join("");

  const optLength = view[17];
  const cmd = view[18 + optLength];
  let isUDP = false;
  if (cmd === 2) isUDP = true;
  else if (cmd !== 1) return { hasError: true, message: "cmd " + cmd };

  const portIndex = 18 + optLength + 1;
  const portRemote = (view[portIndex] << 8) | view[portIndex + 1];
  let i = portIndex + 2;
  const atyp = view[i];
  i += 1;

  let addressRemote = "";
  if (atyp === 1) {
    addressRemote = [view[i], view[i + 1], view[i + 2], view[i + 3]].join(".");
    i += 4;
  } else if (atyp === 2) {
    const len = view[i];
    i += 1;
    addressRemote = new TextDecoder().decode(view.slice(i, i + len));
    i += len;
  } else if (atyp === 3) {
    const parts = [];
    for (let k = 0; k < 8; k++) {
      parts.push(((view[i + k * 2] << 8) | view[i + k * 2 + 1]).toString(16));
    }
    addressRemote = parts.join(":");
    i += 16;
  } else {
    return { hasError: true, message: "atyp " + atyp };
  }

  return {
    hasError: false,
    uuid: uuid,
    addressRemote: addressRemote,
    portRemote: portRemote,
    rawClientData: view.slice(i),
    version: new Uint8Array([version, 0]),
    isUDP: isUDP,
  };
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

async function pipeRemoteToWs(remote, webSocket, responseHeader, onNoData) {
  let header = responseHeader;
  let gotData = false;

  try {
    await remote.readable.pipeTo(new WritableStream({
      async write(chunk) {
        gotData = true;
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

  if (!gotData && onNoData) onNoData();
}

function safeClose(socket) {
  try {
    if (socket.readyState === WS_OPEN || socket.readyState === WS_CLOSING) socket.close();
  } catch (e) {}
}
