import { connect } from "cloudflare:sockets";

const DNS_SERVER_ADDRESS = "8.8.8.8";
const DNS_SERVER_PORT = 53;
const RELAY_SERVER_UDP = {
  host: "udp-relay.hobihaus.space",
  port: 7300,
};

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
const CORS_HEADER_OPTIONS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
  "Access-Control-Max-Age": "86400",
};

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);

      if (request.headers.get("Upgrade") === "websocket") {
        const prxMatch = url.pathname.match(/^\/(.+[:=-]\d+)$/);
        if (prxMatch) {
          // prxIP harus per-koneksi, bukan variabel global (selain itu user
          // saling menimpa proxy masing-masing)
          const prxIP = prxMatch[1].replace("-", ":");
          return await websocketHandler(request, prxIP, env || {});
        }
      }

      // Health check: worker hidup? (dipakai deploy script)
      if (url.pathname === "/health") {
        return new Response(
          JSON.stringify({ ok: true, colo: request.cf?.colo, ts: Date.now() }),
          { headers: { ...CORS_HEADER_OPTIONS, "Content-Type": "application/json" } }
        );
      }

      if (url.pathname.startsWith("/myip")) {
        return new Response(JSON.stringify({
          ip: request.headers.get("cf-connecting-ip") || request.headers.get("x-real-ip"),
          colo: request.headers.get("cf-ray")?.split("-")[1],
          ...request.cf,
        }), { headers: CORS_HEADER_OPTIONS });
      }

      const targetReversePrx = env.REVERSE_PRX_TARGET || "example.com";
      const targetUrl = new URL(request.url);
      targetUrl.hostname = targetReversePrx;
      const modifiedRequest = new Request(targetUrl, request);
      modifiedRequest.headers.set("X-Forwarded-Host", request.headers.get("Host"));
      const response = await fetch(modifiedRequest);
      const newResponse = new Response(response.body, response);
      for (const [k, v] of Object.entries(CORS_HEADER_OPTIONS)) newResponse.headers.set(k, v);
      return newResponse;
    } catch (err) {
      return new Response(`Error: ${err.message}`, { status: 500, headers: CORS_HEADER_OPTIONS });
    }
  },
};

async function websocketHandler(request, prxIP, env) {
  // PENTING: jangan pakai Object.values(new WebSocketPair()) - urutan key
  // tidak dijamin oleh spec, bisa terbalik (client <-> server).
  const pair = new WebSocketPair();
  const client = pair[0];
  const webSocket = pair[1];
  webSocket.accept();

  let remoteSocketWrapper = { value: null };
  let isDNS = false;

  let readableStreamCancel = false;
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
  let streamController = null;
  const readableWebSocketStream = new ReadableStream({
    start(controller) {
      streamController = controller;
      if (earlyDataHeader) {
        try {
          // Jangan enqueue di start(): consumer belum siap, Workers throw
          // "Cannot enqueue to a closed stream". Tunda sampai stream ter-pull.
          const earlyData = Uint8Array.from(atob(earlyDataHeader.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0)).buffer;
          queueMicrotask(() => {
            try {
              if (!readableStreamCancel && streamController) {
                streamController.enqueue(earlyData);
              }
            } catch (e) {
              console.log("earlyData enqueue gagal:", e.message);
            }
          });
        } catch(e) {
          // earlyData bukan base64 valid -> abaikan, koneksi tetap jalan
        }
      }
      webSocket.addEventListener("message", (e) => {
        if (!readableStreamCancel) controller.enqueue(e.data);
      });
      webSocket.addEventListener("close", () => {
        if (!readableStreamCancel) controller.close();
        safeCloseWebSocket(webSocket);
      });
      webSocket.addEventListener("error", () => {
        if (!readableStreamCancel) controller.error(new Error("WS error"));
        safeCloseWebSocket(webSocket);
      });
    },
    cancel() {
      readableStreamCancel = true;
      try { streamController?.close(); } catch {}
    }
  });

  readableWebSocketStream.pipeTo(new WritableStream({
    async write(chunk) {
      if (isDNS) {
        return handleUDPOutbound(DNS_SERVER_ADDRESS, DNS_SERVER_PORT, chunk, webSocket, null, RELAY_SERVER_UDP);
      }
      if (remoteSocketWrapper.value) {
        const writer = remoteSocketWrapper.value.writable.getWriter();
        await writer.write(chunk);
        writer.releaseLock();
        return;
      }

      const vlessHeader = readVlessHeader(chunk);
      if (vlessHeader.hasError) {
        // bukan header VLESS -> bypass (mode raw TCP, misal SSH tunnel)
        const parts = prxIP.split(":");
        const tcpSocket = connect({
          hostname: parts[0],
          port: Number(parts[1] || 443),
          secureTransport: "off",
        });
        remoteSocketWrapper.value = tcpSocket;
        const writer = tcpSocket.writable.getWriter();
        writer.write(chunk);
        writer.releaseLock();
        remoteSocketToWS(tcpSocket, webSocket, null, null);
        return;
      }

      // Validasi UUID. Tanpa ini worker = open relay untuk siapa saja.
      // Allowlist diisi lewat env UUID_ALLOWLIST (comma separated) atau KV.
      if (!isUuidAllowed(vlessHeader.uuid, env)) {
        console.log(`UUID ditolak: ${vlessHeader.uuid}`);
        safeCloseWebSocket(webSocket);
        return;
      }

      if (vlessHeader.isUDP) {
        if (vlessHeader.portRemote === 53) isDNS = true;
        return handleUDPOutbound(
          isDNS ? DNS_SERVER_ADDRESS : vlessHeader.addressRemote,
          isDNS ? DNS_SERVER_PORT : vlessHeader.portRemote,
          chunk,
          webSocket,
          vlessHeader.version,
          RELAY_SERVER_UDP
        );
      }

      handleTCPOutBound(
        remoteSocketWrapper,
        vlessHeader.addressRemote,
        vlessHeader.portRemote,
        vlessHeader.rawClientData,
        webSocket,
        vlessHeader.version,
        prxIP
      );
    }
  })).catch(() => {
    safeCloseWebSocket(webSocket);
  });

  return new Response(null, { status: 101, webSocket: client });
}

/**
 * Validasi UUID user.
 * - env.UUID_ALLOWLIST = "uuid1,uuid2" (comma separated)
 * - env.UUID_KV = nama binding KV, kalau diisi UUID diambil dari KV key "uuids"
 * Kalau tidak ada allowlist -> semua UUID diterima (mode terbuka, untuk dev).
 */
function isUuidAllowed(uuid, env) {
  if (!env) return true;
  const allowlist = env.UUID_ALLOWLIST;
  if (!allowlist) return true;
  const list = allowlist.split(",").map((u) => u.trim().toLowerCase()).filter(Boolean);
  if (!list.length) return true;
  // allowlist ditulis sebagai UUID berformat (8-4-4-4-12), sedangkan
  // VLESS uuid datang sebagai 32 hex tanpa dash.
  const hex = String(uuid || "").toLowerCase();
  const dashed = hex.length === 32
    ? `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`
    : hex;
  return list.includes(hex) || list.includes(dashed);
}

function readVlessHeader(buffer) {
  if (buffer.byteLength < 24) return { hasError: true, message: "Invalid data length" };
  const version = new Uint8Array(buffer.slice(0, 1));
  let isUDP = false;
  const optLength = new Uint8Array(buffer.slice(17, 18))[0];
  const cmd = new Uint8Array(buffer.slice(18 + optLength, 18 + optLength + 1))[0];

  if (cmd === 2) isUDP = true;
  else if (cmd !== 1) return { hasError: true, message: `Invalid VLESS command: ${cmd}` };

  const portIndex = 18 + optLength + 1;
  const portRemote = new DataView(buffer.slice(portIndex, portIndex + 2)).getUint16(0);
  let addressIndex = portIndex + 2;
  const addressType = new Uint8Array(buffer.slice(addressIndex, addressIndex + 1))[0];
  addressIndex += 1;

  let addressLength = 0;
  let addressValue = "";

  if (addressType === 1) {
    addressLength = 4;
    addressValue = new Uint8Array(buffer.slice(addressIndex, addressIndex + addressLength)).join(".");
  } else if (addressType === 2) {
    addressLength = new Uint8Array(buffer.slice(addressIndex, addressIndex + 1))[0];
    addressIndex += 1;
    addressValue = new TextDecoder().decode(buffer.slice(addressIndex, addressIndex + addressLength));
  } else if (addressType === 3) {
    addressLength = 16;
    const dataView = new DataView(buffer.slice(addressIndex, addressIndex + addressLength));
    const ipv6 = [];
    for (let i = 0; i < 8; i++) ipv6.push(dataView.getUint16(i * 2).toString(16));
    addressValue = ipv6.join(":");
  } else {
    return { hasError: true, message: `Invalid VLESS address type: ${addressType}` };
  }

  // UUID = 16 byte pada offset 2..18
  const uuid = Array.from(new Uint8Array(buffer.slice(2, 18)))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return {
    hasError: false,
    uuid,
    addressRemote: addressValue,
    portRemote,
    rawClientData: buffer.slice(addressIndex + addressLength),
    version: new Uint8Array([version[0], 0]),
    isUDP,
  };
}

/**
 * Connect ke tujuan lewat proxy HTTP atau SOCKS5.
 * - HTTP   : CONNECT host:port HTTP/1.1
 * - SOCKS5 : greeting 0x05, lalu CONNECT
 * Port proxy 1080/9050/1081 -> SOCKS5, selain itu HTTP.
 *
 * PENTING: sock.readable hanya boleh dibaca SEKALI. Setelah reader dipakai,
 * stream terkunci. Jadi handshake dibaca via reader, lalu stream di-"reconstruct"
 * supaya sisa byte (bila ada) tetap bisa diteruskan.
 */
async function connectViaProxy(proxyIP, proxyPort, targetHost, targetPort) {
  // Port SOCKS5/SOCKS4 umum. Port lain dianggap HTTP proxy.
  const isSocks = [1080, 9050, 1081, 9051, 1082, 4145, 9150].includes(Number(proxyPort));
  const sock = connect({ hostname: proxyIP, port: proxyPort, secureTransport: "off" });
  const writer = sock.writable.getWriter();
  const reader = sock.readable.getReader();

  try {
    if (isSocks) {
      // greeting: ver 5, 1 method, no auth
      await writer.write(new Uint8Array([0x05, 0x01, 0x00]));
      const greet = await reader.read();
      if (!greet.value || greet.value[0] !== 0x05) throw new Error("bukan SOCKS5");
      if (greet.value[1] !== 0x00) throw new Error("SOCKS5 butuh auth");

      // CONNECT ke target (domain name = ATYP 0x03)
      const hostBytes = new TextEncoder().encode(targetHost);
      const req = new Uint8Array(7 + hostBytes.length);
      req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x03;
      req[4] = hostBytes.length;
      req.set(hostBytes, 5);
      const portBuf = new Uint8Array(2);
      new DataView(portBuf.buffer).setUint16(0, targetPort);
      req.set(portBuf, 5 + hostBytes.length);
      await writer.write(req);

      const reply = await reader.read();
      if (!reply.value || reply.value[1] !== 0x00) {
        throw new Error(`SOCKS5 reply ${reply.value ? reply.value[1] : "?"}`);
      }
      return rebuildStream(sock, reader, null);
    }

    // HTTP proxy
    const req = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\nUser-Agent: Mozilla/5.0\r\nProxy-Connection: keep-alive\r\n\r\n`;
    await writer.write(new TextEncoder().encode(req));

    // baca header sampai \r\n\r\n
    let buf = new Uint8Array(0);
    let leftover = null;
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done || !chunk.value) throw new Error("Proxy menutup koneksi");
      const merged = new Uint8Array(buf.length + chunk.value.length);
      merged.set(buf, 0);
      merged.set(chunk.value, buf.length);
      buf = merged;

      const text = new TextDecoder().decode(buf.subarray(0, Math.min(buf.length, 8192)));
      const idx = text.indexOf("\r\n\r\n");
      if (idx !== -1) {
        const statusLine = text.slice(0, text.indexOf("\r\n"));
        const m = statusLine.match(/^HTTP\/1\.[01]\s+(\d{3})/);
        const code = m ? Number(m[1]) : 0;
        if (code !== 200) throw new Error(`Proxy CONNECT kode ${code}`);
        // byte setelah header (bila ada) = data tunnel awal
        const headerEnd = idx + 4;
        leftover = buf.length > headerEnd ? buf.slice(headerEnd) : null;
        break;
      }
      if (buf.length > 8192) throw new Error("Header proxy terlalu besar");
    }

    return rebuildStream(sock, reader, leftover);
  } catch (err) {
    try { reader.cancel(); } catch {}
    try { sock.close(); } catch {}
    throw err;
  }
}

/**
 * Stream yang sudah dipakai reader.read() tidak bisa dilepas lock-nya.
 * Solusi: buat ReadableStream baru yang menyambung reader yang sudah ada,
 * jadi byte lanjutan (leftover) tetap diteruskan.
 */
function rebuildStream(sock, reader, leftover) {
  const writable = new WritableStream({
    async write(chunk) {
      const w = sock.writable.getWriter();
      try {
        await w.write(chunk);
      } finally {
        w.releaseLock();
      }
    },
    close() {
      try { sock.close(); } catch {}
    },
    abort() {
      try { sock.close(); } catch {}
    },
  });

  const readable = new ReadableStream({
    async start(controller) {
      if (leftover && leftover.length) {
        try { controller.enqueue(leftover); } catch {}
      }
      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          if (value) controller.enqueue(value);
        }
        controller.close();
      } catch (err) {
        try { controller.error(err); } catch {}
      }
    },
    cancel() {
      try { reader.cancel(); } catch {}
      try { sock.close(); } catch {}
    },
  });

  return { readable, writable, closed: sock.closed, close: () => sock.close() };
}

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, responseHeader, prxIP) {
  async function connectAndWrite(address, port) {
    const isTLS = port === 443 || port === 8443;
    const tcpSocket = connect({ hostname: address, port: port, secureTransport: isTLS ? "on" : "off" });
    const writer = tcpSocket.writable.getWriter();
    await writer.write(new Uint8Array(rawClientData));
    writer.releaseLock();
    return tcpSocket;
  }

  // Fallback lewat proxy. Proxy harus HTTP/SOCKS5 yang bisa forward, jadi
  // pakai handshake proxy dulu (bukan tulis mentah).
  async function retry() {
    const parts = prxIP.split(":");
    const fallbackIP = parts[0] || addressRemote;
    const fallbackPort = Number(parts[1] || portRemote);

    // 1) Coba lewat proxy (HTTP CONNECT / SOCKS5)
    try {
      const proxied = await connectViaProxy(fallbackIP, fallbackPort, addressRemote, portRemote);
      const w = proxied.writable.getWriter();
      await w.write(new Uint8Array(rawClientData));
      w.releaseLock();
      proxied.closed?.catch(() => {});
      remoteSocketToWS(proxied, webSocket, responseHeader, null);
      return;
    } catch (err) {
      console.log(`proxy handshake gagal (${fallbackIP}:${fallbackPort}): ${err.message}`);
    }

    // 2) Proxy tanpa handshake = raw TCP forwarder: tulis mentah, tanpa CONNECT
    try {
      const raw = connect({
        hostname: fallbackIP,
        port: fallbackPort,
        secureTransport: "off",
      });
      const w = raw.writable.getWriter();
      await w.write(new Uint8Array(rawClientData));
      w.releaseLock();
      raw.closed?.catch(() => {});
      remoteSocketToWS(raw, webSocket, responseHeader, null);
      return;
    } catch (err) {
      console.log(`proxy raw gagal: ${err.message}`);
    }

    // 2) Proxy tidak bisa -> langsung ke tujuan
    try {
      const tcpSocket = await connectAndWrite(addressRemote, portRemote);
      tcpSocket.closed.catch(() => {});
      remoteSocketToWS(tcpSocket, webSocket, responseHeader, null);
    } catch (e2) {
      console.log(`fallback langsung gagal: ${e2.message}`);
      safeCloseWebSocket(webSocket);
    }
  }

  try {
    const tcpSocket = await connectAndWrite(addressRemote, portRemote);
    remoteSocketToWS(tcpSocket, webSocket, responseHeader, retry);
  } catch (err) {
    retry();
  }
}

async function handleUDPOutbound(targetAddress, targetPort, dataChunk, webSocket, responseHeader, relay) {
  try {
    const isTLS = relay.port === 443;
    const tcpSocket = connect({ hostname: relay.host, port: relay.port, secureTransport: isTLS ? "on" : "off" });
    const headerBuffer = new TextEncoder().encode(`udp:${targetAddress}:${targetPort}`);
    const separator = new Uint8Array([0x7c]);
    const relayMessage = new Uint8Array(headerBuffer.byteLength + separator.byteLength + dataChunk.byteLength);

    relayMessage.set(headerBuffer, 0);
    relayMessage.set(separator, headerBuffer.byteLength);
    relayMessage.set(new Uint8Array(dataChunk), headerBuffer.byteLength + separator.byteLength);

    const writer = tcpSocket.writable.getWriter();
    await writer.write(relayMessage);
    writer.releaseLock();

    remoteSocketToWS(tcpSocket, webSocket, responseHeader, null);
  } catch (error) {}
}

async function remoteSocketToWS(
  remoteSocket,
  webSocket,
  responseHeader,
  retry
) {
  let header = responseHeader;
  let hasIncomingData = false;

  try {
    await remoteSocket.readable.pipeTo(
      new WritableStream({
        start() {},
        async write(chunk, controller) {
          hasIncomingData = true;
          if (webSocket.readyState !== WS_READY_STATE_OPEN) {
            controller.error("webSocket not open");
            return;
          }
          if (header) {
            webSocket.send(await new Blob([header, chunk]).arrayBuffer());
            header = null;
          } else {
            webSocket.send(chunk);
          }
        },
        close() {},
        abort(reason) {
          console.error("remoteSocketToWS abort:", reason);
        },
      })
    );
  } catch (error) {
    console.error("remoteSocketToWS exception:", error?.message || error);
    safeCloseWebSocket(webSocket);
    return;
  }

  // Tidak ada data sama sekali -> tunnel mungkin salah target, coba proxy
  if (!hasIncomingData && retry) {
    retry();
  }
}

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (error) {}
}