import { connect } from "cloudflare:sockets";

let prxIP = "";
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
          prxIP = prxMatch[1].replace("-", ":");
          return await websocketHandler(request);
        }
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

async function websocketHandler(request) {
  const [client, webSocket] = Object.values(new WebSocketPair());
  webSocket.accept();

  let remoteSocketWrapper = { value: null };
  let isDNS = false;

  let readableStreamCancel = false;
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
  const readableWebSocketStream = new ReadableStream({
    start(controller) {
      if (earlyDataHeader) {
        try {
          const earlyData = Uint8Array.from(atob(earlyDataHeader.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0)).buffer;
          controller.enqueue(earlyData);
        } catch(e) {}
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
    cancel() { readableStreamCancel = true; }
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
        const tcpSocket = connect({ hostname: prxIP.split(":")[0], port: prxIP.split(":")[1] || 443, secureTransport: "on" });
        remoteSocketWrapper.value = tcpSocket;
        const writer = tcpSocket.writable.getWriter();
        writer.write(chunk);
        writer.releaseLock();
        remoteSocketToWS(tcpSocket, webSocket, null, null);
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
        vlessHeader.version
      );
    }
  })).catch(() => {
    safeCloseWebSocket(webSocket);
  });

  return new Response(null, { status: 101, webSocket: client });
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

  return {
    hasError: false,
    addressRemote: addressValue,
    portRemote,
    rawClientData: buffer.slice(addressIndex + addressLength),
    version: new Uint8Array([version[0], 0]),
    isUDP,
  };
}

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, responseHeader) {
  async function connectAndWrite(address, port) {
    const isTLS = port === 443 || port === 8443;
    const tcpSocket = connect({ hostname: address, port: port, secureTransport: isTLS ? "on" : "off" });

    remoteSocket.value = tcpSocket;
    const writer = tcpSocket.writable.getWriter();
    await writer.write(new Uint8Array(rawClientData));
    writer.releaseLock();
    return tcpSocket;
  }

  async function retry() {
    const fallbackIP = prxIP.split(":")[0] || addressRemote;
    const fallbackPort = prxIP.split(":")[1] || portRemote;
    const tcpSocket = await connectAndWrite(fallbackIP, fallbackPort);
    tcpSocket.closed.catch(() => {});
    remoteSocketToWS(tcpSocket, webSocket, responseHeader, null);
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
  retry,
  log
) {
  let header = responseHeader;
  let hasIncomingData = false;
  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        start() {},
        async write(chunk, controller) {
          hasIncomingData = true;
          if (webSocket.readyState !== WS_READY_STATE_OPEN) {
            controller.error("webSocket.readyState is not open, maybe close");
          }
          if (header) {
            webSocket.send(await new Blob([header, chunk]).arrayBuffer());
            header = null;
          } else {
            webSocket.send(chunk);
          }
        },
        close() {
        },
        abort(reason) {
          console.error(`remoteConnection!.readable abort`, reason);
        },
      })
    )
    .catch((error) => {
      console.error(`remoteSocketToWS has exception `, error.stack || error);
      safeCloseWebSocket(webSocket);
    });
  if (hasIncomingData === false && retry) {
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