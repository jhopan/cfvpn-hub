// Adaptor soket Node untuk checkProxy (cron-worker/src/proxy-check.mjs): memberi bentuk
// {readable, writable, close} seperti `connect` dari cloudflare:sockets.
//
// Tidak memakai Readable.toWeb/Writable.toWeb karena wrapper itu membuat promise internal
// yang tidak tertangkap saat soket di-RST → proses mati dengan uncaughtException saat
// memverifikasi puluhan ribu kandidat. Implementasi langsung di bawah ini mengalirkan
// error ke reader.read() sehingga bisa ditangani checkProxy.
import net from "node:net";
import { once } from "node:events";

export async function nodeConnect({ hostname, port }) {
  const sock = net.connect({ host: hostname, port: Number(port) });
  sock.on("error", () => {}); // RST dari proxy mati tidak boleh mematikan proses
  await once(sock, "connect");
  sock.setNoDelay(true);

  const queue = [];
  let pending = null;
  let ended = false;
  let failed = null;

  const settle = (fn) => {
    if (!pending) return;
    const current = pending;
    pending = null;
    fn(current);
  };

  sock.on("data", (chunk) => {
    if (pending) {
      const current = pending;
      pending = null;
      current.resolve({ value: new Uint8Array(chunk), done: false });
    } else {
      queue.push(new Uint8Array(chunk));
    }
  });
  sock.on("end", () => {
    ended = true;
    settle((p) => p.resolve({ value: undefined, done: true }));
  });
  sock.on("close", () => {
    ended = true;
    settle((p) => p.resolve({ value: undefined, done: true }));
  });
  sock.on("error", (err) => {
    failed = err;
    settle((p) => p.reject(err));
  });

  const readable = {
    getReader() {
      return {
        read() {
          if (queue.length) return Promise.resolve({ value: queue.shift(), done: false });
          if (failed) return Promise.reject(failed);
          if (ended) return Promise.resolve({ value: undefined, done: true });
          return new Promise((resolve, reject) => {
            pending = { resolve: resolve, reject: reject };
          });
        },
        cancel() {
          sock.destroy();
          return Promise.resolve();
        },
        releaseLock() {},
      };
    },
  };

  const writable = {
    getWriter() {
      return {
        write(chunk) {
          return new Promise((resolve, reject) => {
            sock.write(Buffer.from(chunk), (err) => (err ? reject(err) : resolve()));
          });
        },
        close() {
          return new Promise((resolve) => sock.end(() => resolve()));
        },
        releaseLock() {},
      };
    },
  };

  return {
    readable: readable,
    writable: writable,
    // resetAndDestroy mengirim RST supaya soket tidak menyangkut di TIME_WAIT: penting saat
    // memverifikasi puluhan ribu kandidat dari satu mesin (port efemeral Windows terbatas).
    close: () => (sock.resetAndDestroy ? sock.resetAndDestroy() : sock.destroy()),
  };
}

// Filter murah: hanya cek port terbuka (opsional; di sebagian jaringan semua SYN diterima
// sehingga filter ini tidak menyaring apa pun).
export function tcpOpen(host, port, timeoutMs = 3000) {
  return new Promise((resolve) => {
    const sock = net.connect({ host: host, port: Number(port) });
    sock.on("error", () => {});
    const done = (ok) => {
      sock.removeAllListeners();
      if (sock.resetAndDestroy) sock.resetAndDestroy();
      else sock.destroy();
      resolve(ok);
    };
    sock.setTimeout(timeoutMs, () => done(false));
    sock.once("connect", () => done(true));
    sock.once("error", () => done(false));
  });
}
