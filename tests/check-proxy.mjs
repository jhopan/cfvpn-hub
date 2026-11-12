// Uji logika checker cron-worker (cron-worker/src/proxy-check.mjs) dari Node, dengan
// soket Node sebagai pengganti `connect` dari cloudflare:sockets.
//
//   nrun node tests/check-proxy.mjs 8.219.122.8:9999 1.2.3.4:9999
//
// Tanpa argumen: memakai 3 proxy yang sudah terbukti hidup + 2 yang pasti mati.
import { checkProxy } from "../cron-worker/src/proxy-check.mjs";
import { nodeConnect } from "../proxy-scraper/node-socket.mjs";

const DEFAULT_TARGETS = [
  "8.219.122.8:9999",
  "45.194.33.12:30001",
  "67.201.58.190:4145",
  "127.0.0.1:9",
  "192.0.2.1:4145",
];
const KNOWN_DEAD = DEFAULT_TARGETS.slice(3);

const targets = process.argv.slice(2).length ? process.argv.slice(2) : DEFAULT_TARGETS;
let bad = 0;

for (const target of targets) {
  const [host, port] = target.split(":");
  const started = Date.now();
  try {
    const res = await checkProxy(host, Number(port), nodeConnect, { timeoutMs: 6000 });
    const ok = res.alive;
    if (!ok && !KNOWN_DEAD.includes(target)) bad++;
    console.log(`[${ok ? "PASS" : "FAIL"}] ${target.padEnd(24)} ${res.alive ? "HIDUP " + res.protocol + " " + (Date.now() - started) + "ms " + res.detail : "MATI " + res.detail}`);
  } catch (err) {
    bad++;
    console.log(`[FAIL] ${target.padEnd(24)} exception: ${err.message}`);
  }
}

console.log(bad === 0 ? "\nLOGIKA CHECKER OK" : `\n${bad} target di luar dugaan`);
process.exit(bad === 0 ? 0 : 1);
