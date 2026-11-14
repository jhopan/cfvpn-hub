#!/usr/bin/env node
// Scraper + verifikator proxy.
//
//   node proxy-scraper/index.mjs [opsi]
//
// Alur: ambil semua sumber mentah (paralel) -> dedupe -> (opsional) filter port terbuka ->
// handshake SOCKS5/HTTP CONNECT + GET cp.cloudflare.com/generate_204 (checker yang sama
// dipakai cron-worker) -> simpan yang hidup ke Supabase secara bertahap.
//
// Opsi:
//   --cap N            batasi kandidat unik (default 20000)
//   --tcp-jobs N       konkurensi filter TCP; 0 = lewati filter (default 150)
//   --check-jobs N     konkurensi verifikasi penuh (default 60)
//   --check-limit N    batasi jumlah kandidat yang diverifikasi (default 20000)
//   --socks-timeout N  ms per tahap SOCKS5 (default 4000)
//   --http-timeout N   ms per tahap HTTP CONNECT (default 4000)
//   --probe-timeout N  ms untuk request HTTP lewat tunnel (default 6000)
//   --flush N          tulis ke Supabase setiap N proxy hidup (default 100)
//   --only-file FILE   pakai daftar ip:port dari file, jangan ambil sumber
//   --dump FILE        tulis daftar kandidat tahap verifikasi
//   --no-trace         lewati verifikasi TLS/jejak negara (bawaan: dijalankan)
//   --dry-run          jangan tulis ke Supabase
//   --verbose          cetak hasil tiap kandidat
import { SOURCES, extractProxies } from "./sources.mjs";
import { nodeConnect, tcpOpen } from "./node-socket.mjs";
import { checkProxy } from "../cron-worker/src/proxy-check.mjs";
import { tlsTrace } from "./tls-trace.mjs";
import { readFileSync, writeFileSync } from "node:fs";

const SUPABASE_URL = "https://lumbbmhhmkcnxunuryjr.supabase.co";
const SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imx1bWJibWhobWtjbnh1bnVyeWpyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTQ0NzI1MjEsImV4cCI6MjExMDA0ODUyMX0.ylMqMgv2H4vWax-whnXSRHBlD7DZs9DXVRUD9fAO6mc";

// Port yang paling sering dipakai proxy publik -> didahulukan saat memotong kandidat.
const PREFERRED_PORTS = new Set([1080, 1081, 3128, 4145, 4146, 8080, 8081, 8000, 8888, 9090, 9999, 443, 80, 10808]);

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  if (i === -1) return fallback;
  const v = process.argv[i + 1];
  if (v === undefined) return true;
  return Number.isNaN(Number(v)) ? v : Number(v);
}

const OPT = {
  cap: arg("cap", 20000),
  offset: arg("offset", 0),
  tcpJobs: arg("tcp-jobs", 150),
  checkJobs: arg("check-jobs", 60),
  checkLimit: arg("check-limit", 20000),
  sockTimeout: arg("socks-timeout", 4000),
  httpTimeout: arg("http-timeout", 4000),
  probeTimeout: arg("probe-timeout", 6000),
  flush: arg("flush", 100),
  verbose: process.argv.includes("--verbose"),
  dump: arg("dump", null),
  onlyFile: arg("only-file", null),
  noTrace: process.argv.includes("--no-trace"),
  dryRun: process.argv.includes("--dry-run"),
};

const HEADERS = { apikey: SUPABASE_KEY, Authorization: `Bearer ${SUPABASE_KEY}`, "Content-Type": "application/json" };

async function pool(items, limit, fn) {
  const results = [];
  let index = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    for (;;) {
      const i = index++;
      if (i >= items.length) return;
      results[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return results;
}

async function fetchSources() {
  const stats = [];
  const unique = new Set();
  const counts = new Map();
  await Promise.all(SOURCES.map(async (src) => {
    try {
      const res = await fetch(src.url, { signal: AbortSignal.timeout(30000), headers: { "User-Agent": "cfvpn-hub-scraper/1.0" } });
      if (!res.ok) {
        stats.push({ name: src.name, count: 0, error: "HTTP " + res.status });
        return;
      }
      const found = extractProxies(await res.text());
      for (const p of found) {
        unique.add(p);
        counts.set(p, (counts.get(p) || 0) + 1);
      }
      stats.push({ name: src.name, count: found.size });
    } catch (err) {
      stats.push({ name: src.name, count: 0, error: err.message });
    }
  }));
  return { stats, unique, counts };
}

// Urutan prioritas: proxy yang tercantum di banyak sumber independen jauh lebih besar
// peluang hidupnya, lalu port yang umum dipakai proxy. Tanpa ini, slice awal didominasi
// daftar mass-scan (ratusan ribu entri, hampir semuanya mati).
function rank(list, counts) {
  return list.slice().sort((a, b) => {
    const ca = counts ? (counts.get(a) || 0) : 0;
    const cb = counts ? (counts.get(b) || 0) : 0;
    if (ca !== cb) return cb - ca;
    const pa = PREFERRED_PORTS.has(Number(a.split(":")[1])) ? 0 : 1;
    const pb = PREFERRED_PORTS.has(Number(b.split(":")[1])) ? 0 : 1;
    return pa - pb;
  });
}

async function existingRows() {
  const rows = await fetch(`${SUPABASE_URL}/rest/v1/proxy_pool?select=id,ip,port`, { headers: HEADERS }).then((r) => r.json());
  return new Map(rows.map((r) => [`${r.ip}:${r.port}`, r.id]));
}

// Tulis hasil secara bertahap: proses panjang (ribuan kandidat) rawan putus di tengah,
// dan tanpa flush bertahap semua hasil yang sudah didapat akan hilang.
async function request(url, init, label) {
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      return await fetch(url, { ...init, signal: AbortSignal.timeout(30000) });
    } catch (err) {
      if (attempt === 2) throw new Error(label + ": " + err.message);
      await new Promise((r) => setTimeout(r, 500 * (attempt + 1)));
    }
  }
}

async function persist(alive, byKey) {
  const now = new Date().toISOString();
  let updated = 0;
  const fresh = [];
  for (const a of alive) {
    if (byKey.has(a.proxy)) {
      const id = byKey.get(a.proxy);
      if (id === "inserted") continue;
      const res = await request(`${SUPABASE_URL}/rest/v1/proxy_pool?id=eq.${id}`, {
        method: "PATCH",
        headers: { ...HEADERS, Prefer: "return=minimal" },
        body: JSON.stringify(Object.assign({ is_active: true, last_checked: now, ping: a.ms }, a.country ? { country: a.country } : {})),
      }, "patch " + a.proxy);
      if (res.status === 204) updated++;
    } else {
      // tandai lebih dulu supaya flush berikutnya tidak mencoba menyisipkan baris yang sama
      byKey.set(a.proxy, "inserted");
      fresh.push({ ip: a.proxy.split(":")[0], port: a.proxy.split(":")[1], is_active: true, last_checked: now, ping: a.ms, country: a.country || null });
    }
  }
  let inserted = 0;
  for (let i = 0; i < fresh.length; i += 100) {
    const chunk = fresh.slice(i, i + 100);
    const res = await request(`${SUPABASE_URL}/rest/v1/proxy_pool`, {
      method: "POST",
      headers: { ...HEADERS, Prefer: "return=minimal" },
      body: JSON.stringify(chunk),
    }, "insert");
    if (res.status === 201) {
      inserted += chunk.length;
    } else if (res.status === 409) {
      inserted += chunk.length; // sudah ada di DB (balapan antar flush) — bukan kegagalan
    } else {
      console.log("  gagal insert: HTTP " + res.status + " " + (await res.text()).slice(0, 120));
    }
  }
  return { updated, inserted };
}

async function main() {
  const started = Date.now();
  let unique;
  let counts = null;
  if (OPT.onlyFile) {
    unique = new Set(readFileSync(OPT.onlyFile, "utf8").split(/\s+/).filter((l) => /^\d+\.\d+\.\d+\.\d+:\d+$/.test(l)));
    console.log(`--only-file: ${unique.size} kandidat dari ${OPT.onlyFile}`);
  } else {
    console.log(`mengambil ${SOURCES.length} sumber...`);
    const fetched = await fetchSources();
    for (const s of fetched.stats) console.log(`  ${s.name.padEnd(22)} ${s.error ? "GAGAL: " + s.error : s.count + " proxy"}`);
    unique = fetched.unique;
    counts = fetched.counts;
    const multi = [...counts.values()].filter((n) => n > 1).length;
    const many = [...counts.values()].filter((n) => n >= 3).length;
    console.log(`  (${multi} proxy muncul di >1 sumber, ${many} di >=3 sumber)`);
  }

  let candidates = rank([...unique], counts);
  console.log(`\nunik: ${candidates.length}${OPT.offset ? ` (mulai dari ${OPT.offset})` : ""}` + (candidates.length - OPT.offset > OPT.cap ? ` (dibatasi ${OPT.cap})` : ""));
  candidates = candidates.slice(OPT.offset, OPT.offset + OPT.cap);

  let open;
  if (OPT.tcpJobs > 0) {
    console.log(`\nfilter port terbuka (${OPT.tcpJobs} paralel, timeout 3s)...`);
    const flags = await pool(candidates, OPT.tcpJobs, async (p) => {
      const [host, port] = p.split(":");
      return (await tcpOpen(host, port, 3000)) ? p : null;
    });
    open = flags.filter(Boolean);
    console.log(`  port terbuka: ${open.length} (${((Date.now() - started) / 1000).toFixed(0)}s)`);
  } else {
    console.log("\nfilters TCP dilewati (--tcp-jobs 0): semua kandidat diverifikasi langsung");
    open = candidates;
  }

  const toCheck = rank(open).slice(0, OPT.checkLimit);
  if (OPT.dump) {
    writeFileSync(OPT.dump, toCheck.join("\n") + "\n");
    console.log(`  kandidat verifikasi ditulis ke ${OPT.dump} (${toCheck.length})`);
  }

  const byKey = OPT.dryRun ? new Map() : await existingRows();
  console.log(`\nverifikasi ${toCheck.length} kandidat (${OPT.checkJobs} paralel)...`);
  const alive = [];
  let done = 0;
  let updated = 0;
  let inserted = 0;
  let traceOk = 0;
  let traceFail = 0;
  let negaraDiperbarui = 0;
  let pendingFlush = [];
  let chain = Promise.resolve();

  const flush = () => {
    // Antrikan flush: beberapa worker bisa memicunya bersamaan, dan dua insert paralel
    // untuk baris yang sama berakhir 409 duplicate key.
    chain = chain.then(async () => {
      if (!pendingFlush.length || OPT.dryRun) {
        pendingFlush = [];
        return;
      }
      const batch = pendingFlush;
      pendingFlush = [];
      const res = await persist(batch, byKey).catch((err) => {
        console.log("  flush gagal (" + err.message + "), data batch ini dilewati");
        return { updated: 0, inserted: 0 };
      });
      updated += res.updated;
      inserted += res.inserted;
      console.log(`  flush: +${res.updated} diperbarui, +${res.inserted} ditambah (total hidup ${alive.length}, ${((Date.now() - started) / 1000).toFixed(0)}s)`);
    });
    return chain;
  };

  await pool(toCheck, OPT.checkJobs, async (p) => {
    const [host, port] = p.split(":");
    const res = await checkProxy(host, Number(port), nodeConnect, {
      socksTimeoutMs: OPT.sockTimeout,
      httpTimeoutMs: OPT.httpTimeout,
      probeTimeoutMs: OPT.probeTimeout,
    });
    done++;
    // Tingkat-2: cek ringan hanya membuktikan port 80. Proxy yang memblokir/mengacak TLS 443
    // tetap lolos di sana padahal worker memakainya untuk TLS. Sekaligus ambil negara keluar
    // yang sebenarnya (loc= dari cdn-cgi/trace), bukan tebakan tabel IP.
    let trace = null;
    if (res.alive && !OPT.noTrace) {
      trace = await tlsTrace(host, Number(port), { timeoutMs: OPT.sockTimeout });
      if (trace.ok) {
        traceOk++;
        if (trace.country) negaraDiperbarui++;
      } else {
        traceFail++;
      }
    }
    const item = { proxy: p, ...res, tlsMs: trace && trace.tlsMs, country: trace && trace.country, exitIp: trace && trace.exitIp };
    const lulus = res.alive && (OPT.noTrace || (trace && trace.ok));
    if (lulus) {
      alive.push(item);
      pendingFlush.push(item);
      if (pendingFlush.length >= OPT.flush) await flush();
    }
    if (OPT.verbose) console.log(`  [${lulus ? "PAKAI" : "buang"}] ${p.padEnd(24)} ${res.alive ? res.protocol + " " + res.ms + "ms" : res.detail}${trace ? " tls=" + (trace.ok ? trace.country + " " + trace.tlsMs + "ms" : "GAGAL " + trace.detail) : ""}`);
    else if (done % 500 === 0) console.log(`  ${done}/${toCheck.length} selesai, hidup: ${alive.length} (${((Date.now() - started) / 1000).toFixed(0)}s)`);
    return item;
  });
  await flush();

  alive.sort((a, b) => a.ms - b.ms);
  const byProtocol = alive.reduce((acc, a) => ((acc[a.protocol] = (acc[a.protocol] || 0) + 1), acc), {});
  if (!OPT.noTrace) console.log(`TLS lewat tunnel: ${traceOk} lolos, ${traceFail} gagal (negara terisi: ${negaraDiperbarui})`);
  console.log(`\nHIDUP: ${alive.length} dari ${toCheck.length} (${JSON.stringify(byProtocol)})`);
  for (const a of alive.slice(0, 20)) console.log(`  ${a.proxy.padEnd(24)} ${String(a.protocol).padEnd(7)} ${a.ms}ms`);
  if (OPT.dryRun) console.log("\n--dry-run: tidak menulis ke Supabase");
  else console.log(`\nDB: ${updated} diperbarui, ${inserted} ditambah`);
  console.log(`selesai dalam ${((Date.now() - started) / 1000).toFixed(0)}s`);
}

await main();
