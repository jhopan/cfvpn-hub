#!/usr/bin/env node
// Uji semua sumber di sources.mjs: status HTTP, ukuran, jumlah proxy yang terbaca, waktu.
//
//   nrun node proxy-scraper/sources-check.mjs [--out file.txt] [--timeout 30000]
//
// Klasifikasi hasil:
//   OK      -> HTTP 200 dan ada proxy terbaca
//   KOSONG  -> HTTP 200 tapi 0 proxy (format berubah / butuh JS / halaman error)
//   GAGAL   -> HTTP bukan 200 atau koneksi gagal
// Keluar dengan kode 1 kalau ada sumber KOSONG/GAGAL.
import { SOURCES, extractProxies } from "./sources.mjs";
import { writeFileSync } from "node:fs";

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  if (i === -1) return fallback;
  const v = process.argv[i + 1];
  return v === undefined ? true : Number.isNaN(Number(v)) ? v : Number(v);
}

const TIMEOUT = arg("timeout", 30000);
const OUT = arg("out", null);
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36";

const union = new Set();
const results = await Promise.all(SOURCES.map(async (src) => {
  const started = Date.now();
  try {
    const res = await fetch(src.url, { signal: AbortSignal.timeout(TIMEOUT), headers: { "User-Agent": UA, Accept: "*/*" } });
    const text = res.ok ? await res.text() : "";
    const found = res.ok ? extractProxies(text) : new Set();
    for (const p of found) union.add(p);
    return {
      name: src.name,
      kind: src.kind,
      status: res.status,
      bytes: text.length,
      count: found.size,
      ms: Date.now() - started,
      verdict: res.ok ? (found.size ? "OK" : "KOSONG") : "GAGAL",
      note: res.ok ? "" : "HTTP " + res.status,
    };
  } catch (err) {
    return { name: src.name, kind: src.kind, status: 0, bytes: 0, count: 0, ms: Date.now() - started, verdict: "GAGAL", note: err.message };
  }
}));

results.sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));

console.log(`sumber: ${results.length}\n`);
console.log(`${"nama".padEnd(26)}${"jenis".padEnd(7)}${"status".padEnd(8)}${"proxy".padEnd(8)}${"ukuran".padEnd(10)}${"ms".padEnd(7)}catatan`);
for (const r of results) {
  console.log(
    r.name.padEnd(26) + String(r.kind).padEnd(7) + String(r.status).padEnd(8) + String(r.count).padEnd(8) +
    (r.bytes ? (r.bytes / 1024).toFixed(1) + " KB" : "-").padEnd(10) + String(r.ms).padEnd(7) +
    (r.verdict === "OK" ? "" : r.verdict + (r.note ? " (" + r.note + ")" : "")),
  );
}

const ok = results.filter((r) => r.verdict === "OK");
const kosong = results.filter((r) => r.verdict === "KOSONG");
const gagal = results.filter((r) => r.verdict === "GAGAL");
const optionalNames = new Set(SOURCES.filter((s) => s.optional).map((s) => s.name));
const kosongWajib = kosong.filter((r) => !optionalNames.has(r.name));
const gagalWajib = gagal.filter((r) => !optionalNames.has(r.name));
console.log(`\nOK: ${ok.length} | KOSONG: ${kosong.length} | GAGAL: ${gagal.length}`);
console.log(`total proxy mentah (setelah buang duplikat antar sumber): ${union.size}`);
if (kosong.length) console.log("KOSONG: " + kosong.map((r) => r.name + (optionalNames.has(r.name) ? " (opsional)" : "")).join(", "));
if (gagal.length) console.log("GAGAL: " + gagal.map((r) => r.name + " [" + (r.status || r.note) + "]" + (optionalNames.has(r.name) ? " (opsional)" : "")).join(", "));

if (OUT) {
  writeFileSync(OUT, [...union].join("\n") + "\n");
  console.log(`daftar kandidat ditulis ke ${OUT}`);
}

process.exit(kosongWajib.length || gagalWajib.length ? 1 : 0);
