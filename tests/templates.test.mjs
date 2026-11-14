// Invarian artefak: berkas Worker yang di-upload halaman Deploy harus berupa turunan langsung
// dari sumber yang diuji. Bedanya cuma satu konstanta: TIER_FREE (prem false, free true), yang
// mematikan fitur premium berbasis binding (relay UDP). Kalau berkas free menyimpang, tier free
// menjalankan kode yang tidak pernah diuji.
// Jalankan: node --test "tests/*.test.mjs"
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { deriveFree } from "../scripts/sync-templates.mjs";

const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "frontend", "source");
const read = (name) => fs.readFileSync(path.join(dir, name), "utf8");

test("vpn-worker-free.js adalah turunan vpn-worker-prem.js (beda hanya TIER_FREE)", () => {
  const prem = read("vpn-worker-prem.js");
  const free = read("vpn-worker-free.js");
  assert.ok(prem.length > 10000, "berkas sumber mencurigakan kecil");
  assert.equal(prem.includes("const TIER_FREE = false;"), true, "prem harus memuat TIER_FREE = false");
  assert.equal(
    free,
    deriveFree(prem),
    "jalankan `npm run sync-templates` supaya tier free tidak menjalankan kode basi",
  );
  // Jumlah baris berbeda harus tepat satu (konstantanya), bukan sekadar isi yang mirip.
  const berbeda = prem.split("\n").filter((line, i) => line !== free.split("\n")[i]);
  assert.equal(berbeda.length, 1, "hanya satu baris (TIER_FREE) yang boleh berbeda: " + JSON.stringify(berbeda.slice(0, 5)));
});