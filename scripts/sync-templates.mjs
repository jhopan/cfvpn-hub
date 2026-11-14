// Turunkan frontend/source/vpn-worker-free.js dari vpn-worker-prem.js.
//
// Beda tier yang nyata cuma satu konstanta: `TIER_FREE`. Di prem `false`, di free `true`, dan
// kode memakainya untuk mematikan fitur premium yang butuh binding tambahan (relay UDP).
// Sisanya identik supaya perbaikan bug tidak tertinggal di satu tier.
//
// Pakai:
//   node scripts/sync-templates.mjs           # tulis ulang free dari prem
//   node scripts/sync-templates.mjs --check   # keluar 1 kalau free tidak sesuai turunan prem
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PREM_MARKER = "const TIER_FREE = false;";
const FREE_MARKER = "const TIER_FREE = true;";

// deriveFree mengubah prem menjadi free: hanya konstanta TIER_FREE yang berbeda.
export function deriveFree(prem) {
  const parts = prem.split(PREM_MARKER);
  if (parts.length !== 2) {
    throw new Error("vpn-worker-prem.js harus memuat tepat satu `" + PREM_MARKER + "`");
  }
  return parts[0] + FREE_MARKER + parts[1];
}

const here = path.dirname(fileURLToPath(import.meta.url));
const source = path.join(here, "..", "frontend", "source", "vpn-worker-prem.js");
const target = path.join(here, "..", "frontend", "source", "vpn-worker-free.js");

function main() {
  const prem = fs.readFileSync(source, "utf8");
  if (!prem.trim()) {
    console.error("Sumber kosong: " + source);
    return 1;
  }
  if (prem.includes(FREE_MARKER)) {
    console.error("vpn-worker-prem.js tidak boleh memuat TIER_FREE = true; itu berkas free.");
    return 1;
  }

  let expected;
  try {
    expected = deriveFree(prem);
  } catch (error) {
    console.error(String(error && error.message ? error.message : error));
    return 1;
  }

  const actual = fs.readFileSync(target, "utf8");
  const check = process.argv.includes("--check");

  if (actual === expected) {
    console.log("Template sinkron: free = turunan prem (beda 1 baris: TIER_FREE).");
    return 0;
  }

  if (check) {
    console.error("Template TIDAK sinkron: jalankan `npm run sync-templates`.");
    return 1;
  }

  fs.writeFileSync(target, expected);
  console.log("vpn-worker-free.js diturunkan dari prem (" + expected.length + " byte, " + expected.split("\n").length + " baris).");
  return 0;
}

// Hanya jalankan CLI kalau berkas ini dieksekusi langsung (diimpor oleh tes tanpa efek samping).
const invokedDirectly = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  process.exit(main());
}