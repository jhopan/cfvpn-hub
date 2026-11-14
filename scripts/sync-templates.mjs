// Sinkronkan frontend/source/vpn-worker-free.js dari vpn-worker-prem.js.
//
// Kenapa ada dua berkas padahal isinya sama: halaman Deploy memilih berkas berdasarkan tier
// (`/source/vpn-worker-<tier>.js`), dan perbedaan tier yang sebenarnya datang dari env yang
// dipasang saat deploy (RELAY_SERVER_UDP dkk hanya untuk premium), bukan dari kode worker.
// Jadi kedua berkas WAJIB identik — kalau tidak, pengguna free bisa menjalankan kode lama.
//
// Pakai:
//   node scripts/sync-templates.mjs           # tulis ulang free = prem
//   node scripts/sync-templates.mjs --check   # keluar 1 kalau sudah beda (dipakai tes)
import fs from "node:fs";
import path from "node:path";

const root = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"));
const source = path.join(root, "..", "frontend", "source", "vpn-worker-prem.js");
const target = path.join(root, "..", "frontend", "source", "vpn-worker-free.js");

const prem = fs.readFileSync(source, "utf8");
if (!prem.trim()) {
  console.error(`Sumber kosong: ${source}`);
  process.exit(1);
}

const free = fs.readFileSync(target, "utf8");
const check = process.argv.includes("--check");

if (prem === free) {
  console.log(`Template sudah sinkron (${prem.length} byte, ${prem.split("\n").length} baris).`);
  process.exit(0);
}

if (check) {
  console.error("Template TIDAK sinkron: vpn-worker-free.js berbeda dari vpn-worker-prem.js.");
  console.error("Jalankan: node scripts/sync-templates.mjs");
  process.exit(1);
}

fs.writeFileSync(target, prem);
console.log(`vpn-worker-free.js disalin dari prem (${prem.length} byte, ${prem.split("\n").length} baris).`);
