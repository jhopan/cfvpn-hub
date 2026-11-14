// Invarian artefak: berkas Worker yang di-upload halaman Deploy harus identik antar tier.
// Perbedaan Free vs Premium datang dari env saat deploy (RELAY_SERVER_UDP dkk), bukan dari
// kode. Kalau kedua berkas berbeda, tier free menjalankan kode yang tidak pernah diuji.
// Jalankan: node --test "tests/*.test.mjs"
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "frontend", "source");
const read = (name) => fs.readFileSync(path.join(dir, name), "utf8");

test("vpn-worker-free.js identik dengan vpn-worker-prem.js", () => {
  const prem = read("vpn-worker-prem.js");
  const free = read("vpn-worker-free.js");
  assert.ok(prem.length > 10000, "berkas sumber mencurigakan kecil");
  assert.equal(
    free,
    prem,
    "jalankan `npm run sync-templates` supaya tier free tidak menjalankan kode basi",
  );
});
