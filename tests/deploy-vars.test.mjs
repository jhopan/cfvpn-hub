// Uji validasi env pada jalur deploy (/api/cf) — satu-satunya logika baru di functions/api/cf.js.
// Jalankan: nrun node --test tests/deploy-vars.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import { normalizeVars } from "../functions/api/cf.js";

test("env kosong / tidak dikirim berarti tanpa binding", () => {
  assert.deepEqual(normalizeVars(undefined), { bindings: [] });
  assert.deepEqual(normalizeVars(null), { bindings: [] });
  assert.deepEqual(normalizeVars({}), { bindings: [] });
});

test("nilai kosong dilewati supaya tidak memasang variabel kosong", () => {
  const result = normalizeVars({ RELAY_SERVER_UDP: "  ", RELAY_SERVER_PORT: "7300" });
  assert.deepEqual(result, { bindings: [{ type: "plain_text", name: "RELAY_SERVER_PORT", text: "7300" }] });
});

test("relay UDP lengkap diterjemahkan menjadi binding plain_text", () => {
  const result = normalizeVars({
    RELAY_SERVER_UDP: "relay.domainku.com",
    RELAY_SERVER_PORT: "7300",
    RELAY_SERVER_TLS: "1",
    RELAY_SECRET: "rahasia-panjang",
  });
  assert.equal(result.error, undefined);
  assert.equal(result.bindings.length, 4);
  assert.deepEqual(
    result.bindings.map((binding) => binding.name),
    ["RELAY_SERVER_UDP", "RELAY_SERVER_PORT", "RELAY_SERVER_TLS", "RELAY_SECRET"]
  );
  assert.equal(result.bindings[0].text, "relay.domainku.com");
  assert.equal(result.bindings.every((binding) => binding.type === "plain_text"), true);
});

test("nama env tidak valid ditolak (bukan sekadar dibuang)", () => {
  assert.match(normalizeVars({ "RELAY-X": "1" }).error, /Nama env tidak valid/);
  assert.match(normalizeVars({ "1RELAY": "1" }).error, /Nama env tidak valid/);
  assert.match(normalizeVars({ "": "1" }).error, /Format env|Nama env/);
});

test("nilai terlalu panjang dan jumlah berlebih ditolak", () => {
  assert.match(normalizeVars({ RELAY_SECRET: "x".repeat(1025) }).error, /terlalu panjang/);
  const many = {};
  for (let i = 0; i < 13; i++) many["VAR_" + i] = "1";
  assert.match(normalizeVars(many).error, /Terlalu banyak env/);
});

test("format env bukan objek ditolak", () => {
  assert.match(normalizeVars(["RELAY_SECRET=1"]).error, /Format env tidak valid/);
  assert.match(normalizeVars("RELAY_SECRET=1").error, /Format env tidak valid/);
});
