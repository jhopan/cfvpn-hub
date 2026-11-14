// Uji pagar /api/cf: gerbang Origin opsional + rate limit per IP (Cache API).
// Jalankan: nrun node --test tests/cf-guard.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import {
  clientIp,
  parseOrigins,
  originAllowed,
  rateLimitKey,
  readEnvInt,
  checkRateLimit,
} from "../functions/api/cf.js";

// --- Gerbang Origin ---------------------------------------------------------

test("parseOrigins memecah daftar, huruf kecil, tanpa spasi/garis miring pinggir", () => {
  assert.deepEqual(parseOrigins("https://Panel.Contoh.com/, http://localhost:8788"), [
    "https://panel.contoh.com",
    "http://localhost:8788",
  ]);
  assert.deepEqual(parseOrigins(" *.contoh.com ,, "), ["*.contoh.com"]);
});

test("parseOrigins: env kosong / tipe lain berarti daftar kosong (gerbang mati)", () => {
  assert.deepEqual(parseOrigins(undefined), []);
  assert.deepEqual(parseOrigins(null), []);
  assert.deepEqual(parseOrigins(""), []);
  assert.deepEqual(parseOrigins("  ,  , "), []);
  assert.deepEqual(parseOrigins(123), []);
});

test("env kosong = izinkan semua Origin (perilaku lama tidak berubah)", () => {
  const patterns = parseOrigins(undefined);
  assert.equal(originAllowed("https://situs-asing.com", patterns), true);
  assert.equal(originAllowed("", patterns), true);
  assert.equal(originAllowed(undefined, patterns), true);
  assert.equal(originAllowed("https://apa-saja.com", []), true);
});

test("origin cocok persis dengan pola origin utuh", () => {
  const patterns = parseOrigins("https://panel.contoh.com,http://localhost:8788");
  assert.equal(originAllowed("https://panel.contoh.com", patterns), true);
  assert.equal(originAllowed("https://panel.contoh.com/", patterns), true);
  assert.equal(originAllowed("HTTP://LOCALHOST:8788", patterns), true);
  assert.equal(originAllowed("https://panel.contoh.com.asing.com", patterns), false);
  assert.equal(originAllowed("http://panel.contoh.com", patterns), false);
  assert.equal(originAllowed("https://sub.panel.contoh.com", patterns), false);
});

test("pola wildcard *.domain cocok untuk subdomain dan domain polos (tanpa bocor ke domain mirip)", () => {
  const patterns = parseOrigins("*.contoh.com");
  assert.equal(originAllowed("https://app.contoh.com", patterns), true);
  assert.equal(originAllowed("https://a.b.contoh.com", patterns), true);
  assert.equal(originAllowed("http://contoh.com", patterns), true);
  assert.equal(originAllowed("https://contoh.com.evil.com", patterns), false);
  assert.equal(originAllowed("https://bukan-contoh.com", patterns), false);
  assert.equal(originAllowed("https://contoh.com.asing.net", patterns), false);

  assert.equal(originAllowed("https://situs-apa-saja.com", parseOrigins("*")), true);
});

test("host polos (tanpa skema) cocok untuk host itu di skema apa pun", () => {
  const patterns = parseOrigins("localhost:8788");
  assert.equal(originAllowed("http://localhost:8788", patterns), true);
  assert.equal(originAllowed("https://localhost:8788", patterns), true);
  assert.equal(originAllowed("http://localhost:9999", patterns), false);
});

test("Origin kosong selalu izinkan (curl / deploy-bulk / server-ke-server), juga saat gerbang aktif", () => {
  const patterns = parseOrigins("https://panel.contoh.com");
  assert.equal(originAllowed("", patterns), true);
  assert.equal(originAllowed(undefined, patterns), true);
  assert.equal(originAllowed(null, patterns), true);
});

test("Origin: null (konteks opaque, mis. iframe sandbox) ditolak saat gerbang aktif", () => {
  assert.equal(originAllowed("null", parseOrigins("https://panel.contoh.com")), false);
  assert.equal(originAllowed("null", parseOrigins("*")), true);
});

// --- IP pemanggil -----------------------------------------------------------

function reqWithHeaders(headers) {
  return { headers: headers };
}

test("clientIp memakai CF-Connecting-IP lebih dulu", () => {
  const request = reqWithHeaders({
    "CF-Connecting-IP": "203.0.113.7",
    "X-Forwarded-For": "198.51.100.9, 10.0.0.1",
  });
  assert.equal(clientIp(request), "203.0.113.7");
  assert.equal(clientIp({ headers: new Headers({ "cf-connecting-ip": "203.0.113.8" }) }), "203.0.113.8");
});

test("clientIp fallback ke X-Forwarded-For paling kiri", () => {
  assert.equal(clientIp(reqWithHeaders({ "X-Forwarded-For": "198.51.100.9, 10.0.0.1" })), "198.51.100.9");
  assert.equal(clientIp(reqWithHeaders({ "x-forwarded-for": " 198.51.100.10 " })), "198.51.100.10");
});

test("clientIp mengembalikan string kosong kalau header IP tidak ada", () => {
  assert.equal(clientIp(reqWithHeaders({})), "");
  assert.equal(clientIp({ headers: new Headers() }), "");
  assert.equal(clientIp(undefined), "");
});

// --- Rate limit -------------------------------------------------------------

// Stempel waktu yang tepat di awal jendela (kelipatan 600 s), supaya Retry-After bisa
// diperiksa persis: sisanya pas penuh di detik ke-0.
const T0 = 1_700_000_000_000 - (1_700_000_000_000 % 600_000);

test("rateLimitKey stabil dalam satu jendela dan berpindah di jendela berikutnya", () => {
  const ip = "203.0.113.7";
  const short = 10;
  const inside = rateLimitKey(ip, short, 1_700_000_003_000);
  assert.equal(rateLimitKey(ip, short, 1_700_000_000_000), inside);
  assert.equal(rateLimitKey(ip, short, 1_700_000_009_999), inside);
  assert.notEqual(rateLimitKey(ip, short, 1_700_000_010_000), inside);
  assert.notEqual(rateLimitKey(ip, short, 1_700_000_020_000), rateLimitKey(ip, short, 1_700_000_010_000));
});

test("rateLimitKey memisahkan IP dan panjang jendela", () => {
  const t = 1_700_000_000_000;
  assert.notEqual(rateLimitKey("203.0.113.7", 600, t), rateLimitKey("203.0.113.8", 600, t));
  assert.notEqual(rateLimitKey("203.0.113.7", 600, t), rateLimitKey("203.0.113.7", 60, t));
  assert.equal(rateLimitKey("203.0.113.7", 600, t), rateLimitKey("203.0.113.7", 600, t));
  assert.match(rateLimitKey("2001:db8::1", 600, t), /^https:\/\/cfvpn-hub-rate-limit\.invalid\/api\/cf\?/);
});

test("readEnvInt: nilai tidak masuk akal jatuh ke bawaan", () => {
  assert.equal(readEnvInt("25", 10), 25);
  assert.equal(readEnvInt(" 25 ", 10), 25);
  assert.equal(readEnvInt("", 10), 10);
  assert.equal(readEnvInt(undefined, 10), 10);
  assert.equal(readEnvInt("0", 10), 10);
  assert.equal(readEnvInt("-3", 10), 10);
  assert.equal(readEnvInt("abc", 10), 10);
});

// Cache API tiruan: cukup match/put dengan Map, perilaku cukup untuk menguji penghitung.
function fakeCache() {
  const store = new Map();
  return {
    store: store,
    async match(key) {
      const value = store.get(String(key));
      return value === undefined ? undefined : new Response(value);
    },
    async put(key, response) {
      store.set(String(key), await response.text());
    },
  };
}

function requestFrom(ip) {
  return { headers: { "CF-Connecting-IP": ip } };
}

test("limiter meloloskan 10 permintaan lalu menolak ke-11 dengan Retry-After", async () => {
  const cache = fakeCache();
  const env = {}; // bawaan: 10 permintaan / 600 detik
  const nowMs = T0;
  const request = requestFrom("203.0.113.7");

  for (let i = 1; i <= 10; i++) {
    const gate = await checkRateLimit(env, request, { cache: cache, nowMs: nowMs });
    assert.equal(gate.limited, false, "permintaan ke-" + i + " harus lolos");
    assert.equal(gate.count, i);
    assert.equal(gate.limit, 10);
    assert.equal(gate.windowSec, 600);
  }

  const blocked = await checkRateLimit(env, request, { cache: cache, nowMs: nowMs });
  assert.equal(blocked.limited, true);
  assert.equal(blocked.count, 11);
  assert.equal(blocked.retryAfter, 600);
});

test("limiter menghitung per IP dan per jendela", async () => {
  const env = { RATE_LIMIT: "2", RATE_WINDOW_SEC: "60" };
  const cache = fakeCache();
  const t = T0;

  assert.equal((await checkRateLimit(env, requestFrom("a"), { cache: cache, nowMs: t })).limited, false); // a #1
  assert.equal((await checkRateLimit(env, requestFrom("b"), { cache: cache, nowMs: t })).limited, false); // b #1, jatah sendiri
  assert.equal((await checkRateLimit(env, requestFrom("a"), { cache: cache, nowMs: t })).limited, false); // a #2
  assert.equal((await checkRateLimit(env, requestFrom("a"), { cache: cache, nowMs: t })).limited, true); // a #3
  assert.equal((await checkRateLimit(env, requestFrom("b"), { cache: cache, nowMs: t })).limited, false); // b #2
  // Jendela berikutnya: penghitung mulai dari nol lagi.
  assert.equal((await checkRateLimit(env, requestFrom("a"), { cache: cache, nowMs: t + 60_000 })).limited, false);
});

test("Retry-After mengecil menjelang akhir jendela (minimal 1 detik)", async () => {
  const env = { RATE_LIMIT: "1", RATE_WINDOW_SEC: "60" };
  const cache = fakeCache();
  const start = T0;

  const first = await checkRateLimit(env, requestFrom("a"), { cache: cache, nowMs: start });
  assert.equal(first.retryAfter, 60);

  const late = await checkRateLimit(env, requestFrom("c"), { cache: cache, nowMs: start + 59_400 });
  assert.equal(late.retryAfter, 1);

  const later = await checkRateLimit(env, requestFrom("d"), { cache: cache, nowMs: start + 59_999 });
  assert.equal(later.retryAfter, 1);
});

test("tanpa Cache API (mis. Node) limiter meloloskan permintaan", async () => {
  const gate = await checkRateLimit({}, { headers: { "CF-Connecting-IP": "203.0.113.7" } }, { nowMs: T0 });
  assert.equal(gate.limited, false);
  assert.equal(gate.limit, 10);
  assert.equal(gate.windowSec, 600);
});

test("env RATE_LIMIT / RATE_WINDOW_SEC dihormati, nilai aneh kembali ke bawaan", async () => {
  const gate = await checkRateLimit({ RATE_LIMIT: "3", RATE_WINDOW_SEC: "30" }, requestFrom("203.0.113.7"), {
    nowMs: T0,
  });
  assert.equal(gate.limit, 3);
  assert.equal(gate.windowSec, 30);
  assert.equal(gate.retryAfter, 30);

  const odd = await checkRateLimit(
    { RATE_LIMIT: "banyak", RATE_WINDOW_SEC: "0" },
    requestFrom("203.0.113.8"),
    { nowMs: T0 }
  );
  assert.equal(odd.limit, 10);
  assert.equal(odd.windowSec, 600);
});
