// Uji endpoint auth panel: POST /api/login dan POST /api/register.
// Jalankan: node --test tests/auth-endpoints.test.mjs
//
// fetch global di-stub: tidak ada jaringan Supabase sungguhan yang dipanggil, dan tiap uji
// memeriksa balasan HTTP apa adanya seperti yang dilihat panel.
import test from "node:test";
import assert from "node:assert/strict";
import { onRequest as login } from "../functions/api/login.js";
import { onRequest as register } from "../functions/api/register.js";

// --- perkakas ---------------------------------------------------------------

function jsonReply(body, status) {
  return new Response(JSON.stringify(body), {
    status: status || 200,
    headers: { "Content-Type": "application/json" },
  });
}

// withFetch memasang pengganti fetch global selama fn berjalan, lalu mengembalikannya.
// routes = daftar [potongan URL, (init) => Response]. URL yang tidak dikenal melempar supaya
// panggilan tak terduga terlihat sebagai kegagalan uji, bukan lolos diam-diam.
async function withFetch(routes, fn) {
  const original = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init) => {
    const target = String(url);
    const call = { url: target, body: init && init.body ? JSON.parse(init.body) : null, headers: init && init.headers };
    calls.push(call);
    for (const [match, reply] of routes) {
      if (target.includes(match)) return reply(init, call);
    }
    throw new Error("fetch tak terduga: " + target);
  };
  try {
    return await fn(calls);
  } finally {
    globalThis.fetch = original;
  }
}

// bump_rate selalu lolos: batas global bukan yang sedang diuji kecuali dinyatakan lain.
const BUMP_OK = ["bump_rate", () => jsonReply(true, 200)];
const RPC_MISSING_CODE = "PGRST202";

function post(path, body, ip) {
  return new Request("http://localhost" + path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "CF-Connecting-IP": ip || "203.0.113.7" },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

function context(path, body, ip) {
  return { request: post(path, body, ip), env: {} };
}

async function readJson(response) {
  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

// Cache API tiruan: cukup match/put dengan Map, sama seperti dipakai tests/cf-guard.test.mjs.
function fakeCache() {
  const store = new Map();
  return {
    async match(key) {
      const value = store.get(String(key));
      return value === undefined ? undefined : new Response(value);
    },
    async put(key, response) {
      store.set(String(key), await response.text());
    },
  };
}

// withCaches memasang globalThis.caches selama fn berjalan (Node tidak punya Cache API).
async function withCaches(cache, fn) {
  const original = globalThis.caches;
  globalThis.caches = { default: cache };
  try {
    return await fn();
  } finally {
    if (original === undefined) delete globalThis.caches;
    else globalThis.caches = original;
  }
}

// --- metode ---------------------------------------------------------------

test("GET /api/login dan /api/register ditolak 405 JSON", async () => {
  for (const handler of [login, register]) {
    const response = await handler({ request: new Request("http://localhost/api/x", { method: "GET" }), env: {} });
    assert.equal(response.status, 405);
    assert.equal(response.headers.get("Content-Type"), "application/json");
    assert.equal((await readJson(response)).error, "Method not allowed");
  }
});

// --- validasi body --------------------------------------------------------

test("login 400 untuk body tidak valid (tanpa memanggil verify_login)", async () => {
  const bad = [
    "{ bukan json",
    JSON.stringify({ password: "rahasia" }),
    JSON.stringify({ username: "", password: "rahasia" }),
    JSON.stringify({ username: "   ", password: "rahasia" }),
    JSON.stringify({ username: "saya admin", password: "rahasia" }),
    JSON.stringify({ username: "budi", password: 123 }),
    JSON.stringify({ username: "budi", password: "" }),
    JSON.stringify(["budi", "rahasia"]),
  ];

  await withFetch([BUMP_OK], async (calls) => {
    for (let i = 0; i < bad.length; i++) {
      // IP berbeda tiap kasus: jatah limiter (10 / 600 detik) tidak ikut terpakai habis.
      const response = await login(context("/api/login", bad[i], "203.0.113." + (30 + i)));
      assert.equal(response.status, 400, "body: " + bad[i]);
      assert.match(response.headers.get("Content-Type"), /application\/json/);
      assert.ok((await readJson(response)).error, "harus ada pesan error: " + bad[i]);
      assert.equal(calls.some((call) => call.url.includes("verify_login")), false);
    }
  });
});

test("register 400 untuk body tidak valid (sandi minimal 6 karakter)", async () => {
  const bad = [
    "{ bukan json",
    JSON.stringify({ username: "ci-baru" }),
    JSON.stringify({ username: "ci-baru", password: "12345" }),
    JSON.stringify({ username: "ci baru", password: "rahasia" }),
    JSON.stringify({ username: "ci-baru", password: 123456 }),
  ];

  await withFetch([BUMP_OK], async (calls) => {
    for (let i = 0; i < bad.length; i++) {
      // IP berbeda tiap kasus: jatah limiter (5 / 600 detik) tidak ikut terpakai habis.
      const response = await register(context("/api/register", bad[i], "203.0.113." + (21 + i)));
      assert.equal(response.status, 400, "body: " + bad[i]);
      assert.ok((await readJson(response)).error, "harus ada pesan error: " + bad[i]);
      assert.equal(calls.some((call) => call.url.includes("register_user")), false);
    }
  });
});

// --- kredensial & RPC -----------------------------------------------------

test("login 401 saat kredensial salah; username dikirim huruf kecil", async () => {
  const routes = [BUMP_OK, ["verify_login", () => jsonReply(null, 200)]];
  await withFetch(routes, async (calls) => {
    const response = await login(context("/api/login", { username: "Budi", password: "salah" }, "203.0.113.40"));
    assert.equal(response.status, 401);
    assert.equal((await readJson(response)).error, "Username atau sandi salah.");

    const call = calls.find((item) => item.url.includes("verify_login"));
    assert.ok(call, "verify_login harus dipanggil");
    assert.equal(call.body.p_username, "budi");
    assert.equal(call.body.p_password, "salah");
    assert.equal(String(call.headers.apikey).split(".").length, 3, "anon key JWT dikirim sebagai apikey");
  });
});

test("login 200 sukses mengembalikan { success, username, role }", async () => {
  const routes = [BUMP_OK, ["verify_login", () => jsonReply({ username: "budi", role: "admin" }, 200)]];
  await withFetch(routes, async () => {
    const response = await login(context("/api/login", { username: "budi", password: "rahasia" }, "203.0.113.41"));
    assert.equal(response.status, 200);
    assert.deepEqual(await readJson(response), { success: true, username: "budi", role: "admin" });
  });
});

test("register 409 saat username sudah ada (register_user false)", async () => {
  const routes = [BUMP_OK, ["register_user", () => jsonReply(false, 200)]];
  await withFetch(routes, async () => {
    const response = await register(context("/api/register", { username: "budi", password: "rahasia" }, "203.0.113.42"));
    assert.equal(response.status, 409);
    assert.equal((await readJson(response)).error, "Username sudah dipakai.");
  });
});

test("register 200 sukses selalu role user", async () => {
  const routes = [BUMP_OK, ["register_user", () => jsonReply(true, 200)]];
  await withFetch(routes, async () => {
    const response = await register(context("/api/register", { username: "ci-1750000", password: "rahasia" }, "203.0.113.43"));
    assert.equal(response.status, 200);
    assert.deepEqual(await readJson(response), { success: true, username: "ci-1750000", role: "user" });
  });
});

test("login 503 saat RPC verify_login belum ada (PGRST202)", async () => {
  const missing = () => jsonReply({ code: RPC_MISSING_CODE, message: "Could not find the function public.verify_login" }, 404);
  await withFetch([BUMP_OK, ["verify_login", missing]], async () => {
    const response = await login(context("/api/login", { username: "budi", password: "rahasia" }, "203.0.113.44"));
    assert.equal(response.status, 503);
    assert.ok((await readJson(response)).error);
  });
});

test("register 503 saat RPC register_user tidak ditemukan (HTTP 404)", async () => {
  const missing = () => jsonReply({ message: "Not Found" }, 404);
  await withFetch([BUMP_OK, ["register_user", missing]], async () => {
    const response = await register(context("/api/register", { username: "budi", password: "rahasia" }, "203.0.113.45"));
    assert.equal(response.status, 503);
    assert.ok((await readJson(response)).error);
  });
});

test("login 502 saat verify_login balas error lain (BUKAN 'belum ada')", async () => {
  const broken = () => jsonReply({ code: "42501", message: "permission denied" }, 403);
  await withFetch([BUMP_OK, ["verify_login", broken]], async () => {
    const response = await login(context("/api/login", { username: "budi", password: "rahasia" }, "203.0.113.46"));
    assert.equal(response.status, 502);
    assert.match((await readJson(response)).error, /permission denied/);
  });
});

// --- pagar -----------------------------------------------------------------

test("limiter Cache API menolak permintaan ke-(limit+1) dengan 429 + Retry-After", async () => {
  const cache = fakeCache();
  await withCaches(cache, async () => {
    const routes = [BUMP_OK, ["verify_login", () => jsonReply(null, 200)]];
    await withFetch(routes, async () => {
      const env = { LOGIN_RATE_LIMIT: "2", LOGIN_RATE_WINDOW_SEC: "600" };
      for (let i = 1; i <= 2; i++) {
        const allowed = await login({ request: post("/api/login", { username: "budi", password: "salah" }, "198.51.100.5"), env: env });
        assert.equal(allowed.status, 401, "permintaan ke-" + i + " harus lolos pagar");
      }
      const blocked = await login({ request: post("/api/login", { username: "budi", password: "salah" }, "198.51.100.5"), env: env });
      assert.equal(blocked.status, 429);
      assert.match(blocked.headers.get("Retry-After"), /^[1-9][0-9]*$/);
      assert.match((await readJson(blocked)).error, /Terlalu banyak percobaan/);
    });
  });
});

test("batas global: bump_rate false menolak 429, IP lain tidak terpengaruh", async () => {
  const routes = [
    ["bump_rate", (init, call) => jsonReply(!call.body.p_key.includes("198.51.100.77"), 200)],
    ["verify_login", () => jsonReply({ username: "budi", role: "user" }, 200)],
  ];
  await withFetch(routes, async () => {
    const blocked = await login(context("/api/login", { username: "budi", password: "rahasia" }, "198.51.100.77"));
    assert.equal(blocked.status, 429);
    assert.match(blocked.headers.get("Retry-After"), /^[1-9][0-9]*$/);

    const allowed = await login(context("/api/login", { username: "budi", password: "rahasia" }, "198.51.100.78"));
    assert.equal(allowed.status, 200);
  });
});

test("register memakai kunci dan jatah bump_rate sendiri", async () => {
  const routes = [BUMP_OK, ["register_user", () => jsonReply(true, 200)]];
  await withFetch(routes, async (calls) => {
    const response = await register(context("/api/register", { username: "ci-1750001", password: "rahasia" }, "198.51.100.79"));
    assert.equal(response.status, 200);
    const call = calls.find((item) => item.url.includes("bump_rate"));
    assert.ok(call, "bump_rate harus dipanggil");
    assert.match(call.body.p_key, /^register:198\.51\.100\.79:\d+$/);
    assert.equal(call.body.p_limit, 5);
    assert.equal(call.body.p_window_sec, 600);
  });
});

test("bump_rate belum ada/gagal tidak memblokir login (fail-open)", async () => {
  const missing = () => jsonReply({ code: RPC_MISSING_CODE, message: "Could not find the function public.bump_rate" }, 404);
  await withFetch([["bump_rate", missing], ["verify_login", () => jsonReply({ username: "budi", role: "user" }, 200)]], async () => {
    const response = await login(context("/api/login", { username: "budi", password: "rahasia" }, "198.51.100.80"));
    assert.equal(response.status, 200);
    assert.deepEqual(await readJson(response), { success: true, username: "budi", role: "user" });
  });

  // Jaringan mati pun bukan alasan menolak permintaan.
  const down = () => {
    throw new Error("network down");
  };
  await withFetch([["bump_rate", down], ["verify_login", () => jsonReply({ username: "budi", role: "user" }, 200)]], async () => {
    const response = await login(context("/api/login", { username: "budi", password: "rahasia" }, "198.51.100.81"));
    assert.equal(response.status, 200);
  });
});
