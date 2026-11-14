// Uji endpoint purge proxy_pool: POST /api/pool-purge.
// Jalankan: node --test tests/pool-purge.test.mjs
//
// fetch global di-stub: tidak ada jaringan Supabase sungguhan yang dipanggil. Yang diuji adalah
// kontrak yang dilihat panel: tanpa service key 503 (tidak pernah jatuh ke anon), hash salah 401,
// RPC whoami belum ada 409, dan sukses memakai service key untuk DELETE, bukan anon key.
import test from "node:test";
import assert from "node:assert/strict";
import { onRequest as poolPurge } from "../functions/api/pool-purge.js";
import { SUPABASE_ANON_KEY } from "../functions/api/lib/supabase.js";

// Nilai palsu: route tidak memvalidasi bentuk JWT, hanya memastikan key inilah yang dikirim.
const SERVICE_KEY = "service-role-test-key";
const RPC_MISSING_CODE = "PGRST202";

// --- perkakas ---------------------------------------------------------------

function jsonReply(body, status) {
  return new Response(JSON.stringify(body), {
    status: status || 200,
    headers: { "Content-Type": "application/json" },
  });
}

// withFetch memasang pengganti fetch global selama fn berjalan. routes = daftar
// [potongan URL, (init, call) => Response]. URL tak dikenal melempar supaya panggilan tak
// terduga terlihat sebagai kegagalan uji, bukan lolos diam-diam.
async function withFetch(routes, fn) {
  const original = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init) => {
    const target = String(url);
    const options = init || {};
    const call = {
      url: target,
      method: options.method || "GET",
      headers: options.headers || {},
      body: options.body ? JSON.parse(options.body) : null,
    };
    calls.push(call);
    for (const [match, reply] of routes) {
      if (target.includes(match)) return reply(options, call);
    }
    throw new Error("fetch tak terduga: " + target);
  };
  try {
    return await fn(calls);
  } finally {
    globalThis.fetch = original;
  }
}

// Cache API tiruan: cukup match/put dengan Map, sama seperti tests/auth-endpoints.test.mjs.
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

function post(path, body, ip) {
  return new Request("http://localhost" + path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "CF-Connecting-IP": ip || "203.0.113.9" },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

function context(path, body, ip, env) {
  return { request: post(path, body, ip), env: env || {} };
}

const CREDENTIALS = { username: "budi", hash: "hash-sesi" };

async function readJson(response) {
  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

// deleteReply menirukan PostgREST: DELETE + Prefer count=exact membalas Content-Range "*/N".
function deleteReply(count, status) {
  return new Response(null, {
    status: status || 204,
    headers: { "Content-Range": "*/" + count },
  });
}

// --- metode & pagar --------------------------------------------------------

test("GET /api/pool-purge ditolak 405 JSON tanpa memanggil fetch", async () => {
  await withCaches(fakeCache(), async () => {
    await withFetch([], async (calls) => {
      const response = await poolPurge({
        request: new Request("http://localhost/api/pool-purge", { method: "GET" }),
        env: { SUPABASE_SERVICE_KEY: SERVICE_KEY },
      });
      assert.equal(response.status, 405);
      assert.equal(response.headers.get("Content-Type"), "application/json");
      assert.equal((await readJson(response)).error, "Method not allowed");
      assert.equal(calls.length, 0);
    });
  });
});

test("limiter per IP menolak permintaan berlebih dengan 429 + Retry-After", async () => {
  const routes = [
    ["rpc/whoami", () => jsonReply("admin", 200)],
    ["proxy_pool", () => deleteReply(0)],
  ];
  await withCaches(fakeCache(), async () => {
    await withFetch(routes, async () => {
      const env = { SUPABASE_SERVICE_KEY: SERVICE_KEY, PURGE_RATE_LIMIT: "1", PURGE_RATE_WINDOW_SEC: "600" };
      const first = await poolPurge(context("/api/pool-purge", CREDENTIALS, "203.0.113.50", env));
      assert.equal(first.status, 200);
      const second = await poolPurge(context("/api/pool-purge", CREDENTIALS, "203.0.113.50", env));
      assert.equal(second.status, 429);
      assert.ok(second.headers.get("Retry-After"));
    });
  });
});

// --- gerbang service key ---------------------------------------------------

test("503 tanpa SUPABASE_SERVICE_KEY, tidak pernah jatuh ke anon key", async () => {
  await withCaches(fakeCache(), async () => {
    await withFetch([], async (calls) => {
      const response = await poolPurge(context("/api/pool-purge", CREDENTIALS, "203.0.113.7", {}));
      assert.equal(response.status, 503);
      const data = await readJson(response);
      assert.match(data.error, /SUPABASE_SERVICE_KEY/);
      assert.equal(calls.length, 0, "tanpa service key tidak boleh ada panggilan Supabase sama sekali");
    });
  });
});

test("503 juga saat service key hanya berisi spasi", async () => {
  await withCaches(fakeCache(), async () => {
    await withFetch([], async (calls) => {
      const response = await poolPurge(
        context("/api/pool-purge", CREDENTIALS, "203.0.113.8", { SUPABASE_SERVICE_KEY: "   " })
      );
      assert.equal(response.status, 503);
      assert.equal(calls.length, 0);
    });
  });
});

// --- verifikasi sesi -------------------------------------------------------

test("400 untuk body tidak valid (tanpa memanggil Supabase)", async () => {
  const bad = [
    "{ bukan json",
    JSON.stringify({ hash: "hash-sesi" }),
    JSON.stringify({ username: "  ", hash: "hash-sesi" }),
    JSON.stringify({ username: "budi", hash: "" }),
    JSON.stringify({ username: "budi", hash: 123 }),
    JSON.stringify(["budi", "hash-sesi"]),
  ];

  await withCaches(fakeCache(), async () => {
    await withFetch([], async (calls) => {
      for (let i = 0; i < bad.length; i++) {
        const env = { SUPABASE_SERVICE_KEY: SERVICE_KEY };
        const response = await poolPurge(context("/api/pool-purge", bad[i], "203.0.113." + (60 + i), env));
        assert.equal(response.status, 400, "body: " + bad[i]);
        assert.ok((await readJson(response)).error);
      }
      assert.equal(calls.length, 0);
    });
  });
});

test("401 saat hash salah; whoami memakai service key, DELETE tidak dipanggil", async () => {
  const routes = [["rpc/whoami", () => jsonReply(null, 200)]];
  await withCaches(fakeCache(), async () => {
    await withFetch(routes, async (calls) => {
      const env = { SUPABASE_SERVICE_KEY: SERVICE_KEY };
      const response = await poolPurge(context("/api/pool-purge", { username: "Budi", hash: "salah" }, "203.0.113.10", env));
      assert.equal(response.status, 401);
      assert.match((await readJson(response)).error, /login ulang|tidak valid/i);

      const who = calls.find((call) => call.url.includes("rpc/whoami"));
      assert.ok(who, "whoami harus dipanggil");
      assert.equal(who.method, "POST");
      assert.equal(who.headers.apikey, SERVICE_KEY);
      assert.equal(who.headers.Authorization, "Bearer " + SERVICE_KEY);
      assert.notEqual(who.headers.apikey, SUPABASE_ANON_KEY);
      assert.deepEqual(who.body, { p_username: "budi", p_hash: "salah" }, "username dinormalkan huruf kecil");
      assert.equal(calls.some((call) => call.url.includes("proxy_pool")), false);
    });
  });
});

test("403 saat hash benar tapi role bukan admin", async () => {
  const routes = [["rpc/whoami", () => jsonReply("user", 200)]];
  await withCaches(fakeCache(), async () => {
    await withFetch(routes, async (calls) => {
      const response = await poolPurge(
        context("/api/pool-purge", CREDENTIALS, "203.0.113.11", { SUPABASE_SERVICE_KEY: SERVICE_KEY })
      );
      assert.equal(response.status, 403);
      assert.equal((await readJson(response)).error, "Hanya admin yang boleh menghapus baris proxy.");
      assert.equal(calls.some((call) => call.url.includes("proxy_pool")), false);
    });
  });
});

test("409 saat RPC whoami belum ada (PGRST202), tanpa fail-open", async () => {
  const routes = [["rpc/whoami", () => jsonReply({ code: RPC_MISSING_CODE, message: "Could not find the function" }, 404)]];
  await withCaches(fakeCache(), async () => {
    await withFetch(routes, async (calls) => {
      const response = await poolPurge(
        context("/api/pool-purge", CREDENTIALS, "203.0.113.12", { SUPABASE_SERVICE_KEY: SERVICE_KEY })
      );
      assert.equal(response.status, 409);
      assert.match((await readJson(response)).error, /2026-11-14-login-lockout\.sql/);
      assert.equal(calls.some((call) => call.url.includes("proxy_pool")), false, "tidak boleh menghapus tanpa verifikasi");
    });
  });
});

// --- sukses ---------------------------------------------------------------

test("200 admin: DELETE proxy_pool?is_active=eq.false memakai service key, deleted dari Content-Range", async () => {
  const routes = [
    ["rpc/whoami", () => jsonReply("admin", 200)],
    ["proxy_pool", () => deleteReply(12)],
  ];
  await withCaches(fakeCache(), async () => {
    await withFetch(routes, async (calls) => {
      const response = await poolPurge(
        context("/api/pool-purge", CREDENTIALS, "203.0.113.13", { SUPABASE_SERVICE_KEY: SERVICE_KEY })
      );
      assert.equal(response.status, 200);
      assert.deepEqual(await readJson(response), { success: true, deleted: 12 });

      const purge = calls.find((call) => call.url.includes("proxy_pool"));
      assert.ok(purge, "DELETE proxy_pool harus dipanggil");
      assert.equal(purge.method, "DELETE");
      assert.match(purge.url, /\/rest\/v1\/proxy_pool\?is_active=eq\.false$/);
      assert.equal(purge.headers.apikey, SERVICE_KEY, "DELETE memakai service key");
      assert.equal(purge.headers.Authorization, "Bearer " + SERVICE_KEY);
      assert.notEqual(purge.headers.apikey, SUPABASE_ANON_KEY, "anon key tidak boleh dipakai untuk DELETE");
      assert.match(purge.headers.Prefer, /count=exact/);
    });
  });
});

test("balasan whoami berbentuk array tetap diterima (PostgREST variasi)", async () => {
  const routes = [
    ["rpc/whoami", () => jsonReply(["admin"], 200)],
    ["proxy_pool", () => deleteReply(3)],
  ];
  await withCaches(fakeCache(), async () => {
    await withFetch(routes, async () => {
      const response = await poolPurge(
        context("/api/pool-purge", CREDENTIALS, "203.0.113.14", { SUPABASE_SERVICE_KEY: SERVICE_KEY })
      );
      assert.equal(response.status, 200);
      assert.deepEqual(await readJson(response), { success: true, deleted: 3 });
    });
  });
});

test("502 saat DELETE gagal; tidak melaporkan sukses palsu", async () => {
  const routes = [
    ["rpc/whoami", () => jsonReply("admin", 200)],
    ["proxy_pool", () => jsonReply({ message: "permission denied for table proxy_pool" }, 403)],
  ];
  await withCaches(fakeCache(), async () => {
    await withFetch(routes, async () => {
      const response = await poolPurge(
        context("/api/pool-purge", CREDENTIALS, "203.0.113.15", { SUPABASE_SERVICE_KEY: SERVICE_KEY })
      );
      assert.equal(response.status, 502);
      const data = await readJson(response);
      assert.equal(data.success, undefined);
      assert.match(data.error, /permission denied/);
    });
  });
});