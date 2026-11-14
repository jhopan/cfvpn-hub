// Bersihkan baris mati proxy_pool: POST /api/pool-purge { username, hash } -> { success, deleted }.
//
// Sejak sql/2026-11-15-pool-prune-service-key.sql mencabut DELETE `anon` pada public.proxy_pool,
// panel tidak boleh lagi menghapus dari browser: langkah itu dulu memakai anon key yang ikut
// terkirim ke setiap pengunjung. Route ini memverifikasi sesi panel lewat RPC whoami (hash =
// oracle yang sama dengan /api/login) dan hanya mengizinkan role admin, lalu melakukan DELETE
// dengan service key yang hanya ada di sisi server.
//
// Gerbang ini SENGAJA fail-closed: tanpa SUPABASE_SERVICE_KEY atau tanpa RPC whoami, permintaan
// ditolak (503/409) alih-alih jatuh ke anon key. Endpoint destruktif tidak boleh fail-open.
//
// Pagar: hanya POST + limiter Cache API per IP (bawaan 6 permintaan / 600 detik, env
// PURGE_RATE_LIMIT dan PURGE_RATE_WINDOW_SEC). Kunci cache dipisah per route seperti /api/login
// supaya jatah antar route tidak saling mengurangi.
import { checkRateLimit } from "./lib/rate-limit.js";
import { SUPABASE_URL } from "./lib/supabase.js";

const PURGE_RATE_LIMIT = 6;
const PURGE_RATE_WINDOW_SEC = 600;
const PURGE_KEY_ORIGIN = "https://cfvpn-hub-rate-limit.invalid/api/pool-purge";
const LIMITER = {
  limitEnv: "PURGE_RATE_LIMIT",
  windowEnv: "PURGE_RATE_WINDOW_SEC",
  limitDefault: PURGE_RATE_LIMIT,
  windowDefault: PURGE_RATE_WINDOW_SEC,
  keyOrigin: PURGE_KEY_ORIGIN,
};

// Kode PostgREST/Postgres yang berarti "fungsi belum ada di database" — sinyal migrasi SQL
// belum dijalankan, bukan salah hash.
const MISSING_CODES = ["PGRST202", "42883", "42P01"];

export async function onRequest(context) {
  if (context.request.method !== "POST") {
    return jsonResponse({ error: "Method not allowed" }, 405);
  }

  try {
    const gate = await checkRateLimit(context.env, context.request, LIMITER);
    if (gate.limited) return tooMany(gate);

    // Service key diperiksa sebelum apa pun yang menyentuh database: tanpa key ini tidak ada
    // jalur sah untuk menghapus, jadi jangan lanjut dengan anon key.
    const serviceKey = readServiceKey(context.env);
    if (!serviceKey) {
      return jsonResponse(
        {
          error:
            "SUPABASE_SERVICE_KEY belum diset di server (Pages variable/secret), jadi tombol bersihkan baris mati dinonaktifkan.",
        },
        503
      );
    }

    const credentials = await readCredentials(context.request);
    if (credentials.error) return jsonResponse({ error: credentials.error }, 400);

    const who = await callWhoami(context.env, serviceKey, credentials.username, credentials.hash);
    if (who.missing) {
      return jsonResponse(
        {
          error:
            "RPC whoami belum ada di database. Jalankan sql/2026-11-14-login-lockout.sql dulu, lalu coba lagi.",
        },
        409
      );
    }
    if (!who.ok) {
      return jsonResponse({ error: "Verifikasi sesi gagal di server: " + errorText(who) }, 502);
    }

    const role = roleOf(who.data);
    if (!role) return jsonResponse({ error: "Sesi tidak valid — login ulang." }, 401);
    if (role !== "admin") {
      return jsonResponse({ error: "Hanya admin yang boleh menghapus baris proxy." }, 403);
    }

    const purge = await deleteDeadRows(context.env, serviceKey);
    if (!purge.ok) {
      return jsonResponse({ error: "Gagal menghapus baris proxy mati: " + errorText(purge) }, 502);
    }
    return jsonResponse({ success: true, deleted: purge.deleted }, 200);
  } catch (error) {
    return jsonResponse({ error: error.message }, 500);
  }
}

// readServiceKey mengambil binding env.SUPABASE_SERVICE_KEY (trim, tolak kosong). Nilai ini
// tidak pernah dikembalikan ke pemanggil maupun dicatat ke log.
function readServiceKey(env) {
  const key = env && typeof env.SUPABASE_SERVICE_KEY === "string" ? env.SUPABASE_SERVICE_KEY.trim() : "";
  return key || "";
}

// supabaseBase memakai env.SUPABASE_URL kalau dipasang; kalau tidak, URL project yang sama
// dengan frontend/app.js.
function supabaseBase(env) {
  const url = env && env.SUPABASE_URL ? String(env.SUPABASE_URL) : SUPABASE_URL;
  return url.replace(/\/+$/, "");
}

// authHeaders = header PostgREST untuk service key. DELETE butuh apikey + Bearer.
function authHeaders(serviceKey) {
  return {
    "Content-Type": "application/json",
    apikey: serviceKey,
    Authorization: "Bearer " + serviceKey,
  };
}

// readCredentials membaca body JSON: username huruf kecil tanpa spasi (sama dengan
// lower(btrim(...)) di RPC whoami) dan hash string non-kosong.
async function readCredentials(request) {
  let data;
  try {
    data = await request.json();
  } catch {
    return { error: "Body JSON tidak valid." };
  }
  if (!data || typeof data !== "object" || Array.isArray(data)) return { error: "Body permintaan tidak valid." };

  const username = typeof data.username === "string" ? data.username.trim().toLowerCase() : "";
  if (!username || /\s/.test(username)) return { error: "Username tidak valid." };
  if (typeof data.hash !== "string" || !data.hash) return { error: "Hash sesi tidak valid." };
  return { username: username, hash: data.hash };
}

// callWhoami memanggil RPC whoami lewat PostgREST dengan service key. Hasil selalu objek supaya
// pemanggil tidak perlu melempar: { ok, status, data, missing }. missing = fungsi belum ada.
async function callWhoami(env, serviceKey, username, hash) {
  const response = await fetch(supabaseBase(env) + "/rest/v1/rpc/whoami", {
    method: "POST",
    headers: authHeaders(serviceKey),
    body: JSON.stringify({ p_username: username, p_hash: hash }),
  });

  const data = await parseJson(response);
  const code = data && typeof data === "object" ? data.code : null;
  return {
    ok: response.ok,
    status: response.status,
    data: data,
    missing: response.status === 404 || MISSING_CODES.includes(code),
  };
}

// deleteDeadRows menghapus semua baris is_active = false dan membaca jumlah terhapus dari
// Content-Range (butuh Prefer: count=exact; PostgREST membalas `*/N` untuk DELETE).
async function deleteDeadRows(env, serviceKey) {
  const response = await fetch(supabaseBase(env) + "/rest/v1/proxy_pool?is_active=eq.false", {
    method: "DELETE",
    headers: Object.assign(authHeaders(serviceKey), { Prefer: "count=exact, return=minimal" }),
  });

  return {
    ok: response.ok,
    status: response.status,
    data: await parseJson(response),
    deleted: countOf(response.headers.get("Content-Range")),
  };
}

// roleOf menormalkan balasan whoami (RPC `returns text`) menjadi string role atau null.
function roleOf(data) {
  const value = Array.isArray(data) ? data[0] : data;
  return typeof value === "string" && value ? value : null;
}

// countOf membaca N dari Content-Range ("*/N" atau "0-9/N"); null kalau tidak ada/aneh.
function countOf(contentRange) {
  if (!contentRange) return null;
  const total = String(contentRange).split("/").pop();
  if (!total || total === "*") return null;
  const count = Number(total);
  return Number.isFinite(count) ? count : null;
}

// parseJson mengembalikan body JSON atau null; body kosong (204) juga null.
async function parseJson(response) {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

// errorText mengambil pesan error PostgREST/Postgres untuk dilaporkan apa adanya.
function errorText(result) {
  if (result.data && typeof result.data === "object" && result.data.message) return String(result.data.message);
  return "HTTP " + result.status;
}

// tooMany menyusun 429 + Retry-After dari hasil limiter Cache API.
function tooMany(gate) {
  return jsonResponse(
    { error: "Terlalu banyak permintaan. Coba lagi dalam " + gate.retryAfter + " detik." },
    429,
    { "Retry-After": String(gate.retryAfter) }
  );
}

// jsonResponse menyusun balasan JSON standar route ini (header tambahan, mis. Retry-After).
function jsonResponse(body, status, extraHeaders) {
  return new Response(JSON.stringify(body), {
    status: status,
    headers: Object.assign({ "Content-Type": "application/json" }, extraHeaders || {}),
  });
}