// Login panel: POST /api/login { username, password } -> { success, username, role }.
//
// Kredensial diverifikasi RPC Supabase verify_login (SECURITY DEFINER); hash sandi tidak pernah
// menyentuh browser. Kalau RPC-nya belum ada (SQL belum dijalankan), balasan 503 supaya panel
// tahu harus memakai jalur lama (baca users_custom langsung), bukan menganggap sandi salah.
//
// Pagar berlapis: limiter Cache API (prefilter murah per-colo) lalu batas GLOBAL lintas-colo
// lewat RPC bump_rate. Bawaan 10 percobaan / 600 detik per IP; env LOGIN_RATE_LIMIT dan
// LOGIN_RATE_WINDOW_SEC bisa menimpanya.
import { checkRateLimit, checkGlobalRateLimit } from "./lib/rate-limit.js";
import { rpc } from "./lib/supabase.js";

const LOGIN_RATE_LIMIT = 10;
const LOGIN_RATE_WINDOW_SEC = 600;
// Kunci cache dipisah per route (host .invalid yang sama, path berbeda) supaya jatah /api/cf,
// /api/login, dan /api/register tidak saling mengurangi di colo yang sama.
const LOGIN_KEY_ORIGIN = "https://cfvpn-hub-rate-limit.invalid/api/login";
const LIMITER = {
  limitEnv: "LOGIN_RATE_LIMIT",
  windowEnv: "LOGIN_RATE_WINDOW_SEC",
  limitDefault: LOGIN_RATE_LIMIT,
  windowDefault: LOGIN_RATE_WINDOW_SEC,
  keyOrigin: LOGIN_KEY_ORIGIN,
};

export async function onRequest(context) {
  if (context.request.method !== "POST") {
    return jsonResponse({ error: "Method not allowed" }, 405);
  }

  try {
    // Limiter Cache API dulu (murah, tidak menyentuh database), lalu batas global. Batas global
    // dilewati tanpa memblokir kalau RPC bump_rate belum tersedia (lihat lib/rate-limit.js).
    const gate = await checkRateLimit(context.env, context.request, LIMITER);
    if (gate.limited) return tooMany(gate);

    const globalGate = await checkGlobalRateLimit(context.env, context.request, {
      scope: "login",
      limit: gate.limit,
      windowSec: gate.windowSec,
      ip: gate.ip,
    });
    if (globalGate.limited) return tooMany(globalGate);

    const credentials = await readCredentials(context.request);
    if (credentials.error) return jsonResponse({ error: credentials.error }, 400);

    const result = await rpc(context.env, "verify_login", {
      p_username: credentials.username,
      p_password: credentials.password,
    });
    if (result.missing) {
      return jsonResponse({ error: "Layanan login belum siap di server (RPC verify_login belum ada)." }, 503);
    }
    if (!result.ok) {
      return jsonResponse({ error: "Login gagal di server: " + errorText(result) }, 502);
    }

    // verify_login mengembalikan objek { username, role } atau null (= tidak ada yang cocok).
    const user = result.data;
    if (!user || typeof user !== "object" || !user.username) {
      return jsonResponse({ error: "Username atau sandi salah." }, 401);
    }
    return jsonResponse({ success: true, username: String(user.username), role: user.role || "user" }, 200);
  } catch (error) {
    return jsonResponse({ error: error.message }, 500);
  }
}

// readCredentials membaca body JSON dan memvalidasi kolomnya: username string non-kosong tanpa
// spasi (dikembalikan huruf kecil, sama dengan pembanding lower(btrim(...)) di RPC), password
// string non-kosong.
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
  if (typeof data.password !== "string" || !data.password) return { error: "Sandi tidak valid." };
  return { username: username, password: data.password };
}

// tooMany menyusun 429 + Retry-After dari hasil limiter (Cache API atau global).
function tooMany(gate) {
  return jsonResponse({ error: "Terlalu banyak percobaan. Coba lagi dalam " + gate.retryAfter + " detik." }, 429, {
    "Retry-After": String(gate.retryAfter),
  });
}

// errorText mengambil pesan error PostgREST/Postgres untuk dilaporkan apa adanya.
function errorText(result) {
  if (result.data && typeof result.data === "object" && result.data.message) return String(result.data.message);
  return "HTTP " + result.status;
}

// jsonResponse menyusun balasan JSON standar route ini (header tambahan, mis. Retry-After).
function jsonResponse(body, status, extraHeaders) {
  return new Response(JSON.stringify(body), {
    status: status,
    headers: { "Content-Type": "application/json", ...(extraHeaders || {}) },
  });
}
