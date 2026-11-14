// Pendaftaran panel: POST /api/register { username, password } -> { success, username, role }.
//
// Pendaftaran dilakukan RPC Supabase register_user (SECURITY DEFINER) yang selalu membuat role
// 'user'; anon tidak punya izin tulis mentah ke users_custom. Kalau RPC-nya belum ada (SQL belum
// dijalankan), balasan 503 supaya panel tahu harus memakai jalur lama.
//
// Pagar berlapis: limiter Cache API (prefilter murah per-colo) lalu batas GLOBAL lintas-colo
// lewat RPC bump_rate. Bawaan 5 pendaftaran / 600 detik per IP; env REGISTER_RATE_LIMIT dan
// REGISTER_RATE_WINDOW_SEC bisa menimpanya (lebih ketat dari login karena tiap pendaftaran
// menulis baris baru).
import { checkRateLimit, checkGlobalRateLimit } from "./lib/rate-limit.js";
import { rpc } from "./lib/supabase.js";

// 10 pendaftaran / 10 menit per IP: cukup untuk keluarga/kantor berbagi IP, tetap membatasi
// pembuatan akun massal dari satu alamat.
const REGISTER_RATE_LIMIT = 10;
const REGISTER_RATE_WINDOW_SEC = 600;
// Sandi minimal 6 karakter: aturan yang sama dipakai register_user di
// sql/2026-11-14-auth-hardening.sql, jadi ditolak lebih awal di sini.
const MIN_PASSWORD = 6;
// Kunci cache dipisah per route (host .invalid yang sama, path berbeda) supaya jatah /api/cf,
// /api/login, dan /api/register tidak saling mengurangi di colo yang sama.
const REGISTER_KEY_ORIGIN = "https://cfvpn-hub-rate-limit.invalid/api/register";
const LIMITER = {
  limitEnv: "REGISTER_RATE_LIMIT",
  windowEnv: "REGISTER_RATE_WINDOW_SEC",
  limitDefault: REGISTER_RATE_LIMIT,
  windowDefault: REGISTER_RATE_WINDOW_SEC,
  keyOrigin: REGISTER_KEY_ORIGIN,
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
      scope: "register",
      limit: gate.limit,
      windowSec: gate.windowSec,
      ip: gate.ip,
    });
    if (globalGate.limited) return tooMany(globalGate);

    const credentials = await readCredentials(context.request);
    if (credentials.error) return jsonResponse({ error: credentials.error }, 400);

    const result = await rpc(context.env, "register_user", {
      p_username: credentials.username,
      p_password: credentials.password,
    });
    if (result.missing) {
      return jsonResponse({ error: "Layanan pendaftaran belum siap di server (RPC register_user belum ada)." }, 503);
    }
    if (!result.ok) {
      return jsonResponse({ error: "Pendaftaran gagal di server: " + errorText(result) }, 502);
    }

    // register_user mengembalikan boolean: true = baris dibuat, false = username sudah ada.
    if (result.data !== true) {
      return jsonResponse({ error: "Username sudah dipakai." }, 409);
    }
    return jsonResponse({ success: true, username: credentials.username, role: "user" }, 200);
  } catch (error) {
    return jsonResponse({ error: error.message }, 500);
  }
}

// readCredentials membaca body JSON dan memvalidasi kolomnya: username string non-kosong tanpa
// spasi (dikembalikan huruf kecil, sama dengan pembanding lower(btrim(...)) di RPC), password
// string minimal MIN_PASSWORD karakter.
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
  if (typeof data.password !== "string" || data.password.length < MIN_PASSWORD) {
    return { error: "Sandi minimal " + MIN_PASSWORD + " karakter." };
  }
  return { username: username, password: data.password };
}

// tooMany menyusun 429 + Retry-After dari hasil limiter (Cache API atau global).
function tooMany(gate) {
  return jsonResponse({ error: "Terlalu banyak pendaftaran. Coba lagi dalam " + gate.retryAfter + " detik." }, 429, {
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
