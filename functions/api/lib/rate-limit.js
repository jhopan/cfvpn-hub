// Pagar rate limit bersama untuk route Functions: helper murni + dua lapis penjaga.
//
// Lapis 1 (checkRateLimit): penghitung per IP di Cache API. Murah dan jalan tanpa database,
// tetapi caches.default PER-COLO dan entrinya bisa hilang (eviction) — jadi ini cuma prefilter
// per-colo, bukan batas sebenarnya.
// Lapis 2 (checkGlobalRateLimit): penghitung bersama di Supabase lewat RPC bump_rate. Ini batas
// lintas-colo. Kalau RPC belum ada/gagal, lapis ini dilewati (fail-open), tidak pernah memblokir.
import { rpc } from "./supabase.js";

// Bawaan gaya /api/cf: 10 permintaan / 600 detik per IP (env RATE_LIMIT / RATE_WINDOW_SEC).
// Route lain (login/register) mengoper nama env dan bawaan sendiri lewat options.checkRateLimit.
const DEFAULT_RATE_LIMIT = 10;
const DEFAULT_RATE_WINDOW_SEC = 600;
// Kunci penghitung rate limit memakai host .invalid (TLD terpesan, tidak pernah resolve)
// supaya tidak bertabrakan dengan entri cache nyata di colo yang sama.
const RATE_LIMIT_KEY_ORIGIN = "https://cfvpn-hub-rate-limit.invalid/api/cf";

// readHeader mengambil header tanpa asumsi bentuk pemanggil: Headers asli (punya get) atau
// objek biasa (dipakai pengujian Node) dengan huruf besar/kecil apa pun.
export function readHeader(headers, name) {
  if (!headers) return "";
  if (typeof headers.get === "function") {
    const value = headers.get(name);
    if (value) return String(value).trim();
  }
  const wanted = name.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() !== wanted) continue;
    const value = headers[key];
    if (typeof value === "string") return value.trim();
  }
  return "";
}

// clientIp menentukan IP pemanggil untuk rate limit: CF-Connecting-IP (diisi Cloudflare),
// fallback hop paling kiri X-Forwarded-For (mis. wrangler pages dev lokal). String kosong
// berarti IP tidak diketahui; pemanggil menggantinya jadi satu ember "unknown".
export function clientIp(request) {
  const headers = request && request.headers;
  const direct = readHeader(headers, "CF-Connecting-IP");
  if (direct) return direct;
  const forwarded = readHeader(headers, "X-Forwarded-For");
  if (forwarded) return forwarded.split(",")[0].trim();
  return "";
}

// parseOrigins memecah env ALLOWED_ORIGINS (daftar dipisah koma) jadi daftar pola: huruf
// kecil, tanpa spasi pinggir, tanpa garis miring di belakang. Nilai bukan string / kosong
// menghasilkan daftar kosong, artinya gerbang Origin mati.
export function parseOrigins(value) {
  if (typeof value !== "string") return [];
  return value
    .split(",")
    .map((pattern) => pattern.trim().toLowerCase().replace(/\/+$/, ""))
    .filter(Boolean);
}

// originAllowed mencocokkan header Origin dengan daftar pola:
//   - daftar kosong -> semua diizinkan (gerbang mati, perilaku lama),
//   - "*"           -> semua diizinkan,
//   - origin utuh   -> cocok persis, mis. "https://panel.contoh.com",
//   - "*.domain"    -> domain polos maupun subdomain apa pun ("https://a.b.domain.com"),
//   - host polos    -> cocok untuk host itu di skema apa pun ("localhost:8788").
// Origin kosong/tidak ada selalu diizinkan: itu bukan pemakaian lintas situs dari browser
// (curl, deploy-bulk.mjs, pemanggil server-ke-server), dan klien non-browser bisa memalsukan
// Origin dengan mudah — menolaknya hanya mematahkan perkakas tanpa menambah keamanan.
// Origin literal "null" (konteks opaque, mis. iframe sandbox) justru DITOLAK saat gerbang
// aktif, karena itu tetap permintaan dari browser lintas konteks.
export function originAllowed(origin, patterns) {
  if (!Array.isArray(patterns) || patterns.length === 0) return true;
  const value = typeof origin === "string" ? origin.trim().toLowerCase().replace(/\/+$/, "") : "";
  if (!value) return true;

  let host = value;
  try {
    host = new URL(value).host.toLowerCase();
  } catch {
    // Origin bukan URL utuh (mis. "null"): pencocokan berbasis host dilewati.
  }

  for (const raw of patterns) {
    const pattern = typeof raw === "string" ? raw.trim().toLowerCase().replace(/\/+$/, "") : "";
    if (!pattern) continue;
    if (pattern === "*" || pattern === value) return true;
    if (pattern.startsWith("*.")) {
      const bare = pattern.slice(2);
      if (bare && (host === bare || host.endsWith("." + bare))) return true;
      continue;
    }
    if (!pattern.includes("://") && host === pattern) return true;
  }
  return false;
}

// rateLimitKey = kunci penghitung di Cache API untuk satu IP pada satu jendela waktu. Kunci
// memuat nomor jendela, jadi jendela berikutnya memakai kunci berbeda: penghitung lama tidak
// perlu dihapus dan tidak pernah bocor ke jendela berikutnya.
// keyOrigin (opsional) memisahkan jatah antar route: satu colo tidak boleh menghabiskan kuota
// /api/login hanya karena /api/cf ramai dari IP yang sama.
export function rateLimitKey(ip, windowSec, nowMs, keyOrigin) {
  const window = Math.max(1, Math.floor(windowSec) || 0);
  const bucket = Math.floor(nowMs / (window * 1000));
  const url = new URL(keyOrigin || RATE_LIMIT_KEY_ORIGIN);
  url.searchParams.set("ip", ip || "unknown");
  url.searchParams.set("w", String(window));
  url.searchParams.set("b", String(bucket));
  return url.toString();
}

// readEnvInt membaca angka positif dari env; nilai kosong/aneh kembali ke bawaan supaya salah
// tulis env tidak mematikan pagar maupun tiba-tiba memblokir semua permintaan.
export function readEnvInt(value, fallback) {
  if (value === undefined || value === null || value === "") return fallback;
  const parsed = Number.parseInt(String(value).trim(), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

// checkRateLimit menghitung permintaan per IP pada jendela waktu berjalan memakai Cache API
// (LAPIS 1: prefilter murah per-colo, lihat catatan di kepala berkas). Permintaan ke-(limit+1)
// dan seterusnya ditolak; pemanggil membalas 429 + Retry-After.
//
// options: { cache, nowMs } hanya dipakai pengujian; runtime memakai caches.default + Date.now().
// options scope (limitEnv/windowEnv/limitDefault/windowDefault/keyOrigin) dipakai route lain
// supaya bisa punya bawaan dan nama env sendiri tanpa menyalin fungsi ini.
export async function checkRateLimit(env, request, options) {
  const settings = env || {};
  const opts = options || {};
  const limit = readEnvInt(
    settings[opts.limitEnv || "RATE_LIMIT"],
    typeof opts.limitDefault === "number" ? opts.limitDefault : DEFAULT_RATE_LIMIT
  );
  const windowSec = readEnvInt(
    settings[opts.windowEnv || "RATE_WINDOW_SEC"],
    typeof opts.windowDefault === "number" ? opts.windowDefault : DEFAULT_RATE_WINDOW_SEC
  );
  const ip = clientIp(request) || "unknown";
  const nowMs = typeof opts.nowMs === "number" ? opts.nowMs : Date.now();

  const windowMs = windowSec * 1000;
  // Retry-After = sisa jendela berjalan dalam detik (dibulatkan ke atas, minimal 1).
  const retryAfter = Math.max(1, Math.ceil((windowMs - (nowMs % windowMs)) / 1000));
  const result = { limited: false, count: 0, limit: limit, windowSec: windowSec, retryAfter: retryAfter, ip: ip };

  const cache = opts.cache || (typeof caches !== "undefined" && caches && caches.default ? caches.default : null);
  if (!cache) return result;

  const key = rateLimitKey(ip, windowSec, nowMs, opts.keyOrigin);
  let count = 0;
  try {
    const hit = await cache.match(key);
    if (hit) count = Number.parseInt(await hit.text(), 10) || 0;
  } catch {
    count = 0; // cache tidak terbaca: anggap jendela baru (fail-open; pagar ini hanya best-effort)
  }

  count += 1;
  result.count = count;
  if (count > limit) {
    result.limited = true;
    return result;
  }

  try {
    await cache.put(key, new Response(String(count), { headers: { "Cache-Control": "max-age=" + windowSec } }));
  } catch {
    // gagal menulis penghitung: permintaan tetap dilayani, pagar jadi lebih longgar.
  }
  return result;
}

// Dicatat sekali per isolate supaya log tidak dibanjiri: kekurangan Pagar Global biasanya soal
// konfigurasi/deploy SQL, bukan kejadian per permintaan.
let globalLimitWarned = false;

function warnGlobalLimitOnce(reason) {
  if (globalLimitWarned) return;
  globalLimitWarned = true;
  console.warn("Pagar rate limit global dilewati (" + reason + "); jalankan sql/2026-11-14-ratelimit.sql.");
}

// checkGlobalRateLimit = LAPIS 2, batas lintas-colo lewat RPC public.bump_rate di Supabase.
// Kunci "scope:ip:jendela" (scope = 'cf' | 'login' | 'register') supaya jatah antar route tidak
// saling mengurangi, dan memuat nomor jendela supaya baris lama bisa dibersihkan di sisi SQL.
//
// PENTING: apa pun yang gagal (RPC belum ada, HTTP error, jaringan, balasan bukan boolean)
// DILEWATI — pagar ini tidak pernah memblokir permintaan karena masalah infrastruktur; hanya
// hasil boolean false dari bump_rate yang menolak (429 di pemanggil).
//
// options: { scope, limit, windowSec, ip?, nowMs? }.
export async function checkGlobalRateLimit(env, request, options) {
  const opts = options || {};
  const windowSec = readEnvInt(opts.windowSec, DEFAULT_RATE_WINDOW_SEC);
  const limit = readEnvInt(opts.limit, DEFAULT_RATE_LIMIT);
  const ip = opts.ip || clientIp(request) || "unknown";
  const nowMs = typeof opts.nowMs === "number" ? opts.nowMs : Date.now();

  const windowMs = windowSec * 1000;
  const retryAfter = Math.max(1, Math.ceil((windowMs - (nowMs % windowMs)) / 1000));
  const result = { limited: false, skipped: false, limit: limit, windowSec: windowSec, retryAfter: retryAfter, ip: ip };
  if (!opts.scope) return result;

  const bucket = Math.floor(nowMs / windowMs);
  const key = opts.scope + ":" + ip + ":" + bucket;

  let outcome;
  try {
    outcome = await rpc(env, "bump_rate", { p_key: key, p_limit: limit, p_window_sec: windowSec });
  } catch (error) {
    warnGlobalLimitOnce("jaringan: " + (error && error.message ? error.message : error));
    result.skipped = true;
    return result;
  }

  if (!outcome.ok || outcome.missing || typeof outcome.data !== "boolean") {
    warnGlobalLimitOnce(outcome.missing ? "RPC bump_rate belum ada" : "balasan bump_rate tidak dikenal");
    result.skipped = true;
    return result;
  }

  result.limited = outcome.data === false;
  return result;
}
