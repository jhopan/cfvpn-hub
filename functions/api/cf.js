// Deploy Worker to Cloudflare
// POST /api/cf with { cfEmail, cfApiKey, accountId, scriptName, code, type }
import { stripComments } from "./strip-comments.js";

// Pagar route ini: rate limit per IP (Cache API) + gerbang Origin opsional.
// Bawaan rate limit = 10 permintaan / 600 detik per IP, bisa diatur lewat env RATE_LIMIT
// dan RATE_WINDOW_SEC. Gerbang Origin hanya aktif kalau env ALLOWED_ORIGINS diisi.
const DEFAULT_RATE_LIMIT = 10;
const DEFAULT_RATE_WINDOW_SEC = 600;
// Kunci penghitung rate limit memakai host .invalid (TLD terpesan, tidak pernah resolve)
// supaya tidak bertabrakan dengan entri cache nyata di colo yang sama.
const RATE_LIMIT_KEY_ORIGIN = "https://cfvpn-hub-rate-limit.invalid/api/cf";

export async function onRequest(context) {
  if (context.request.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405,
      headers: { "Content-Type": "application/json" },
    });
  }

  try {
    // Gerbang Origin opsional (env ALLOWED_ORIGINS). Kalau env kosong/tidak diisi, gerbang
    // mati sepenuhnya dan perilaku lama tidak berubah — curl, deploy-bulk.mjs, dan pemanggil
    // server-ke-server (tanpa header Origin) tetap lewat.
    const allowedOrigins = parseOrigins(context.env?.ALLOWED_ORIGINS);
    if (!originAllowed(readHeader(context.request.headers, "Origin"), allowedOrigins)) {
      return jsonResponse({ error: "Origin tidak diizinkan." }, 403);
    }

    // Rate limit per IP, dicek sebelum kerja mahal apa pun (dan setelah gerbang Origin supaya
    // permintaan yang jelas tidak berhak tidak memakan jatah jendela milik pemanggil sah).
    const gate = await checkRateLimit(context.env, context.request);
    if (gate.limited) {
      return jsonResponse(
        { error: "Terlalu banyak permintaan. Coba lagi dalam " + gate.retryAfter + " detik." },
        429,
        { "Retry-After": String(gate.retryAfter) }
      );
    }

    const data = await context.request.json();
    const { cfEmail, cfApiKey, accountId, scriptName, code, type } = data;

    if (!cfEmail || !cfApiKey || !accountId || !scriptName || !code) {
      return new Response(JSON.stringify({ error: "Data Cloudflare tidak lengkap." }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    // Binding env opsional dari panel (dipakai mis. untuk relay UDP: RELAY_SERVER_UDP,
    // RELAY_SERVER_PORT, RELAY_SERVER_TLS, RELAY_SECRET). Divalidasi ketat karena nilainya
    // dikirim ke API Cloudflare sebagai binding plain_text.
    const vars = normalizeVars(data.vars);
    if (vars.error) {
      return new Response(JSON.stringify({ error: vars.error }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    // 1. Get workers.dev subdomain
    let subdomain = null;
    const subRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/subdomain`, {
      headers: { "X-Auth-Email": cfEmail, "X-Auth-Key": cfApiKey },
    });
    if (subRes.ok) {
      const subData = await subRes.json();
      if (subData.success && subData.result) {
        subdomain = subData.result.subdomain;
      }
    }

    // 2. Upload Worker script as ES module (multipart/form-data)
    // Cloudflare requires multipart upload for ES module Workers.
    // Komentar dibuang dulu: source apa adanya (dengan komentar) menghasilkan Worker yang
    // mati beberapa saat setelah deploy (lihat functions/api/strip-comments.js).
    const boundary = "----CFVPN" + Math.random().toString(36).slice(2);
    const moduleName = scriptName + ".js";
    const uploadCode = stripComments(code);

    const multipartBody = [
      `--${boundary}\r\n`,
      `Content-Disposition: form-data; name="metadata"\r\n`,
      `Content-Type: application/json\r\n\r\n`,
      JSON.stringify({
        main_module: moduleName,
        compatibility_date: "2024-05-12",
        ...(vars.bindings.length ? { bindings: vars.bindings } : {}),
      }) + "\r\n",
      `--${boundary}\r\n`,
      `Content-Disposition: form-data; name="${moduleName}"; filename="${moduleName}"\r\n`,
      `Content-Type: application/javascript+module\r\n\r\n`,
      uploadCode + "\r\n",
      `--${boundary}--\r\n`,
    ].join("");

    const uploadRes = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${scriptName}`,
      {
        method: "PUT",
        headers: {
          "X-Auth-Email": cfEmail,
          "X-Auth-Key": cfApiKey,
          "Content-Type": `multipart/form-data; boundary=${boundary}`,
        },
        body: multipartBody,
      }
    );

    const uploadData = await uploadRes.json();
    if (!uploadData.success) {
      const errMsg = uploadData.errors?.[0]?.message || "Gagal upload script";
      return new Response(JSON.stringify({ error: errMsg, details: uploadData.errors }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    // 3. Enable workers.dev subdomain for this script
    await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${scriptName}/subdomain`,
      {
        method: "POST",
        headers: {
          "X-Auth-Email": cfEmail,
          "X-Auth-Key": cfApiKey,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ enabled: true }),
      }
    ).catch(() => {});

    // 4. Determine final host
    const finalHost = subdomain ? `${scriptName}.${subdomain}.workers.dev` : `${scriptName}.workers.dev`;

    return new Response(JSON.stringify({
      success: true,
      host: finalHost,
      subdomain: subdomain || null,
      env: vars.bindings.map((binding) => binding.name),
    }), {
      headers: { "Content-Type": "application/json" },
    });

  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
}

// jsonResponse menyusun balasan JSON standar route ini (header tambahan, mis. Retry-After).
function jsonResponse(body, status, extraHeaders) {
  return new Response(JSON.stringify(body), {
    status: status,
    headers: { "Content-Type": "application/json", ...(extraHeaders || {}) },
  });
}

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
export function rateLimitKey(ip, windowSec, nowMs) {
  const window = Math.max(1, Math.floor(windowSec) || 0);
  const bucket = Math.floor(nowMs / (window * 1000));
  const url = new URL(RATE_LIMIT_KEY_ORIGIN);
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

// checkRateLimit menghitung permintaan per IP pada jendela waktu berjalan memakai Cache API.
// Permintaan ke-(limit+1) dan seterusnya ditolak; pemanggil membalas 429 + Retry-After.
//
// PENTING: caches.default bersifat PER-COLO, bukan global, dan entrinya boleh hilang kapan
// saja (eviction). Jadi batas ini best-effort: trafik yang tersebar ke banyak colo, atau
// cache yang kebetulan kosong, bisa menembusnya. Batas yang benar-benar global butuh Durable
// Objects atau Cloudflare Rate Limiting Rules, bukan Cache API. Yang ditekan di sini adalah
// lonjakan/retry-storm dari satu sumber yang jatuh ke colo yang sama.
//
// options ({ cache, nowMs }) hanya dipakai pengujian; runtime memakai caches.default + Date.now().
export async function checkRateLimit(env, request, options) {
  const settings = env || {};
  const opts = options || {};
  const limit = readEnvInt(settings.RATE_LIMIT, DEFAULT_RATE_LIMIT);
  const windowSec = readEnvInt(settings.RATE_WINDOW_SEC, DEFAULT_RATE_WINDOW_SEC);
  const ip = clientIp(request) || "unknown";
  const nowMs = typeof opts.nowMs === "number" ? opts.nowMs : Date.now();

  const windowMs = windowSec * 1000;
  // Retry-After = sisa jendela berjalan dalam detik (dibulatkan ke atas, minimal 1).
  const retryAfter = Math.max(1, Math.ceil((windowMs - (nowMs % windowMs)) / 1000));
  const result = { limited: false, count: 0, limit: limit, windowSec: windowSec, retryAfter: retryAfter, ip: ip };

  const cache = opts.cache || (typeof caches !== "undefined" && caches && caches.default ? caches.default : null);
  if (!cache) return result;

  const key = rateLimitKey(ip, windowSec, nowMs);
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

// normalizeVars mengubah objek env dari panel menjadi binding plain_text Cloudflare.
// Aturannya sengaja ketat: nama variabel huruf/angka/garis bawah (maks 64), nilai string
// (maks 1024), maksimal 12 pasangan, dan nilai kosong dilewati (artinya "jangan pasang").
const VAR_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const MAX_VARS = 12;
const MAX_VAR_VALUE = 1024;

export function normalizeVars(input) {
  if (input === undefined || input === null) return { bindings: [] };
  if (typeof input !== "object" || Array.isArray(input)) return { error: "Format env tidak valid." };

  const bindings = [];
  for (const [rawName, rawValue] of Object.entries(input)) {
    const name = String(rawName).trim();
    const value = rawValue === undefined || rawValue === null ? "" : String(rawValue).trim();
    if (!value) continue;
    if (!VAR_NAME.test(name)) return { error: "Nama env tidak valid: " + name };
    if (value.length > MAX_VAR_VALUE) return { error: "Nilai env terlalu panjang: " + name };
    if (name === "UUID_ALLOWLIST") {
      const entries = value.split(",").map((entry) => entry.trim()).filter(Boolean);
      if (!entries.length) continue;
      const bad = entries.find((entry) => !/^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$/i.test(entry));
      if (bad) return { error: "UUID pada UUID_ALLOWLIST tidak valid: " + bad };
    }
    if (bindings.length >= MAX_VARS) return { error: "Terlalu banyak env (maks " + MAX_VARS + ")." };
    bindings.push({ type: "plain_text", name: name, text: value });
  }
  return { bindings: bindings };
}
