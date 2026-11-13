// Deploy Worker to Cloudflare
// POST /api/cf with { cfEmail, cfApiKey, accountId, scriptName, code, type }
import { stripComments } from "./strip-comments.js";

export async function onRequest(context) {
  if (context.request.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405,
      headers: { "Content-Type": "application/json" },
    });
  }

  try {
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
