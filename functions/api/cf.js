// Deploy Worker to Cloudflare
// POST /api/cf with { cfEmail, cfApiKey, accountId, scriptName, code, type }
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
    // Cloudflare requires multipart upload for ES module Workers
    const boundary = "----CFVPN" + Math.random().toString(36).slice(2);
    const moduleName = scriptName + ".js";
    
    const multipartBody = [
      `--${boundary}\r\n`,
      `Content-Disposition: form-data; name="metadata"\r\n`,
      `Content-Type: application/json\r\n\r\n`,
      JSON.stringify({ main_module: moduleName, compatibility_date: "2024-05-12" }) + "\r\n",
      `--${boundary}\r\n`,
      `Content-Disposition: form-data; name="${moduleName}"; filename="${moduleName}"\r\n`,
      `Content-Type: application/javascript+module\r\n\r\n`,
      code + "\r\n",
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
