#!/usr/bin/env node
/**
 * CFVPN Hub - Interactive Bulk Deploy Script
 * 
 * Cara pakai:
 * 1. Pastikan file .env ada (berisi CF_EMAIL, CF_API_KEY, CF_ACCOUNT_ID)
 * 2. node deploy-bulk.mjs
 */

import { readFileSync, writeFileSync, existsSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";
import * as readline from "readline";

const __dirname = dirname(fileURLToPath(import.meta.url));

// ====== READ CREDENTIALS FROM .env ======
function loadEnv() {
  const envPath = resolve(__dirname, ".env");
  if (!existsSync(envPath)) {
    console.log("❌ File .env tidak ditemukan!");
    console.log("   Buat file .env dengan format:");
    console.log("   CF_EMAIL=email@gmail.com");
    console.log("   CF_API_KEY=cfk_xxx");
    console.log("   CF_ACCOUNT_ID=xxx");
    process.exit(1);
  }
  const env = readFileSync(envPath, "utf-8");
  const vars = {};
  env.split("\n").forEach(line => {
    line = line.trim();
    if (!line || line.startsWith("#")) return;
    const [key, ...rest] = line.split("=");
    vars[key.trim()] = rest.join("=").trim().replace(/^["']|["']$/g, "");
  });
  return vars;
}

const env = loadEnv();
const CF_EMAIL = env.CF_EMAIL;
const CF_API_KEY = env.CF_API_KEY;
const CF_ACCOUNT_ID = env.CF_ACCOUNT_ID;

if (!CF_EMAIL || !CF_API_KEY || !CF_ACCOUNT_ID) {
  console.log("❌ Credentials tidak lengkap di .env!");
  console.log("   Pastikan ada: CF_EMAIL, CF_API_KEY, CF_ACCOUNT_ID");
  process.exit(1);
}
// =========================================

const SOURCE_FREE = readFileSync(resolve(__dirname, "frontend/source/vpn-worker-free.js"), "utf-8");
const SOURCE_PREM = readFileSync(resolve(__dirname, "frontend/source/vpn-worker-prem.js"), "utf-8");
const SOURCE_LB = readFileSync(resolve(__dirname, "frontend/source/load-balancer.js"), "utf-8");

const C = {
  green: (s) => `\x1b[32m${s}\x1b[0m`,
  red: (s) => `\x1b[31m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  cyan: (s) => `\x1b[36m${s}\x1b[0m`,
  dim: (s) => `\x1b[2m${s}\x1b[0m`,
  bold: (s) => `\x1b[1m${s}\x1b[0m`,
  magenta: (s) => `\x1b[35m${s}\x1b[0m`,
};

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const ask = (q) => new Promise((r) => rl.question(q, r));

function printHeader() {
  console.log(C.bold(C.cyan("\n╔══════════════════════════════════════════╗")));
  console.log(C.bold(C.cyan("║     🚀 CFVPN Hub - Deploy Manager        ║")));
  console.log(C.bold(C.cyan("╚══════════════════════════════════════════╝")));
  console.log(C.dim(`   Email:   ${CF_EMAIL}`));
  console.log(C.dim(`   Account: ${CF_ACCOUNT_ID}`));
  console.log("");
}

function printMenu() {
  console.log(C.bold("\n📋 Menu:\n"));
  console.log(`   ${C.cyan("1.")} Deploy Worker (dari file)`);
  console.log(`   ${C.cyan("2.")} Deploy Worker (input manual)`);
  console.log(`   ${C.cyan("3.")} Cek Status Worker (dari deployed.txt)`);
  console.log(`   ${C.cyan("4.")} Cek Status Worker (input URL)`);
  console.log(`   ${C.cyan("5.")} Hapus Worker`);
  console.log(`   ${C.cyan("0.")} Keluar\n`);
}

async function getSubdomain() {
  try {
    const res = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/workers/subdomain`,
      { headers: { "X-Auth-Email": CF_EMAIL, "X-Auth-Key": CF_API_KEY } }
    );
    const data = await res.json();
    return data?.result?.subdomain || null;
  } catch {
    return null;
  }
}

async function deployWorker(name, code) {
  const boundary = "----CFVPN" + Math.random().toString(36).slice(2);
  const moduleName = name + ".js";

  const body = [
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
    `https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/workers/scripts/${name}`,
    {
      method: "PUT",
      headers: {
        "X-Auth-Email": CF_EMAIL,
        "X-Auth-Key": CF_API_KEY,
        "Content-Type": `multipart/form-data; boundary=${boundary}`,
      },
      body,
    }
  );
  const uploadData = await uploadRes.json();
  if (!uploadData.success) {
    throw new Error(uploadData.errors?.[0]?.message || "Upload gagal");
  }

  await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/workers/scripts/${name}/subdomain`,
    {
      method: "POST",
      headers: {
        "X-Auth-Email": CF_EMAIL,
        "X-Auth-Key": CF_API_KEY,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ enabled: true }),
    }
  ).catch(() => {});
}

async function checkOnline(url) {
  const checks = [`${url}/myip`, `${url}/`];
  for (const checkUrl of checks) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10000);
      const res = await fetch(checkUrl, {
        signal: controller.signal,
        headers: { "User-Agent": "CFVPN-Check/1.0" },
      });
      clearTimeout(timeout);
      if (res.status < 500) return { online: true, status: res.status, url: checkUrl };
    } catch {}
  }
  return { online: false, status: 0, url: "" };
}

async function deleteWorker(name) {
  const res = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/workers/scripts/${name}`,
    {
      method: "DELETE",
      headers: { "X-Auth-Email": CF_EMAIL, "X-Auth-Key": CF_API_KEY },
    }
  );
  const data = await res.json();
  return data.success;
}

async function menuDeploy() {
  console.log(C.bold("\n📦 Deploy Worker\n"));

  console.log(`   ${C.cyan("1.")} VPN Worker (Free)`);
  console.log(`   ${C.cyan("2.")} VPN Worker (Premium)`);
  console.log(`   ${C.cyan("3.")} Load Balancer\n`);
  const srcChoice = await ask(C.bold("   Pilih jenis [1-3]: "));

  let sourceCode, sourceLabel;
  if (srcChoice === "1") { sourceCode = SOURCE_FREE; sourceLabel = "VPN Free"; }
  else if (srcChoice === "2") { sourceCode = SOURCE_PREM; sourceLabel = "VPN Premium"; }
  else if (srcChoice === "3") { sourceCode = SOURCE_LB; sourceLabel = "Load Balancer"; }
  else { console.log(C.red("❌ Pilihan tidak valid")); return; }

  console.log(`\n   ${C.cyan("1.")} Baca dari file (workers.txt)`);
  console.log(`   ${C.cyan("2.")} Input manual\n`);
  const inputChoice = await ask(C.bold("   Pilih input [1-2]: "));

  let workerNames = [];
  if (inputChoice === "1") {
    const filePath = resolve(__dirname, "workers.txt");
    if (!existsSync(filePath)) {
      console.log(C.red(`❌ File workers.txt tidak ditemukan!`));
      console.log(C.dim(`   Buat file dengan format: satu nama per baris`));
      return;
    }
    workerNames = readFileSync(filePath, "utf-8").split("\n").map(l => l.trim()).filter(Boolean);
  } else {
    console.log(C.dim("\n   Ketik nama worker (kosongkan untuk selesai):"));
    while (true) {
      const name = await ask(`   ${C.cyan("→")} `);
      if (!name.trim()) break;
      workerNames.push(name.trim());
    }
  }

  if (!workerNames.length) {
    console.log(C.red("❌ Tidak ada worker untuk deploy!"));
    return;
  }

  console.log(C.bold(`\n📋 ${workerNames.length} worker akan di-deploy (${sourceLabel})\n`));
  workerNames.forEach((n, i) => console.log(`   ${i+1}. ${n}`));

  const confirm = await ask(C.bold(`\n   Lanjut? [y/N]: `));
  if (confirm.toLowerCase() !== "y") { console.log(C.yellow("Dibatalkan.")); return; }

  const subdomain = await getSubdomain();
  const results = [];

  for (let i = 0; i < workerNames.length; i++) {
    const name = workerNames[i];
    console.log(C.bold(`\n[${i+1}/${workerNames.length}] ${name}`));

    let url = "";
    let status = "GAGAL";
    let note = "";

    try {
      process.stdout.write(`   Uploading... `);
      await deployWorker(name, sourceCode);
      console.log(C.green("✓"));

      url = subdomain ? `https://${name}.${subdomain}.workers.dev` : `https://${name}.workers.dev`;

      process.stdout.write(`   Waiting 3s... `);
      await new Promise(r => setTimeout(r, 3000));
      console.log(C.dim("done"));

      process.stdout.write(`   Checking... `);
      const check = await checkOnline(url);
      if (check.online) {
        status = "ONLINE";
        console.log(C.green(`✅ ONLINE (${check.status})`));
      } else {
        console.log(C.red(`❌ OFFLINE`));
        note = " - worker tidak response";
      }
    } catch (err) {
      console.log(C.red(`❌ ${err.message}`));
      note = ` - ${err.message}`;
    }

    results.push({ name, url, status, note });
  }

  const lines = results.map(r =>
    r.status === "ONLINE"
      ? `${r.name}\t${r.url}\t✅ ONLINE`
      : `${r.name}\tGAGAL\t❌${r.note}`
  );
  writeFileSync(resolve(__dirname, "deployed.txt"), lines.join("\n") + "\n");

  const success = results.filter(r => r.status === "ONLINE").length;
  const failed = results.filter(r => r.status === "GAGAL").length;

  console.log(C.bold(`\n\n📊 HASIL\n`));
  console.log(`   ${C.green(`✅ Sukses: ${success}`)}`);
  console.log(`   ${C.red(`❌ Gagal:  ${failed}`)}`);
  console.log(C.dim(`   Total:   ${results.length}`));
  console.log(C.cyan(`\n   Hasil: deployed.txt\n`));

  if (success > 0) {
    console.log(C.bold(`🔗 URL Online:\n`));
    results.filter(r => r.status === "ONLINE").forEach(r => {
      console.log(`   ${C.green(r.url)}`);
    });
  }
}

async function menuCheckStatus() {
  console.log(C.bold("\n🔍 Cek Status Worker\n"));

  const filePath = resolve(__dirname, "deployed.txt");
  if (!existsSync(filePath)) {
    console.log(C.red("❌ File deployed.txt tidak ditemukan!"));
    console.log(C.dim("   Deploy dulu sebelum cek status."));
    return;
  }

  const lines = readFileSync(filePath, "utf-8").split("\n").filter(Boolean);
  const urls = lines.map(l => l.split("\t")).filter(p => p[1] && p[1].startsWith("http")).map(p => ({ name: p[0], url: p[1] }));

  if (!urls.length) {
    console.log(C.red("❌ Tidak ada URL di deployed.txt!"));
    return;
  }

  console.log(`   Mengecek ${urls.length} worker...\n`);

  const results = [];
  for (let i = 0; i < urls.length; i++) {
    const { name, url } = urls[i];
    process.stdout.write(`   [${i+1}/${urls.length}] ${name}... `);
    const check = await checkOnline(url);
    if (check.online) {
      console.log(C.green(`✅ ONLINE (${check.status})`));
      results.push(`${name}\t${url}\t✅ ONLINE`);
    } else {
      console.log(C.red(`❌ OFFLINE`));
      results.push(`${name}\t${url}\t❌ OFFLINE`);
    }
  }

  writeFileSync(resolve(__dirname, "status.txt"), results.join("\n") + "\n");
  const online = results.filter(r => r.includes("ONLINE")).length;
  console.log(C.bold(`\n   ${C.green(`${online} online`)} / ${results.length} total`));
  console.log(C.cyan(`   Hasil: status.txt\n`));
}

async function menuCheckManual() {
  console.log(C.bold("\n🔍 Cek Status Manual\n"));
  console.log(C.dim("   Ketik URL (kosongkan untuk selesai):"));

  const urls = [];
  while (true) {
    const url = await ask(`   ${C.cyan("→")} `);
    if (!url.trim()) break;
    urls.push(url.trim());
  }

  if (!urls.length) return;

  for (let i = 0; i < urls.length; i++) {
    const url = urls[i];
    process.stdout.write(`   [${i+1}/${urls.length}] ${url}... `);
    const check = await checkOnline(url);
    if (check.online) {
      console.log(C.green(`✅ ONLINE (${check.status})`));
    } else {
      console.log(C.red(`❌ OFFLINE`));
    }
  }
}

async function menuDelete() {
  console.log(C.bold("\n🗑️ Hapus Worker\n"));
  const name = await ask("   Nama worker: ");
  if (!name.trim()) return;

  const confirm = await ask(C.red(`   Hapus ${name.trim()}? [y/N]: `));
  if (confirm.toLowerCase() !== "y") { console.log(C.yellow("Dibatalkan.")); return; }

  process.stdout.write("   Menghapus... ");
  const ok = await deleteWorker(name.trim());
  if (ok) console.log(C.green("✓ Hapus berhasil"));
  else console.log(C.red("❌ Gagal hapus"));
}

async function main() {
  printHeader();

  while (true) {
    printMenu();
    const choice = await ask(C.bold("   Pilih menu [0-5]: "));

    switch (choice.trim()) {
      case "1":
      case "2":
        await menuDeploy();
        break;
      case "3":
        await menuCheckStatus();
        break;
      case "4":
        await menuCheckManual();
        break;
      case "5":
        await menuDelete();
        break;
      case "0":
        console.log(C.dim("\n   Sampai jumpa! 👋\n"));
        rl.close();
        process.exit(0);
      default:
        console.log(C.red("   Pilihan tidak valid!\n"));
    }
  }
}

main().catch((err) => {
  console.error(C.red(`\n❌ Fatal: ${err.message}`));
  process.exit(1);
});
