// Pemanggil RPC Supabase (PostgREST) untuk Functions Pages.
//
// Anon key memang publik (sudah ikut terkirim ke setiap pengunjung panel lewat frontend/app.js),
// jadi boleh jadi nilai bawaan di sini. Kalau binding env SUPABASE_URL / SUPABASE_ANON_KEY
// dipasang saat deploy, nilai env itu yang dipakai.
export const SUPABASE_URL = "https://lumbbmhhmkcnxunuryjr.supabase.co";
export const SUPABASE_ANON_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imx1bWJibWhobWtjbnh1bnVyeWpyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTQ0NzI1MjEsImV4cCI6MjExMDA0ODUyMX0.ylMqMgv2H4vWax-whnXSRHBlD7DZs9DXVRUD9fAO6mc";

// Kode error PostgREST/Postgres yang berarti "fungsi/tabel belum ada di database": pelanggan
// harus dipaksa memakai jalur lama, bukan dianggap salah kredensial.
const MISSING_CODES = ["PGRST202", "42883", "42P01"];

// rpc memanggil satu fungsi Postgres lewat PostgREST. Hasilnya selalu objek supaya pemanggil
// tidak perlu melempar: { ok, status, data, missing }. missing = true kalau fungsinya belum ada
// (HTTP 404 atau kode PGRST202/42883/42P01), dan itu sinyal "layanan auth server belum siap".
export async function rpc(env, name, args) {
  const settings = env || {};
  const base = String(settings.SUPABASE_URL || SUPABASE_URL).replace(/\/+$/, "");
  const key = String(settings.SUPABASE_ANON_KEY || SUPABASE_ANON_KEY);

  const response = await fetch(base + "/rest/v1/rpc/" + name, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      apikey: key,
      Authorization: "Bearer " + key,
    },
    body: JSON.stringify(args || {}),
  });

  const text = await response.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }

  const code = data && typeof data === "object" ? data.code : null;
  const missing = response.status === 404 || MISSING_CODES.includes(code);
  return { ok: response.ok, status: response.status, data: data, missing: missing };
}
