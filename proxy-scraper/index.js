const axios = require('axios');
const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = "https://cgflrpjavyotvolnvcnl.supabase.co";
const SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImNnZmxycGphdnlvdHZvbG52Y25sIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODU5MjU5MTYsImV4cCI6MjEwMTUwMTkxNn0.-e9GFpQBDBQUdAYsqfu7kuUwAQaY_Mf6dc3BhUuGNmc";
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

const SOURCES = [
  "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt"
];

async function checkProxy(ip, port) {
  try {
    const { data } = await axios.get("https://id1.foolvpn.web.id/api/v1/check?ip=" + ip + ":" + port, { timeout: 3000 });
    return data && data.ip !== ""; // Endpoint tidak return tcp_port_open, tapi isi 'ip' kalau berhasil
  } catch (e) {
    return false;
  }
}

async function asyncPool(poolLimit, array, iteratorFn) {
  const ret = [];
  const executing = [];
  for (const item of array) {
    const p = Promise.resolve().then(() => iteratorFn(item, array));
    ret.push(p);
    if (poolLimit <= array.length) {
      const e = p.then(() => executing.splice(executing.indexOf(e), 1));
      executing.push(e);
      if (executing.length >= poolLimit) await Promise.race(executing);
    }
  }
  return Promise.all(ret);
}

async function scrapeProxies() {
  console.log("Memulai scraping proxy...");
  let allProxies = new Set(); 

  for (const url of SOURCES) {
    try {
      console.log("Mendownload dari: " + url);
      const { data } = await axios.get(url, { timeout: 10000 });
      const lines = data.split(/\r?\n/);
      for (const line of lines) {
        const ip = line.trim();
        if (/^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/.test(ip)) {
          allProxies.add(ip);
        }
      }
    } catch (e) {
      console.error("Gagal load " + url + ": " + e.message);
    }
  }

  const list = Array.from(allProxies).slice(0, 500); // Ambil 500 dulu biar cepet
  console.log("Total proxy unik diambil (max 500): " + list.length);
  if (list.length === 0) return;

  const { data: existingData } = await supabase.from('proxy_pool').select('ip, port');
  const existingSet = new Set((existingData || []).map(p => p.ip + ":" + p.port));

  const newProxies = [];
  for (const item of list) {
    let host = item; let port = '443';
    if (item.includes(':')) {
      const parts = item.split(':');
      host = parts[0]; port = parts[1];
    }
    if (!existingSet.has(host + ":" + port)) {
      newProxies.push({ ip: host, port });
    }
  }

  console.log("Proxy BARU untuk dicek & disave: " + newProxies.length);
  if (newProxies.length === 0) return;

  console.log("Mengecek proxy (bisa memakan waktu beberapa saat)...");
  
  const results = [];
  let checked = 0;
  
  await asyncPool(50, newProxies, async (proxy) => {
    const isAlive = await checkProxy(proxy.ip, proxy.port);
    checked++;
    if (checked % 50 === 0) console.log("Dicek: " + checked + "/" + newProxies.length);
    
    results.push({
      ip: proxy.ip,
      port: proxy.port,
      is_active: isAlive,
      last_checked: new Date().toISOString()
    });
  });

  const activeCount = results.filter(r => r.is_active).length;
  console.log("Selesai cek. Hidup: " + activeCount + " | Mati: " + (results.length - activeCount));

  console.log("Menyimpan ke Supabase...");
  const chunkSize = 200;
  for (let i = 0; i < results.length; i += chunkSize) {
    const chunk = results.slice(i, i + chunkSize);
    const { error } = await supabase.from('proxy_pool').insert(chunk);
    if (error) console.error("Gagal insert:", error.message);
    else console.log("Berhasil insert " + chunk.length + " baris.");
  }
}

scrapeProxies();
