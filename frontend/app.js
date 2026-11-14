import { createClient } from "https://cdn.jsdelivr.net/npm/@supabase/supabase-js/+esm";

const SUPABASE_URL = "https://lumbbmhhmkcnxunuryjr.supabase.co";
const SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imx1bWJibWhobWtjbnh1bnVyeWpyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTQ0NzI1MjEsImV4cCI6MjExMDA0ODUyMX0.ylMqMgv2H4vWax-whnXSRHBlD7DZs9DXVRUD9fAO6mc";
const supabase = SUPABASE_URL !== "ISI_URL_SUPABASE_DISINI" ? createClient(SUPABASE_URL, SUPABASE_ANON_KEY) : null;

const $ = (id) => document.getElementById(id);
const usersKey = "CFVPN-vpn-panel-users";
const sessionKey = "CFVPN-vpn-panel-session";
const emptyState = { generatedCount: 0, workers: [] };
const protectedPages = new Set(["index.html", "workers.html", "generator.html", "deploy.html", "admin.html"]);

// Constants for generator
const ALLOWED_PORTS = new Set(["80", "443"]);
const ALLOWED_PROTOCOLS = new Set(["vless", "trojan", "ss"]);
const ALLOWED_FORMATS = new Set(["raw", "v2ray", "clash", "sfa", "bfr"]);

function getFlagEmoji(cc) {
  if (!/^[a-zA-Z]{2}$/.test(cc)) return "";
  return String.fromCodePoint(...cc.toUpperCase().split("").map((char) => 0x1f1e6 + char.charCodeAt(0) - 65));
}

function shuffleArray(items) {
  for (let i = items.length - 1; i > 0; i -= 1) {
    const j = Math.floor(Math.random() * (i + 1));
    [items[i], items[j]] = [items[j], items[i]];
  }
  return items;
}function generateClashYaml(configs) {
  const proxies = configs.map((c, i) => {
    const u = new URL(c);
    if (u.protocol === "vless:") {
      return `  - name: "${decodeURIComponent(u.hash.slice(1))}"
    type: vless
    server: ${u.hostname}
    port: ${u.port}
    uuid: ${u.username}
    udp: true
    tls: ${u.searchParams.get("security") === "tls"}
    network: ws
    servername: ${u.searchParams.get("sni") || u.hostname}
    ws-opts:
      path: "${u.searchParams.get("path") || "/"}"
      headers:
        Host: ${u.searchParams.get("host") || u.hostname}`;
    }
    return ""; // Simplified: Add trojan/ss mapping if needed
  }).filter(Boolean).join("\n");
  
  return `proxies:\n${proxies}`;
}

function generateSingboxJson(configs) {
  const outbounds = configs.map((c, i) => {
    const u = new URL(c);
    if (u.protocol === "vless:") {
      return {
        type: "vless",
        tag: decodeURIComponent(u.hash.slice(1)),
        server: u.hostname,
        server_port: parseInt(u.port),
        uuid: u.username,
        tls: u.searchParams.get("security") === "tls" ? { enabled: true, server_name: u.searchParams.get("sni") || u.hostname, insecure: false } : undefined,
        transport: { type: "ws", path: u.searchParams.get("path") || "/", headers: { Host: u.searchParams.get("host") || u.hostname } }
      };
    }
    return null;
  }).filter(Boolean);
  
  return JSON.stringify({ outbounds }, null, 2);
}

async function generateLocalConfigs(params) {
  // Mode rotasi: worker yang memilih proxy sendiri (path /rotate), jadi tidak perlu daftar
  // proxy sama sekali — satu config, dan tidak perlu diganti saat pool berubah.
  if (params.rotate) {
    const bound = (state.workers || []).find((w) => w.host === params.host && w.uuid);
    const uuid = bound ? bound.uuid : crypto.randomUUID();
    const port = params.portList[0] || "443";
    const tls = port === "443";
    // Semua negara terpilih menjadi selector path: /ID, /ID,SG, atau /ALL kalau kosong.
    const countryList = (params.ccList || []).map((cc) => String(cc).trim().toUpperCase()).filter((cc) => /^[A-Z]{2}$/.test(cc));
    const country = [...new Set(countryList)].join(",");
    const path = country ? "/" + country : "/ALL";
    // `sni` hanya ditulis kalau TLS: parameter kosong membuat sebagian klien menolak config.
    const query = new URLSearchParams({
      encryption: "none", type: "ws", host: params.host,
      security: tls ? "tls" : "none", path,
    });
    if (tls) query.set("sni", params.host);
    const label = `1 CFVPN WS ${tls ? "TLS" : "NTLS"} [${country || "ALL"}] [${params.serviceName}]`;
    return formatConfigs([`vless://${uuid}@${params.host}:${port}?${query}#${encodeURIComponent(label)}`], params.format);
  }

  let proxies = [];
  
  if (params.customProxyList && params.customProxyList.length > 0) {
    proxies = params.customProxyList.map(item => {
      let ip = item;
      let port = "443";
      if (item.includes(":")) {
        const parts = item.split(":");
        ip = parts[0];
        port = parts[1];
      }
      return {
        prxIP: ip,
        prxPort: port,
        country: "XX",
        org: "Custom Proxy"
      };
    });
  } else if (supabase) {
    // Hanya proxy yang benar-benar hidup: is_active + ping bagus + cek tidak basi
    const freshLimit = new Date(Date.now() - 6 * 3600 * 1000).toISOString();
    let query = supabase.from('proxy_pool').select('*').eq('is_active', true).gt('last_checked', freshLimit);
    if (params.ccList && params.ccList.length > 0) {
      query = query.in('country', params.ccList);
    }
    const { data, error } = await query;
    if (!error && data && data.length > 0) {
      proxies = data.map(p => ({
        prxIP: p.ip,
        prxPort: p.port,
        country: p.country || "DB",
        org: p.org || "Cloud"
      }));
    }
  }
  
  if (!proxies.length) {
    throw new Error("Tidak ada proxy aktif. Coba ubah filter negara/penyedia.");
  }
  
  shuffleArray(proxies);

  // Kalau worker ini dikunci dengan UUID saat deploy (binding UUID_ALLOWLIST), pakai UUID itu —
  // kalau tidak, worker akan menolak koneksi.
  const boundWorker = (state.workers || []).find((w) => w.host === params.host && w.uuid);
  const uuid = boundWorker ? boundWorker.uuid : crypto.randomUUID();
  const configs = [];
  outer: for (const proxy of proxies) {
    for (const port of params.portList) {
      if (configs.length >= params.limit) break outer;
      const tls = port === "443";
      const path = `/${proxy.prxIP}-${proxy.prxPort}`;
      const label = `${configs.length + 1} ${getFlagEmoji(proxy.country)} ${proxy.org} WS ${tls ? "TLS" : "NTLS"} [${params.serviceName}]`;
      
      const query = new URLSearchParams({ encryption: "none", type: "ws", host: params.host, security: tls ? "tls" : "none", path });
      if (tls) query.set("sni", params.host);
      const config = `vless://${uuid}@${params.host}:${port}?${query}#${encodeURIComponent(label)}`;
      configs.push(config);
    }
  }

  if (!configs.length) throw new Error("Proxy tidak ditemukan untuk negara pilihan.");
  return formatConfigs(configs, params.format);
}

// Formatkan daftar VLESS URI sesuai pilihan output (dipakai jalur normal maupun mode rotate).
function formatConfigs(configs, format) {
  if (format === "v2ray") return btoa(configs.join("\n"));
  if (format === "clash") return generateClashYaml(configs);
  if (format === "sfa" || format === "bfr") return generateSingboxJson(configs);
  return configs.join("\n");
}


function pageName() { return location.pathname.split("/").pop() || "index.html"; }

let state = { ...emptyState };
let currentUser = null; // now holds { username: string }

async function checkAuth() {
  const s = localStorage.getItem(sessionKey);
  currentUser = s ? JSON.parse(s) : null;

  const isProtected = protectedPages.has(pageName());
  const isAuthPage = pageName() === "login.html" || pageName() === "register.html";
  
  if (isProtected && !currentUser) {
    location.replace("landing.html");
    return false;
  }
  if (isAuthPage && currentUser) {
    location.replace("index.html");
    return false;
  }
  // Admin page: only admin role
  if (pageName() === "admin.html" && currentUser?.role !== "admin") {
    location.replace("index.html");
    return false;
  }
  return true;
}

// State per user: dua fase seperti auth. Setelah sql/2026-11-14-state-hardening.sql, tabel
// user_states tidak bisa dibaca/ditulis anon dan semuanya lewat RPC yang memverifikasi hash
// pemiliknya — jadi sesi palsu tidak bisa menimpa daftar worker user lain.
async function loadState() {
  if (!currentUser) return;
  const stateId = currentUser.username;

  if (!supabase) {
    const saved = localStorage.getItem(`state-${stateId}`);
    state = saved ? { ...emptyState, ...JSON.parse(saved) } : { ...emptyState };
    return;
  }

  if (currentUser.hash) {
    const viaRpc = await supabase.rpc("get_state", { p_username: stateId, p_actor_hash: currentUser.hash });
    if (!viaRpc.error) {
      state = viaRpc.data ? { ...emptyState, ...viaRpc.data } : { ...emptyState };
      return;
    }
    if (!rpcMissing(viaRpc.error)) {
      console.warn("get_state ditolak:", rpcErrorMessage(viaRpc.error));
      state = { ...emptyState };
      return;
    }
  }

  const { data } = await supabase.from('user_states').select('state_data').eq('username', stateId).maybeSingle();
  state = data && data.state_data ? { ...emptyState, ...data.state_data } : { ...emptyState };
}

async function saveState() {
  if (!currentUser) return;
  const stateId = currentUser.username;

  if (!supabase) {
    localStorage.setItem(`state-${stateId}`, JSON.stringify(state));
    return;
  }

  if (currentUser.hash) {
    const viaRpc = await supabase.rpc("save_state", { p_username: stateId, p_actor_hash: currentUser.hash, p_state: state });
    if (!viaRpc.error) return;
    if (!rpcMissing(viaRpc.error)) {
      console.warn("save_state ditolak:", rpcErrorMessage(viaRpc.error));
      return;
    }
  }

  await supabase.from('user_states').upsert({
    username: stateId,
    state_data: state,
    updated_at: new Date().toISOString(),
  }, { onConflict: 'username' });
}

function typeLabel(type) { return type === "load_balancer" ? "Load Balancer" : "VPN Worker"; }
function escapeHtml(value) { return String(value).replace(/[&<>'"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[char]); }
function activeWorkers(type) { return state.workers.filter((worker) => worker.active && (!type || worker.type === type)); }
// Hapus deklarasi lama yang tergabung dengan function lain
function validHost(host) { return /^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/.test(host) && !host.includes(".."); }

function setMessage(id, message = "", error = false) { const el = $(id); if (!el) return; el.textContent = message; el.classList.toggle("error", error); }
function requireAuth() { return true; } // Diganti checkAuth()

function renderNav() {
  const displayId = currentUser ? currentUser.username : "";
  const role = currentUser?.role || "user";
  document.querySelectorAll("[data-user-email]").forEach((el) => {
    el.innerHTML = `${escapeHtml(displayId)} <span class="role-badge ${role}">${role}</span>`;
  });
  // Show user management nav if admin
  const adminNav = $("adminNav");
  if (adminNav && role === "admin") adminNav.hidden = false;
  const adminStat = $("adminUserStat");
  if (adminStat && role === "admin") adminStat.hidden = false;
  $("logoutButton")?.addEventListener("click", () => { 
    localStorage.removeItem(sessionKey); 
    location.href = "login.html"; 
  });

  // Show admin toolbars if admin
  if (role === "admin") {
    document.querySelectorAll(".admin-toolbar").forEach(el => el.hidden = false);
    
    // Generator admin toolbar
    const genRefresh = $("genRefreshCache");
    if (genRefresh) genRefresh.onclick = () => {
      localStorage.removeItem("proxyPickerCache");
      localStorage.removeItem("proxyActiveCountCache");
      location.reload();
    };
    const genCron = $("genForceCron");
    if (genCron) genCron.onclick = async () => {
      genCron.disabled = true; genCron.textContent = "Menjalankan...";
      try { await fetch("https://cfvpn-cron-checker.fianazahwa3.workers.dev/trigger"); } catch {}
      setTimeout(() => { genCron.disabled = false; genCron.textContent = "Force Cron"; }, 3000);
    };

    // Proxy admin toolbar
    const proxyRefresh = $("proxyRefreshBtn");
    if (proxyRefresh) proxyRefresh.onclick = () => {
      localStorage.removeItem("proxyListCache");
      localStorage.removeItem("proxyPickerCache");
      localStorage.removeItem("proxyActiveCountCache");
      location.reload();
    };
    const proxyCron = $("proxyForceCron");
    if (proxyCron) proxyCron.onclick = async () => {
      proxyCron.disabled = true; proxyCron.textContent = "Menjalankan...";
      try { await fetch("https://cfvpn-cron-checker.fianazahwa3.workers.dev/trigger"); } catch {}
      setTimeout(() => { proxyCron.disabled = false; proxyCron.textContent = "Force Cron"; }, 3000);
    };
    const proxyDelDead = $("proxyDeleteDeadBtn");
    if (proxyDelDead) proxyDelDead.onclick = async () => {
      if (!confirm("Hapus semua proxy mati?")) return;
      proxyDelDead.disabled = true;
      try {
        await supabase.from("proxy_pool").delete().eq("is_active", false);
        localStorage.removeItem("proxyListCache");
        location.reload();
      } catch {}
      proxyDelDead.disabled = false;
    };
  }
}
function renderDashboard() {
  if (!$("activeWorkerCount")) return;
  $("activeWorkerCount").textContent = state.workers.filter((w) => w.active).length;
  $("generatedCount").textContent = state.generatedCount;
  // Admin: fetch total users
  if (currentUser?.role === "admin" && supabase) {
    (async () => {
      const el = $("statTotalUsers");
      if (!el) return;
      try {
        const { count } = await supabase.from("users_custom").select("username", { count: "exact", head: true });
        el.textContent = count ?? 0;
      } catch { el.textContent = "0"; }
    })();
  }
  (async () => {
    const el = $("activeProxyCount");
    if (!el) return;
    const CACHE_KEY = "proxyActiveCountCache";
    const CACHE_TTL = 6 * 60 * 60 * 1000; // 6 jam
    // 1. Cek cache localStorage dulu
    try {
      const cached = JSON.parse(localStorage.getItem(CACHE_KEY) || "null");
      if (cached && (Date.now() - cached.ts) < CACHE_TTL) {
        el.textContent = cached.count;
        return; // cache masih segar, tidak query Supabase
      }
    } catch {}
    // 2. Cache kedaluwarsa atau tidak ada → fetch baru
    try {
      let count = 0;
      if (supabase) {
        const { count: dbCount } = await supabase.from("proxy_pool").select("*", { count: "exact", head: true }).eq("is_active", true);
        if (dbCount != null) count = dbCount;
      }
      el.textContent = count;
      localStorage.setItem(CACHE_KEY, JSON.stringify({ count, ts: Date.now() }));
    } catch { el.textContent = 0; }
  })();
}
// Versi template worker yang terpasang di frontend ini. Harus sama dengan WORKER_VERSION di
// frontend/source/vpn-worker-*.js: /health mengembalikannya, jadi panel bisa menandai worker
// yang masih versi lama dan menawarkan deploy ulang.
const WORKER_TEMPLATE_VERSION = "2026-11-13b";

// Cek versi tiap worker aktif lewat /health (CORS terbuka) dan tampilkan badge.
async function checkWorkerVersions(workers) {
  await Promise.all(
    workers.filter((w) => w.active).map(async (worker) => {
      const el = document.querySelector(`[data-version="${worker.id}"]`);
      if (!el) return;
      try {
        const res = await fetch(`https://${worker.host}/health`, { signal: AbortSignal.timeout(6000) });
        if (!res.ok) throw new Error(`http ${res.status}`);
        const data = await res.json();
        if (data.version === WORKER_TEMPLATE_VERSION) {
          el.innerHTML = "<b>terbaru</b>";
          return;
        }
        const link = `deploy.html?name=${encodeURIComponent(worker.name)}&type=${encodeURIComponent(worker.type)}&uuid=${encodeURIComponent(worker.uuid || "")}`;
        el.innerHTML = `versi lama (${escapeHtml(String(data.version || "?"))}) · <a href="${link}">deploy ulang</a>`;
        el.style.borderColor = "var(--warn)";
      } catch (err) {
        el.textContent = "versi tidak diketahui";
      }
    })
  );
}

function renderWorkers() {
  if (!$("workerList")) return;
  $("emptyWorkers").hidden = state.workers.length > 0;

  const vpnWorkers = state.workers.filter(w => w.type === "vpn");
  const lbWorkers = state.workers.filter(w => w.type === "load_balancer");

  const cardHtml = (worker) => {
    let extra = "";
    if (worker.type === "load_balancer") {
      const domains = worker.vpn_domains || [];
      const subUrl = `${worker.host}/api/v1/sub?format=raw&limit=20${domains.length ? "&domains=" + domains.join(",") : ""}`;
      extra = `<div class="lb-details"><div class="lb-domains"><span class="eyebrow">VPN Worker terhubung</span><code>${domains.length ? escapeHtml(domains.join(", ")) : "<i>Belum ada</i>"}</code></div><div class="lb-sub"><span class="eyebrow">URL Subscription</span><div class="sub-row"><code class="sub-url">${escapeHtml(subUrl)}</code><button class="icon-button" data-copy-sub="${escapeHtml(subUrl)}" type="button">Copy</button></div></div><button class="icon-button" data-edit-lb="${worker.id}" type="button" style="margin-top:8px">Edit VPN Domains</button></div>`;
    }
    return `<article class="worker-card worker-card-lb"><div class="worker-card-head"><div><p class="worker-title">${escapeHtml(worker.name)}</p><code>${escapeHtml(worker.host)}</code></div><div class="worker-meta"><span class="type">${typeLabel(worker.type)}</span><label class="switch"><input data-toggle="${worker.id}" type="checkbox" ${worker.active ? "checked" : ""}><span></span><b>${worker.active ? "Aktif" : "Nonaktif"}</b></label>${worker.type === "vpn" ? `<a class="icon-button" href="generator.html?worker=${worker.id}">Pakai</a><span class="badge" data-version="${worker.id}" style="margin-left:6px">cek versi…</span>` : ""}<button class="icon-button danger" data-delete="${worker.id}" type="button">Hapus</button></div></div>${extra}</article>`;
  };

  const sectionHtml = (title, count, workers) => {
    if (!workers.length) return "";
    return `<div class="worker-section"><div class="worker-section-head"><h3>${title}</h3><span class="badge">${count} aktif</span></div><div class="worker-grid">${workers.map(cardHtml).join("")}</div></div>`;
  };

  $("workerList").innerHTML =
    sectionHtml("VPN Worker", vpnWorkers.filter(w => w.active).length, vpnWorkers) +
    sectionHtml("Load Balancer", lbWorkers.filter(w => w.active).length, lbWorkers);

  checkWorkerVersions(vpnWorkers);

  $("showAddWorker").onclick = () => {
    const form = $("addWorkerForm");
    form.reset();
    delete form.dataset.editId;
    form.querySelector("button[type=submit]").textContent = "Simpan Worker";
    $("vpnDomainsField").hidden = true;
    form.hidden = false;
  };
  $("cancelAddWorker").onclick = () => { $("addWorkerForm").hidden = true; $("addWorkerForm").reset(); $("vpnDomainsField").hidden = true; };

  // Show/hide VPN domains field based on type
  $("workerType").onchange = (e) => {
    $("vpnDomainsField").hidden = e.target.value !== "load_balancer";
  };

  $("addWorkerForm").onsubmit = (event) => {
    event.preventDefault();
    const form = event.target;
    const host = $("workerHost").value.trim().replace(/^https?:\/\//i, "").replace(/[/?:#].*$/, "").toLowerCase();
    if (!validHost(host)) return alert("Domain Worker tidak valid.");
    const type = $("workerType").value;
    const editId = form.dataset.editId;
    if (editId) {
      const w = state.workers.find(w => w.id === editId);
      if (!w) return;
      w.name = $("workerName").value.trim();
      w.host = host;
      w.type = type;
      if (type === "load_balancer") {
        const domains = $("workerVpnDomains").value.trim();
        w.vpn_domains = domains ? domains.split(",").map(d => d.trim().replace(/^https?:\/\//i, "").replace(/[/?:#].*$/, "").toLowerCase()).filter(Boolean) : [];
      } else {
        delete w.vpn_domains;
      }
      delete form.dataset.editId;
    } else {
      const worker = { id: crypto.randomUUID(), name: $("workerName").value.trim(), host, type, active: true };
      if (type === "load_balancer") {
        const domains = $("workerVpnDomains").value.trim();
        worker.vpn_domains = domains ? domains.split(",").map(d => d.trim().replace(/^https?:\/\//i, "").replace(/[/?:#].*$/, "").toLowerCase()).filter(Boolean) : [];
      }
      state.workers.push(worker);
    }
    saveState();
    form.reset();
    form.hidden = true;
    $("vpnDomainsField").hidden = true;
    form.querySelector("button[type=submit]").textContent = "Simpan Worker";
    renderWorkers();
  };

  $("workerList").onclick = (event) => {
    const delId = event.target.dataset.delete;
    if (delId) { state.workers = state.workers.filter(w => w.id !== delId); saveState(); renderWorkers(); return; }
    const copySub = event.target.dataset.copySub;
    if (copySub) { navigator.clipboard.writeText(copySub); event.target.textContent = "Copied!"; setTimeout(() => event.target.textContent = "Copy", 1500); return; }
    const editLb = event.target.dataset.editLb;
    if (editLb) {
      const worker = state.workers.find(w => w.id === editLb);
      if (!worker) return;
      const form = $("addWorkerForm");
      $("workerName").value = worker.name;
      $("workerHost").value = worker.host;
      $("workerType").value = worker.type;
      $("vpnDomainsField").hidden = worker.type !== "load_balancer";
      $("workerVpnDomains").value = (worker.vpn_domains || []).join(", ");
      form.hidden = false;
      form.dataset.editId = editLb;
      form.querySelector("button[type=submit]").textContent = "Update Worker";
      form.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  };

  $("workerList").onchange = (event) => {
    const id = event.target.dataset.toggle;
    if (id) { state.workers = state.workers.map(w => w.id === id ? { ...w, active: event.target.checked } : w); saveState(); renderWorkers(); }
  };
}

let _proxyPickerCache = null;

async function loadProxyPickerData() {
  if (_proxyPickerCache) return _proxyPickerCache;
  const CACHE_KEY = "proxyPickerCache";
  const CACHE_TTL = 6 * 60 * 60 * 1000;
  try {
    const cached = JSON.parse(localStorage.getItem(CACHE_KEY) || "null");
    if (cached && cached.v === 2 && (Date.now() - cached.ts) < CACHE_TTL) {
      _proxyPickerCache = cached.data;
      return _proxyPickerCache;
    }
  } catch {}
  let proxies = [];
  if (supabase) {
    // `last_checked` dipakai untuk tahu baris mana yang masih segar (worker hanya memakai baris
    // < 6 jam), sedangkan `tunnel_ok`/`tunnel_ms` diisi cron-worker dari probe tunnel nyata.
    // Kolom tunnel bisa belum ada (butuh SQL), jadi kalau PostgREST menolaknya panel tetap jalan
    // dengan proyeksi lama.
    const base = "ip,port,country,org,last_checked,ping";
    const { data, error } = await supabase.from("proxy_pool").select(base + ",tunnel_ok,tunnel_ms").eq("is_active", true);
    let rows = data;
    if (error) ({
      data: rows,
    } = await supabase.from("proxy_pool").select(base).eq("is_active", true));
    if (rows && rows.length) {
      proxies = rows.map((p) => ({
        ip: p.ip,
        port: String(p.port),
        country: p.country || "",
        org: p.org || "",
        checked: p.last_checked || "",
        ping: Number(p.ping) || 0,
        tunnel: typeof p.tunnel_ok === "boolean" ? p.tunnel_ok : null,
        tunnelMs: Number(p.tunnel_ms) || 0,
      }));
    }
  }
  // No local fallback — only use Supabase
  if (!proxies.length) return [];
  proxies = proxies.map(p => ({ ...p, country: p.country || "??", org: p.org || "Unknown" }));
  _proxyPickerCache = proxies;
  localStorage.setItem(CACHE_KEY, JSON.stringify({ v: 2, data: proxies, ts: Date.now() }));
  return proxies;
}

// Sehat = cron baru mengecek (< 6 jam, sama seperti filter pool di worker) dan tidak pernah
// dinyatakan mati oleh probe tunnel. `null` berarti belum pernah diprobe, bukan mati.
const PROXY_FRESH_MS = 6 * 60 * 60 * 1000;
function proxyHealth(list, countries) {
  const now = Date.now();
  const wanted = (countries || []).filter(Boolean);
  const scope = wanted.length ? list.filter((p) => wanted.includes(p.country)) : list;
  const fresh = scope.filter((p) => {
    const t = Date.parse(p.checked || "");
    return Number.isFinite(t) && (now - t) < PROXY_FRESH_MS;
  });
  const verifiedList = fresh.filter((p) => p.tunnel === true);
  const usable = fresh.filter((p) => p.tunnel !== false);
  return {
    total: scope.length,
    fresh: fresh.length,
    verifiedCount: verifiedList.length,
    knownDead: fresh.filter((p) => p.tunnel === false).length,
    usable: usable.slice().sort(proxySpeed),
    verified: verifiedList.slice().sort(proxySpeed),
    // Kalau sudah ada cukup baris yang terbukti tembus tunnel, tawarkan hanya itu: baris yang
    // belum pernah diprobe masih untung-untungan, dan cron hampir selalu mematikan separuhnya.
    preferred: (verifiedList.length >= 2 ? verifiedList.slice() : usable.slice()).sort(proxySpeed),
  };
}

// Tercepat dulu: tunnel_ms (hasil tunnel nyata yang diukur cron) → ping cek ringan → sisanya
// di belakang. Urutan ini yang dipakai daftar proxy maupun mode rotasi.
function proxySpeed(a, b) {
  const speed = (p) => (p.tunnelMs > 0 ? p.tunnelMs : (p.ping > 0 ? p.ping + 1000 : 1e9));
  return speed(a) - speed(b);
}

function renderGenerator() {
  if (!$("generatorForm")) return;
  const workerSelect = $("workerSelect");
  const lbSelect = $("lbSelect");
  const modeSelect = $("modeSelect");
  const wanted = new URLSearchParams(location.search).get("worker");

  workerSelect.innerHTML = `<option value="">Pilih VPN Worker</option>${activeWorkers("vpn").map(w => `<option value="${w.id}">${escapeHtml(w.name)} · ${escapeHtml(w.host)}</option>`).join("")}`;
  if (wanted && [...workerSelect.options].some(o => o.value === wanted)) workerSelect.value = wanted;

  const lbWorkers = activeWorkers("load_balancer");
  lbSelect.innerHTML = `<option value="">Pilih Load Balancer</option>${lbWorkers.map(w => `<option value="${w.id}">${escapeHtml(w.name)} · ${escapeHtml(w.host)}</option>`).join("")}`;

  let allProxies = [];
  const countrySelect = $("countrySelect");
  const orgSelect = $("orgSelect");
  const proxySelect = $("proxySelect");

  // Multi-pilih: tidak ada opsi "semua negara" — tidak memilih apa pun berarti semua negara.
  const selectedCountries = () => [...countrySelect.selectedOptions].map(o => o.value).filter(Boolean);
  const populateCountries = () => {
    const countries = [...new Set(allProxies.map(p => p.country))].filter(c => c && c !== "??").sort();
    countrySelect.innerHTML = countries.map(c => {
      const fresh = proxyHealth(allProxies, [c]).fresh;
      return `<option value="${c}">${getFlagEmoji(c)} ${c} · ${fresh} segar</option>`;
    }).join("");
  };
  const updateCountryStats = () => {
    const el = $("countryStats");
    if (!el) return;
    const cc = selectedCountries();
    if (!cc.length) {
      const all = proxyHealth(allProxies, []);
      el.textContent = `${all.fresh} proxy segar di semua negara (${all.usable.length} siap dipakai).`;
      el.classList.remove("error");
      return;
    }
    const h = proxyHealth(allProxies, cc);
    const flag = cc.map(c => `${getFlagEmoji(c)} ${c}`).join(" + ");
    const parts = [`${flag}: ${h.fresh} dari ${h.total} proxy masih segar`];
    if (h.verifiedCount) parts.push(h.verifiedCount + " terverifikasi tunnel");
    else if (h.knownDead) parts.push(`${h.knownDead} terbukti mati`);
    else parts.push("belum ada yang terverifikasi tunnel");
    let text = parts.join(" · ");
    if (!h.usable.length) text += " — kemungkinan gagal: tidak ada proxy siap pakai, pakai /ALL atau negara lain.";
    if (h.verified.length) text += " · tercepat " + h.verified[0].tunnelMs + " ms";
    el.textContent = text;
    el.classList.toggle("error", h.usable.length === 0);
  };
  const populateOrgs = () => {
    const cc = selectedCountries();
    const scope = cc.length ? allProxies.filter(p => cc.includes(p.country)) : allProxies;
    const orgs = [...new Set(scope.map(p => p.org))].sort();
    orgSelect.innerHTML = `<option value="">Semua penyedia</option>` + orgs.map(o => `<option value="${escapeHtml(o)}">${escapeHtml(o)}</option>`).join("");
  };
  const populateProxies = () => {
    const cc = selectedCountries();
    const org = orgSelect.value;
    const usable = proxyHealth(allProxies, cc).preferred;
    const filtered = org ? usable.filter(p => p.org === org) : usable;
    proxySelect.innerHTML = `<option value="">Acak (${filtered.length} proxy siap pakai)</option>` + filtered.slice(0, 200).map(p => {
      return `<option value="${p.ip}:${p.port}">${getFlagEmoji(p.country)} ${p.ip}:${p.port} · ${escapeHtml(p.org)}${p.tunnel === true ? " ✓" : ""}</option>`;
    }).join("");
  };

  (async () => {
    try {
      setMessage("formMessage", "Memuat daftar proxy...");
      allProxies = await loadProxyPickerData();
      populateCountries();
      populateOrgs();
      populateProxies();
      updateCountryStats();
      setMessage("formMessage", `${allProxies.length} proxy aktif tersedia.`);
    } catch (e) {
      setMessage("formMessage", "Gagal memuat proxy: " + e.message, true);
    }
  })();

  const selectedWorker = () => state.workers.find(w => w.id === workerSelect.value && w.type === "vpn");
  const selectedLb = () => state.workers.find(w => w.id === lbSelect.value && w.type === "load_balancer");

  modeSelect.onchange = () => {
    const isSub = modeSelect.value === "subscription";
    $("localMode").hidden = isSub;
    $("subMode").hidden = !isSub;
    updatePreview();
  };

  countrySelect.onchange = () => { populateOrgs(); populateProxies(); updateCountryStats(); updatePreview(); };
  $("rotateMode")?.addEventListener("change", () => updatePreview());
  orgSelect.onchange = () => { populateProxies(); updatePreview(); };
  proxySelect.onchange = () => updatePreview();
  lbSelect.onchange = () => updatePreview();

  const buildSubUrl = () => {
    const lb = selectedLb();
    if (!lb) return "";
    const lim = $("subLimitInput").value || 20;
    const fmt = $("subFormatSelect").value;
    const cc = $("subCcInput").value.trim();
    const domains = lb.vpn_domains || [];
    let url = `https://${lb.host}/api/v1/sub?format=${fmt}&limit=${lim}`;
    if (cc) url += `&cc=${cc.toUpperCase()}`;
    if (domains.length) url += `&domains=${domains.join(",")}`;
    return url;
  };

  const updatePreview = () => {
    const isSub = modeSelect.value === "subscription";
    if (isSub) {
      const lb = selectedLb();
      if (!lb) { $("urlPreview").textContent = "Pilih Load Balancer dulu."; return; }
      $("urlPreview").textContent = `Subscription: ${lb.host} · ${$("subLimitInput").value} config`;
    } else {
      $("subUrlPreview").hidden = true;
      const worker = selectedWorker();
      if (!worker) { $("urlPreview").textContent = "Pilih VPN Worker aktif dulu."; return; }
      const cc = selectedCountries();
      const org = orgSelect.value;
      const specific = proxySelect.value;
      const lim = $("limitInput").value;
      const rotate = $("rotateMode")?.checked === true;
      let info = `${worker.host} · ${lim} config`;
      if (specific) info += ` · ${specific}`;
      else if (cc.length) info += ` · ${cc.map(c => `${getFlagEmoji(c)} ${c}`).join("+")}`;
      else info += ` · semua negara`;
      if (org) info += ` · ${org}`;
      if (!worker.uuid) info += " · ⚠ UUID belum terikat (deploy ulang dari panel)";
      if (rotate) info += ` · path ${cc.length ? "/" + cc.join(",") : "/ALL"}`;
      $("urlPreview").textContent = info;
    }
  };

  ["workerSelect", "vpnSelect", "portSelect", "formatSelect", "limitInput", "subFormatSelect", "subLimitInput", "subCcInput"].forEach(id => $(id).addEventListener("input", updatePreview));
  updatePreview();

  $("generatorForm").onsubmit = async (event) => {
    event.preventDefault();
    const isSub = modeSelect.value === "subscription";
    $("generateButton").disabled = true;
    try {
      if (isSub) {
        const lb = selectedLb();
        if (!lb) return setMessage("formMessage", "Pilih Load Balancer dulu.", true);
        const url = buildSubUrl();
        setMessage("formMessage", "Mengambil config dari Load Balancer...");
        try {
          const res = await fetch(url, { signal: AbortSignal.timeout(15000) });
          if (!res.ok) throw new Error(`Load Balancer merespons ${res.status}`);
          const content = await res.text();
          if (!content || content.length < 10) throw new Error("Load Balancer tidak mengembalikan config.");
          $("resultText").value = content;
          const count = $("subFormatSelect").value === "raw" ? content.split("\n").filter(Boolean).length : 1;
          $("countBadge").textContent = `${count} config`;
        } catch (fetchErr) {
          // CORS atau network error: tetap tampilkan URL supaya user bisa pakai manual
          $("resultText").value = `Gagal fetch otomatis (${fetchErr.message}).\n\nSalin URL subscription di bawah dan buka di browser atau tempel ke app VPN client.\n\nURL:\n${url}`;
          $("countBadge").textContent = "0 config";
          setMessage("formMessage", "Fetch gagal. URL tetap dibuat — salin dan pakai manual.", true);
        }
        // Tampilkan URL subscription di area hasil
        const subPreview = $("subUrlPreview");
        if (subPreview) {
          $("subUrlCode").textContent = url;
          subPreview.hidden = false;
        }
        $("copyButton").disabled = false;
        $("downloadButton").disabled = false;
        state.generatedCount += 1;
        saveState();
      } else {
        const worker = selectedWorker();
        if (!worker) return setMessage("formMessage", "Pilih VPN Worker aktif dulu.", true);
        // Worker yang di-deploy panel mengunci UUID lewat binding UUID_ALLOWLIST. Kalau state
        // tidak menyimpan UUID-nya (worker lama / ditambah manual), config hasil generate akan
        // membawa UUID acak yang pasti ditolak worker — lebih baik ditolak di sini dengan pesan
        // jelas daripada user bingung kenapa "tersambung lalu putus".
        if (!worker.uuid) {
          return setMessage("formMessage", "Worker ini belum punya UUID terikat. Deploy ulang worker dari halaman Deploy supaya UUID-nya tercatat, lalu generate lagi (atau pakai config lama yang masih memakai UUID tersebut).", true);
        }
        const ccList = selectedCountries();
        const orgValue = orgSelect.value;
        const rotate = $("rotateMode")?.checked === true;
        const specificProxy = proxySelect.value;
        let customProxyList = [];
        if (!rotate) {
          if (specificProxy) {
            customProxyList = [specificProxy];
          } else {
            // Hanya baris segar (< 6 jam) dan yang belum dinyatakan mati oleh probe tunnel;
            // proxy basi berarti config yang tidak akan tersambung.
            const usable = proxyHealth(allProxies, ccList).preferred;
            customProxyList = (orgValue ? usable.filter(p => p.org === orgValue) : usable).map(p => p.ip + ":" + p.port);
          }
          if (!customProxyList.length) throw new Error("Tidak ada proxy segar untuk filter ini.");
        }
        const params = {
          host: worker.host,
          serviceName: worker.host.split(".")[0],
          vpnList: [$("vpnSelect").value],
          portList: [$("portSelect").value],
          format: $("formatSelect").value,
          limit: Number($("limitInput").value),
          ccList,
          customProxyList,
          rotate,
        };
        const content = await generateLocalConfigs(params);
        $("resultText").value = content;
        const count = params.format === "raw" ? content.split("\n").filter(Boolean).length : 1;
        $("countBadge").textContent = `${count} config`;
      }
      $("copyButton").disabled = false;
      $("downloadButton").disabled = false;
      state.generatedCount += 1;
      saveState();
      setMessage("formMessage", "Config berhasil dibuat.");
    } catch (error) {
      setMessage("formMessage", error.message, true);
    } finally {
      $("generateButton").disabled = false;
    }
  };

  $("copyButton").onclick = async () => { await navigator.clipboard.writeText($("resultText").value); setMessage("formMessage", "Config disalin."); };
  $("downloadButton").onclick = () => { const link = Object.assign(document.createElement("a"), { href: URL.createObjectURL(new Blob([$("resultText").value])), download: "CFVPN-config.txt" }); link.click(); URL.revokeObjectURL(link.href); };

  const copySubBtn = $("copySubUrlBtn");
  if (copySubBtn) {
    copySubBtn.onclick = async () => {
      await navigator.clipboard.writeText($("subUrlCode").textContent);
      copySubBtn.textContent = "Copied!";
      setTimeout(() => copySubBtn.textContent = "Copy", 1500);
    };
  }
  const openSubBtn = $("openSubUrlBtn");
  if (openSubBtn) {
    openSubBtn.onclick = () => {
      const url = $("subUrlCode").textContent;
      if (url) window.open(url, "_blank");
    };
  }
}
function renderDeploy() {
  if (!$("deployForm")) return;
  $("cancelDeploy").onclick = () => { location.href = "workers.html"; };

  // Hide premium option for non-admin users
  const tierField = $("tierField");
  const tierSelect = $("deployTier");
  if (tierSelect) {
    const premOpt = tierSelect.querySelector('option[value="prem"]');
    if (premOpt && currentUser?.role !== "admin") {
      premOpt.hidden = true;
      premOpt.disabled = true;
      tierSelect.value = "free";
    }
    // Hide entire tier field if not admin
    if (tierField && currentUser?.role !== "admin") {
      tierField.hidden = true;
    }
  }

  // Relay UDP hanya untuk worker VPN **tier Premium** — Load Balancer dan tier Free tidak
  // memasang binding relay sama sekali. Pengaman sebenarnya tetap RELAY_SECRET di relay:
  // tanpa rahasia itu, worker mana pun tidak bisa memakai relay operator.
  const relayFields = $("relayFields");
  const typeSelect = $("deployType");
  const tierSelectForRelay = $("deployTier");
  if (relayFields && typeSelect) {
    const syncRelayFields = () => {
      relayFields.hidden = typeSelect.value === "load_balancer" || currentDeployTier() !== "prem";
    };
    typeSelect.addEventListener("change", syncRelayFields);
    if (tierSelectForRelay) tierSelectForRelay.addEventListener("change", syncRelayFields);
    syncRelayFields();
  }

  // UUID worker: tombol pembuat + prefill dari query (dipakai tautan "deploy ulang" dari
  // halaman Workers) supaya redeploy memakai UUID yang sama dengan konfigurasi klien lama.
  const uuidInput = $("deployUuid");
  if (uuidInput) {
    const query = new URLSearchParams(location.search);
    if (!uuidInput.value) uuidInput.value = query.get("uuid") || "";
    const genBtn = $("genUuidBtn");
    if (genBtn) genBtn.onclick = () => { uuidInput.value = crypto.randomUUID(); };
  }
  const nameInput = $("deployName");
  if (nameInput) {
    const query = new URLSearchParams(location.search);
    const nameParam = query.get("name");
    if (nameParam) nameInput.value = nameParam.toLowerCase();
    const typeParam = query.get("type");
    if (typeParam && typeSelect) {
      typeSelect.value = typeParam;
      typeSelect.dispatchEvent(new Event("change"));
    }
  }

  $("deployForm").onsubmit = async (event) => { 
    event.preventDefault(); 
    const type = $("deployType").value; 
    const name = $("deployName").value.trim().toLowerCase();
    
    const cfApiKey = $("cfApiKey").value.trim();
    const cfEmail = $("cfEmail").value.trim();
    const accountId = $("cfAccountId").value.trim();

    // Relay tanpa rahasia akan ditolak relay-nya sendiri, jadi cegah di sini.
    if (($("relayHost")?.value.trim() || "") && !($("relaySecret")?.value.trim() || "")) {
      setMessage("deployMessage", "Rahasia relay wajib diisi kalau host relay diisi.", true);
      return;
    }

    // UUID opsional: kalau diisi, worker dikunci ke UUID ini (binding UUID_ALLOWLIST).
    const uuidValue = ($("deployUuid")?.value || "").trim();
    if (uuidValue && !/^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$/i.test(uuidValue)) {
      setMessage("deployMessage", "UUID tidak valid (format 8-4-4-4-12 heksadesimal).", true);
      return;
    }

    $("startDeployBtn").disabled = true;
    setMessage("deployMessage", "Mengambil source code worker...");

    try {
      // Ambil file dari dalam repo kita sendiri (di folder source)
      // Determine source URL based on type + tier
      let sourceUrl;
      if (type === "load_balancer") {
        sourceUrl = "/source/load-balancer.js";
      } else {
        // User biasa hanya bisa free, admin bisa pilih prem
        const tierSelect = $("deployTier");
        if (tierSelect) {
          // Hide prem option for non-admin
          const premOpt = tierSelect.querySelector('option[value="prem"]');
          if (premOpt && currentUser?.role !== "admin") {
            premOpt.hidden = true;
            premOpt.disabled = true;
          }
          // Force free for non-admin
          const tier = currentDeployTier();
          sourceUrl = tier === "prem" ? "/source/vpn-worker-prem.js" : "/source/vpn-worker-free.js";
        } else {
          sourceUrl = "/source/vpn-worker-free.js";
        }
      }
        
      const codeRes = await fetch(sourceUrl);
      if (!codeRes.ok) throw new Error("Gagal mengambil source code worker dari server");
      const code = await codeRes.text();

      setMessage("deployMessage", "Mengirim instruksi deploy ke Cloudflare API...");

      const deployRes = await fetch("/api/cf", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          cfEmail,
          cfApiKey,
          accountId,
          scriptName: name,
          code,
          type,
          vars: {
            ...(uuidValue ? { UUID_ALLOWLIST: uuidValue } : {}),
            ...collectRelayVars(type),
          },
        })
      });

      const deployData = await deployRes.json();
      
      if (!deployRes.ok || !deployData.success) {
        throw new Error(deployData.error || "Deploy gagal: " + JSON.stringify(deployData.details));
      }

      const envNote = Array.isArray(deployData.env) && deployData.env.length
        ? ` · env terpasang: ${deployData.env.join(", ")}`
        : "";
      setMessage("deployMessage", "Deploy sukses! Menyimpan worker ke dashboard..." + envNote);

      // Pakai host dari API response (sudah include subdomain asli)
      const finalHost = deployData.host || `${name}.workers.dev`;

      state.workers.push({
        id: crypto.randomUUID(),
        name: name,
        host: finalHost,
        type,
        active: true,
        source: "cloudflare-auto",
        uuid: uuidValue || undefined,
      });

      await saveState();
      setMessage("deployMessage", `Deploy sukses! Worker: ${finalHost}`);
      setTimeout(() => location.href = "workers.html", 1500);

    } catch (error) {
      setMessage("deployMessage", error.message, true);
      $("startDeployBtn").disabled = false;
    }
  };
}
// Tier efektif untuk deploy ini: non-admin selalu Free (sama seperti pemilihan source).
function currentDeployTier() {
  const select = $("deployTier");
  return currentUser?.role === "admin" && select ? select.value : "free";
}

// Nilai relay UDP dari halaman Deploy. Hanya untuk worker VPN bertier Premium dan hanya
// dikirim kalau host relay diisi — kosong berarti tidak ada binding env.
function collectRelayVars(type) {
  if (type === "load_balancer") return {};
  if (currentDeployTier() !== "prem") return {};
  const host = $("relayHost")?.value.trim() || "";
  if (!host) return {};
  return {
    RELAY_SERVER_UDP: host,
    RELAY_SERVER_PORT: $("relayPort")?.value.trim() || "7300",
    RELAY_SERVER_TLS: $("relayTls")?.value || "",
    RELAY_SECRET: $("relaySecret")?.value.trim() || "",
  };
}

async function hashPassword(password) { 
  const bytes = new TextEncoder().encode(password); 
  const hash = await crypto.subtle.digest("SHA-256", bytes); 
  return [...new Uint8Array(hash)].map((item) => item.toString(16).padStart(2, "0")).join(""); 
}

// Endpoint auth di Pages Function (/api/login, /api/register) membatasi percobaan per IP dan
// menaikkan batasnya jadi global lewat Supabase. Kalau endpoint itu belum ada (deploy lama) atau
// menjawab 503 (RPC belum tersedia), panel jatuh ke jalur berikutnya: RPC langsung, lalu cara lama.
async function postJson(url, payload, timeoutMs) {
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(timeoutMs || 12000),
    });
    let data = null;
    try { data = await res.json(); } catch {}
    return { status: res.status, ok: res.ok, data };
  } catch {
    return null;
  }
}

function throttleMessage(data) {
  return (data && data.error) || "Terlalu banyak percobaan. Coba lagi nanti.";
}

// ---- Auth lewat RPC: sql/2026-11-14-auth-hardening.sql -------------------------------
// Setelah SQL itu dijalankan, kolom password_hash tidak lagi bisa dibaca dengan anon key dan
// tidak ada izin tulis mentah ke users_custom, jadi login/daftar/aksi admin lewat fungsi
// SECURITY DEFINER. Semua jalur memakai fallback ke cara lama saat fungsinya belum ada, supaya
// panel tetap bekerja sebelum maupun sesudah SQL dijalankan.
function rpcMissing(error) {
  if (!error) return false;
  const code = String(error.code || "");
  const message = String(error.message || "");
  return code === "PGRST202" || code === "404" || /could not find the function|does not exist/i.test(message);
}
function rpcErrorMessage(error) {
  return String((error && error.message) || "tidak diketahui");
}
// Sesi menyimpan hash sandi (bukan sandinya) karena aksi admin diverifikasi server dengan hash itu.
// Aksi admin diverifikasi server dengan hash sandi pelaku. Sesi lama (login sebelum SQL auth,
// atau sebelum login ulang) tidak membawa hash itu, jadi beri pesan yang jelas daripada error RPC
// mentah "Hanya admin yang boleh melakukan ini".
function adminActor() {
  if (!supabase) throw new Error("Supabase tidak terkoneksi.");
  if (!currentUser || !currentUser.hash) throw new Error("Sesi ini belum membawa verifikasi sandi — login ulang dulu.");
  return { p_actor: currentUser.username, p_actor_hash: currentUser.hash };
}

function saveSession(user, hash) {
  const session = { username: user.username, role: user.role || "user" };
  if (hash) session.hash = hash;
  localStorage.setItem(sessionKey, JSON.stringify(session));
  return session;
}

function renderAuth() {
  const tabLogin = $("tabLogin");
  const tabRegister = $("tabRegister");
  const paneLogin = $("paneLogin");
  const paneRegister = $("paneRegister");
  const loginMessage = $("loginMessage");
  const registerMessage = $("registerMessage");

  if (tabLogin && tabRegister) {
    const switchTab = (tab) => {
      const isLogin = tab === "login";
      tabLogin.classList.toggle("active", isLogin);
      tabLogin.setAttribute("aria-selected", String(isLogin));
      tabRegister.classList.toggle("active", !isLogin);
      tabRegister.setAttribute("aria-selected", String(!isLogin));
      paneLogin.hidden = !isLogin;
      paneRegister.hidden = isLogin;
      if (loginMessage) loginMessage.textContent = "";
      if (registerMessage) registerMessage.textContent = "";
    };
    tabLogin.onclick = () => switchTab("login");
    tabRegister.onclick = () => switchTab("register");
    if (location.hash === "#register") switchTab("register");
  }

  $("registerForm")?.addEventListener("submit", async (event) => { 
    event.preventDefault(); 
    const username = $("registerUsername").value.trim().toLowerCase();
    const password = $("registerPassword").value; 
    
    if (username.includes(" ")) return setMessage("registerMessage", "Username tidak boleh pakai spasi.", true);
    if (password !== $("registerConfirm").value) return setMessage("registerMessage", "Ulangi sandi harus sama.", true); 

    const passwordHash = await hashPassword(password);

    if (supabase) {
      // 1. Endpoint Function (dibatasi per IP; hanya boleh membuat role user di server).
      const endpoint = await postJson("/api/register", { username, password });
      if (endpoint && endpoint.ok && endpoint.data && endpoint.data.username) {
        saveSession({ username: endpoint.data.username, role: "user" }, passwordHash);
        location.href = "index.html";
        return;
      }
      if (endpoint && endpoint.status === 409) return setMessage("registerMessage", "Username sudah terdaftar.", true);
      if (endpoint && endpoint.status === 429) return setMessage("registerMessage", throttleMessage(endpoint.data), true);
      if (endpoint && endpoint.status === 400) return setMessage("registerMessage", (endpoint.data && endpoint.data.error) || "Data tidak valid.", true);

      // 2. RPC langsung (endpoint belum ada di deploy lama)
      const viaRpc = await supabase.rpc("register_user", { p_username: username, p_password: password });
      if (!viaRpc.error) {
        if (viaRpc.data === false) return setMessage("registerMessage", "Username sudah terdaftar.", true);
        saveSession({ username, role: "user" }, passwordHash);
        location.href = "index.html";
        return;
      }
      if (!rpcMissing(viaRpc.error)) return setMessage("registerMessage", "Gagal buat akun: " + rpcErrorMessage(viaRpc.error), true);

      // 3. Jalur lama (SQL auth belum dijalankan)
      const { data: existingUser, error: checkError } = await supabase.from('users_custom').select('username, role').eq('username', username).maybeSingle();
      if (checkError) return setMessage("registerMessage", "Error cek DB: " + checkError.message, true);
      if (existingUser) return setMessage("registerMessage", "Username sudah terdaftar.", true);
      const { error: insertError } = await supabase.from('users_custom').insert([{ username, password_hash: passwordHash }]).select("username, role");
      if (insertError) return setMessage("registerMessage", "Gagal buat akun: " + insertError.message, true);

      saveSession({ username, role: "user" }, passwordHash);
      location.href = "index.html";
      return;
    }

    // Fallback Lokal
    const allUsers = readJson(usersKey, []); 
    if (allUsers.some((user) => user.username === username)) return setMessage("registerMessage", "Username sudah dipakai.", true); 
    allUsers.push({ username, passwordHash, role: "user" }); 
    localStorage.setItem(usersKey, JSON.stringify(allUsers)); 
    localStorage.setItem(sessionKey, JSON.stringify({ username, role: "user" })); 
    location.href = "index.html"; 
  });

  $("loginForm")?.addEventListener("submit", async (event) => { 
    event.preventDefault(); 
    const username = $("loginUsername").value.trim().toLowerCase(); 
    const password = $("loginPassword").value;
    const passwordHash = await hashPassword(password);

    if (supabase) {
      // 1. Endpoint Function: dibatasi per IP + global, dan server yang membandingkan hash.
      const endpoint = await postJson("/api/login", { username, password });
      if (endpoint && endpoint.ok && endpoint.data && endpoint.data.username) {
        saveSession({ username: endpoint.data.username, role: endpoint.data.role || "user" }, passwordHash);
        location.href = "index.html";
        return;
      }
      if (endpoint && endpoint.status === 401) return setMessage("loginMessage", "Username atau sandi salah.", true);
      if (endpoint && endpoint.status === 429) return setMessage("loginMessage", throttleMessage(endpoint.data), true);

      // 2. RPC langsung (endpoint belum ada di deploy lama)
      const viaRpc = await supabase.rpc("verify_login", { p_username: username, p_password: password });
      if (!viaRpc.error) {
        const row = Array.isArray(viaRpc.data) ? viaRpc.data[0] : viaRpc.data;
        if (!row || !row.username) return setMessage("loginMessage", "Username atau sandi salah.", true);
        saveSession({ username: row.username, role: row.role || "user" }, passwordHash);
        location.href = "index.html";
        return;
      }
      if (!rpcMissing(viaRpc.error)) return setMessage("loginMessage", "Error DB: " + rpcErrorMessage(viaRpc.error), true);

      // 3. Jalur lama (SQL auth belum dijalankan)
      const { data: user, error } = await supabase.from('users_custom')
        .select('username, role')
        .eq('username', username)
        .eq('password_hash', passwordHash)
        .maybeSingle();
      if (error) return setMessage("loginMessage", "Error DB: " + error.message, true);
      if (!user) return setMessage("loginMessage", "Username atau sandi salah.", true);
      saveSession({ username: user.username, role: user.role || "user" }, passwordHash);
      location.href = "index.html";
      return;
    }

    // Fallback Lokal
    const user = readJson(usersKey, []).find((item) => item.username === username); 
    if (!user || user.passwordHash !== passwordHash) return setMessage("loginMessage", "Username atau sandi salah.", true); 
    localStorage.setItem(sessionKey, JSON.stringify({ username, role: user.role || "user" })); 
    location.href = "index.html"; 
  });
}

function readJson(key, fallback) { try { return JSON.parse(localStorage.getItem(key)) ?? fallback; } catch { return fallback; } }


function renderAdmin() {
  if (!document.getElementById("addAdminForm")) return;

  let userFilter = "all";
  let allUserData = [];

  const loadStats = async () => {
    if (!supabase) return;
    try {
      const { count: total } = await supabase.from("users_custom").select("username", { count: "exact", head: true });
      document.getElementById("statTotalUsers").textContent = total ?? 0;
      const { count: admins } = await supabase.from("users_custom").select("username", { count: "exact", head: true }).eq("role", "admin");
      document.getElementById("statAdmins").textContent = admins ?? 0;
      const { count: regular } = await supabase.from("users_custom").select("username", { count: "exact", head: true }).eq("role", "user");
      document.getElementById("statRegularUsers").textContent = regular ?? 0;
    } catch {}
  };
  loadStats();

  const loadUsers = async () => {
    if (!supabase) return setMessage("userMessage", "Supabase tidak terkoneksi.", true);
    setMessage("userMessage", "Memuat...");
    try {
      const { data, error } = await supabase.from("users_custom").select("username, role");
      if (error) throw error;
      allUserData = data || [];
      let users = allUserData;
      if (userFilter === "admin") users = users.filter(u => u.role === "admin");
      const tbody = document.getElementById("userTableBody");
      tbody.innerHTML = users.map(u => {
        const isAdmin = u.role === "admin";
        const isSelf = u.username === currentUser?.username;
        const toggleBtn = isSelf ? '<span style="color:var(--muted);font-size:.75rem">Anda</span>' : `<button class="icon-button" data-toggle-role="${escapeHtml(u.username)}" data-current="${isAdmin ? "admin" : "user"}" type="button">${isAdmin ? "↓ User" : "↑ Admin"}</button>`;
        const delBtn = isSelf ? "" : `<button class="icon-button danger" data-delete-user="${escapeHtml(u.username)}" type="button" style="margin-left:4px">Hapus</button>`;
        return `<tr><td><code>${escapeHtml(u.username)}</code></td><td>${isAdmin ? '<span class="proxy-status live">admin</span>' : '<span class="proxy-status dead">user</span>'}</td><td>${toggleBtn}${delBtn}</td></tr>`;
      }).join("");
      setMessage("userMessage", `${users.length} user.`);
    } catch (e) {
      setMessage("userMessage", "Error: " + e.message, true);
    }
  };
  loadUsers();

  document.getElementById("tabUsersBtn").onclick = () => { userFilter = "all"; updateUTabs(); loadUsers(); };
  document.getElementById("tabAdminsBtn").onclick = () => { userFilter = "admin"; updateUTabs(); loadUsers(); };
  const updateUTabs = () => {
    document.getElementById("tabUsersBtn").classList.toggle("active", userFilter === "all");
    document.getElementById("tabAdminsBtn").classList.toggle("active", userFilter === "admin");
  };

  // Toggle role
  document.getElementById("userTableBody").onclick = async (e) => {
    const toggleBtn = e.target.closest("[data-toggle-role]");
    if (toggleBtn) {
      const username = toggleBtn.dataset.toggleRole;
      const current = toggleBtn.dataset.current;
      const newRole = current === "admin" ? "user" : "admin";
      if (!confirm(`Ubah ${username} → ${newRole}?`)) return;
      toggleBtn.disabled = true;
      try {
        const viaRpc = await supabase.rpc("admin_action", {
          ...adminActor(),
          p_action: "set_role", p_target: username, p_role: newRole,
        });
        if (viaRpc.error) {
          if (!rpcMissing(viaRpc.error)) throw viaRpc.error;
          const { error } = await supabase.from("users_custom").update({ role: newRole }).eq("username", username);
          if (error) throw error;
        }
        setMessage("userMessage", `${username} → ${newRole}.`);
        loadUsers();
        loadStats();
      } catch (err) {
        setMessage("userMessage", "Gagal: " + err.message, true);
        toggleBtn.disabled = false;
      }
      return;
    }
    const delBtn = e.target.closest("[data-delete-user]");
    if (delBtn) {
      const username = delBtn.dataset.deleteUser;
      if (!confirm(`Hapus user ${username} permanen?`)) return;
      delBtn.disabled = true;
      try {
        const viaRpc = await supabase.rpc("admin_action", {
          ...adminActor(),
          p_action: "delete", p_target: username,
        });
        if (viaRpc.error) {
          if (!rpcMissing(viaRpc.error)) throw viaRpc.error;
          const { error } = await supabase.from("users_custom").delete().eq("username", username);
          if (error) throw error;
        }
        setMessage("userMessage", `${username} dihapus.`);
        loadUsers();
        loadStats();
      } catch (err) {
        setMessage("userMessage", "Gagal: " + err.message, true);
        delBtn.disabled = false;
      }
    }
  };

  // Add admin
  document.getElementById("addAdminForm").onsubmit = async (e) => {
    e.preventDefault();
    const username = document.getElementById("newAdminUsername").value.trim().toLowerCase();
    const password = document.getElementById("newAdminPassword").value;
    if (username.includes(" ")) return setMessage("addAdminMessage", "Username tidak boleh spasi.", true);
    if (password.length < 6) return setMessage("addAdminMessage", "Sandi minimal 6 karakter.", true);
    const btn = document.getElementById("addAdminBtn");
    btn.disabled = true;
    btn.textContent = "Menyimpan...";
    try {
      const viaRpc = await supabase.rpc("admin_action", {
        ...adminActor(),
        p_action: "create", p_target: username, p_role: "admin", p_password: password,
      });
      if (!viaRpc.error && viaRpc.data === false) { setMessage("addAdminMessage", "Username sudah ada.", true); return; }
      if (viaRpc.error) {
        if (!rpcMissing(viaRpc.error)) throw viaRpc.error;
        const passwordHash = await hashPassword(password);
        const { data: existing } = await supabase.from("users_custom").select("username").eq("username", username).maybeSingle();
        if (existing) { setMessage("addAdminMessage", "Username sudah ada.", true); return; }
        const { error } = await supabase.from("users_custom").insert([{ username, password_hash: passwordHash, role: "admin" }]).select("username, role");
        if (error) throw error;
      }
      setMessage("addAdminMessage", `Admin ${username} dibuat.`);
      document.getElementById("newAdminUsername").value = "";
      document.getElementById("newAdminPassword").value = "";
      loadUsers();
      loadStats();
    } catch (err) {
      setMessage("addAdminMessage", "Gagal: " + err.message, true);
    } finally {
      btn.disabled = false;
      btn.textContent = "Tambah Admin";
    }
  };
}


async function init() {
  const authOk = await checkAuth();
  if (authOk) {
    await loadState();
    renderNav();
    renderAuth();
    if (currentUser) {
      renderDashboard();
      renderWorkers();
      renderGenerator();
      renderDeploy();
      renderProxyManager();
      renderAdmin();
    }
  }
}

init();




// Ganti proxy manager script yg lama jadi logic Supabase
function renderProxyManager() {
  if (!document.getElementById('dbProxyForm')) return;

  let currentList = [];
  let viewMode = 'live';

  const CACHE_KEY = "proxyListCache";
  const CACHE_TTL = 6 * 60 * 60 * 1000;

  const fmtDate = (ts) => {
    if (!ts) return '—';
    const d = new Date(ts);
    const pad = n => String(n).padStart(2, '0');
    return `${pad(d.getDate())}/${pad(d.getMonth()+1)} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
  };

  const renderTable = () => {
    const list = currentList.filter(p => viewMode === 'live' ? p.is_active : !p.is_active);
    const tbody = document.getElementById('proxyTableBody');
    const empty = document.getElementById('proxyEmpty');
    document.getElementById('dbCount').textContent = list.length;

    if (!list.length) {
      tbody.innerHTML = '';
      empty.hidden = false;
      empty.textContent = viewMode === 'live' ? 'Belum ada proxy aktif.' : 'Tidak ada proxy mati.';
      return;
    }
    empty.hidden = true;
    tbody.innerHTML = list.map(p => {
      const flag = p.country ? getFlagEmoji(p.country) : '🏳';
      const status = p.is_active ? '<span class="proxy-status live">Aktif</span>' : '<span class="proxy-status dead">Mati</span>';
      return `<tr><td><code>${escapeHtml(p.ip)}:${escapeHtml(p.port)}</code></td><td>${flag} ${escapeHtml(p.country || '—')}</td><td>${escapeHtml(p.org || '—')}</td><td>${status}</td><td>${fmtDate(p.last_checked)}</td></tr>`;
    }).join('');
  };

  const loadProxies = async (force = false) => {
    setMessage('dbProxyMessage', 'Memuat proxy...');
    // Cek cache dulu
    if (!force) {
      try {
        const cached = JSON.parse(localStorage.getItem(CACHE_KEY) || 'null');
        if (cached && (Date.now() - cached.ts) < CACHE_TTL) {
          currentList = cached.data;
          renderTable();
          setMessage('dbProxyMessage', `${currentList.length} proxy (cached).`);
          return;
        }
      } catch {}
    }
    // Fetch fresh
    if (!supabase) { setMessage('dbProxyMessage', 'Supabase tidak terkoneksi.', true); return; }
    try {
      const { data, error } = await supabase.from('proxy_pool').select('*').order('last_checked', { ascending: false });
      if (error) throw error;
      currentList = data || [];
      renderTable();
      localStorage.setItem(CACHE_KEY, JSON.stringify({ data: currentList, ts: Date.now() }));
      setMessage('dbProxyMessage', `${currentList.length} proxy dimuat.`);
    } catch (e) {
      setMessage('dbProxyMessage', 'Error: ' + e.message, true);
    }
  };

  loadProxies();

  document.getElementById('tabLiveBtn').onclick = () => { viewMode = 'live'; updateTabs(); renderTable(); };
  document.getElementById('tabDeadBtn').onclick = () => { viewMode = 'dead'; updateTabs(); renderTable(); };
  const updateTabs = () => {
    document.getElementById('tabLiveBtn').classList.toggle('active', viewMode === 'live');
    document.getElementById('tabDeadBtn').classList.toggle('active', viewMode === 'dead');
  };

  document.getElementById('copyDbProxyBtn').onclick = async () => {
    const list = currentList.filter(p => viewMode === 'live' ? p.is_active : !p.is_active);
    const txt = list.map(p => p.ip + ':' + p.port).join('\n');
    await navigator.clipboard.writeText(txt);
    setMessage('dbProxyMessage', `${list.length} IP disalin!`);
  };

  document.getElementById('dbProxyForm').onsubmit = async (e) => {
    e.preventDefault();
    if (!supabase) return setMessage('dbProxyMessage', 'Supabase tidak terkoneksi.', true);

    const rawList = document.getElementById('dbProxyInput').value.split(/[\n,]+/).map(i => i.trim()).filter(Boolean);
    if (!rawList.length) return;

    const btn = document.getElementById('addProxyBtn');
    btn.disabled = true;
    btn.textContent = 'Mengecek...';
    setMessage('dbProxyMessage', `Mengecek ${rawList.length} proxy...`);

    const live = [];
    const dead = [];

    for (let i = 0; i < rawList.length; i++) {
      const item = rawList[i];
      let host = item, port = '443';
      if (item.includes(':')) {
        const parts = item.split(':');
        host = parts[0];
        port = parts[1] || '443';
      }
      btn.textContent = `Cek ${i+1}/${rawList.length}...`;
      try {
        const res = await fetch(`https://id1.foolvpn.web.id/api/v1/check?ip=${host}:${port}`, { signal: AbortSignal.timeout(5000) });
        const data = res.ok ? await res.json().catch(() => null) : null;
        if (data && data.tcp_port_open) {
          live.push({ ip: host, port, is_active: true, country: data.country_code || '??', org: data.isp || 'Unknown' });
        } else {
          dead.push(`${host}:${port}`);
        }
      } catch {
        dead.push(`${host}:${port}`);
      }
    }

    if (live.length) {
      const { error } = await supabase.from('proxy_pool').insert(live);
      if (error) {
        setMessage('dbProxyMessage', `Gagal simpan: ${error.message}`, true);
        btn.disabled = false;
        btn.textContent = 'Cek & Tambah';
        return;
      }
    }

    btn.disabled = false;
    btn.textContent = 'Cek & Tambah';
    document.getElementById('dbProxyInput').value = '';

    let msg = `${live.length} proxy aktif ditambahkan.`;
    if (dead.length) msg += ` ${dead.length} mati dilewati: ${dead.slice(0, 5).join(', ')}${dead.length > 5 ? '...' : ''}`;
    setMessage('dbProxyMessage', msg);

    localStorage.removeItem(CACHE_KEY);
    loadProxies(true);
  };
}


