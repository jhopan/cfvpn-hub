// Katalog sumber daftar proxy. Semua diambil dengan parser generik: cari pola ip:port di
// seluruh isi (teks, JSON dengan field ip/port terpisah, atau tabel HTML) — tanpa parser
// khusus per situs. Verifikasi keberadaan/format tiap sumber:
//
//   nrun node proxy-scraper/sources-check.mjs
//
// kind hanya keterangan: txt = daftar mentah, json = API JSON, html = halaman tabel.
export const SOURCES = [
  // --- GitHub mentah (paling stabil, sering di-update) ---
  { name: "proxifly-all", kind: "json", url: "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.json" },
  { name: "proxifly-socks5", kind: "json", url: "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.json" },
  { name: "proxifly-http", kind: "json", url: "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.json" },
  { name: "monosans-socks5", kind: "txt", url: "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt" },
  { name: "monosans-socks4", kind: "txt", url: "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt" },
  { name: "monosans-http", kind: "txt", url: "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt" },
  { name: "thespeedx-socks5", kind: "txt", url: "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt" },
  { name: "thespeedx-socks4", kind: "txt", url: "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt" },
  { name: "thespeedx-http", kind: "txt", url: "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt" },
  { name: "hookzof-socks5", kind: "txt", url: "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt" },
  { name: "shiftytr-socks5", kind: "txt", url: "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt" },
  { name: "shiftytr-socks4", kind: "txt", url: "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt" },
  { name: "shiftytr-http", kind: "txt", url: "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt" },
  { name: "shiftytr-https", kind: "txt", url: "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt" },
  { name: "clarketm", kind: "txt", url: "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt" },
  { name: "jetkai-socks5", kind: "txt", url: "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt" },
  { name: "jetkai-socks4", kind: "txt", url: "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt" },
  { name: "jetkai-http", kind: "txt", url: "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt" },
  { name: "jetkai-https", kind: "txt", url: "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt" },
  { name: "roosterkid-socks5", kind: "txt", url: "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt" },
  { name: "roosterkid-socks4", kind: "txt", url: "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt" },
  { name: "roosterkid-https", kind: "txt", url: "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt" },
  { name: "ercin-socks5", kind: "txt", url: "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks5.txt" },
  { name: "ercin-http", kind: "txt", url: "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/http.txt" },
  { name: "aliilapro-socks5", kind: "txt", url: "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks5.txt" },
  { name: "aliilapro-http", kind: "txt", url: "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt" },
  { name: "murongpig-socks5", kind: "txt", url: "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/socks5.txt" },
  { name: "murongpig-http", kind: "txt", url: "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt" },
  { name: "vakhov-socks5", kind: "txt", url: "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks5.txt" },
  { name: "vakhov-https", kind: "txt", url: "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/https.txt" },
  { name: "kangproxy-socks5", kind: "txt", url: "https://raw.githubusercontent.com/officialputuid/KangProxy/main/socks5/socks5.txt" },
  { name: "kangproxy-http", kind: "txt", url: "https://raw.githubusercontent.com/officialputuid/KangProxy/main/http/http.txt" },
  { name: "prxchk-socks5", kind: "txt", url: "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt" },
  { name: "prxchk-http", kind: "txt", url: "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt" },
  { name: "mmpx12-socks5", kind: "txt", url: "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt" },
  { name: "mmpx12-http", kind: "txt", url: "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt" },
  { name: "hideip-socks5", kind: "txt", url: "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks5.txt" },
  { name: "hideip-http", kind: "txt", url: "https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt" },
  { name: "freeproxies-socks5", kind: "txt", url: "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/socks5_proxies.txt" },
  { name: "freeproxies-http", kind: "txt", url: "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/http_proxies.txt" },

  // --- API teks/JSON ---
  { name: "proxyscrape-v4-socks5", kind: "api", url: "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=socks5&format=text" },
  { name: "proxyscrape-v4-socks4", kind: "api", url: "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=socks4&format=text" },
  { name: "proxyscrape-v4-http", kind: "api", url: "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=http&format=text" },
  { name: "proxy-list-download-socks5", kind: "api", optional: true, url: "https://www.proxy-list.download/api/v1/get?type=socks5" },
  { name: "proxy-list-download-socks4", kind: "api", optional: true, url: "https://www.proxy-list.download/api/v1/get?type=socks4" },
  { name: "proxy-list-download-http", kind: "api", optional: true, url: "https://www.proxy-list.download/api/v1/get?type=http" },
  { name: "geonode", kind: "api", url: "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=socks5,http" },
  { name: "spys-me-proxy", kind: "txt", url: "https://spys.me/proxy.txt" },
  { name: "spys-me-socks", kind: "txt", url: "https://spys.me/socks.txt" },
  { name: "proxyspace-socks5", kind: "txt", url: "https://proxyspace.pro/socks5.txt" },
  { name: "proxyspace-http", kind: "txt", url: "https://proxyspace.pro/http.txt" },

  // --- Halaman tabel HTML (parser generik tetap bisa) ---
  { name: "free-proxy-list-net", kind: "html", url: "https://free-proxy-list.net/" },
  { name: "sslproxies-org", kind: "html", url: "https://www.sslproxies.org/" },
  { name: "socks-proxy-net", kind: "html", url: "https://www.socks-proxy.net/" },
  { name: "us-proxy-org", kind: "html", url: "https://www.us-proxy.org/" },
];

const IP_PORT = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,5})/g;

const RESERVED = [
  /^10\./, /^127\./, /^0\./, /^169\.254\./, /^192\.168\./, /^100\.(6[4-9]|[7-9]\d|1[0-2]\d)\./,
  /^172\.(1[6-9]|2\d|3[01])\./, /^22[4-9]\./, /^23\d\./, /^24\d\./, /^25[0-5]\./,
];

export function isPublicIp(ip) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return false;
  return !RESERVED.some((re) => re.test(ip));
}

export function extractProxies(text) {
  const out = new Set();
  const add = (ip, port) => {
    if (!Number.isInteger(port) || port < 1 || port > 65535) return;
    if (!isPublicIp(ip)) return;
    out.add(`${ip}:${port}`);
  };

  // format teks / "proxy": "ip:port"
  for (const m of text.matchAll(IP_PORT)) add(m[1], Number(m[2]));

  // JSON yang memisah field ip dan port (geonode, proxifly). Sebagian API membungkus JSON
  // sebagai string sehingga field-nya ter-escape (\"ip\":\"...\") — normalkan dulu.
  const normalized = text.includes('\\"') ? text.replace(/\\"/g, '"') : text;
  for (const m of normalized.matchAll(/"ip"\s*:\s*"(\d{1,3}(?:\.\d{1,3}){3})"[^{}]{0,400}?"port"\s*:\s*"?(\d{1,5})"?/g)) add(m[1], Number(m[2]));
  for (const m of normalized.matchAll(/"port"\s*:\s*"?(\d{1,5})"?[^{}]{0,400}?"ip"\s*:\s*"(\d{1,3}(?:\.\d{1,3}){3})"/g)) add(m[2], Number(m[1]));

  return out;
}
