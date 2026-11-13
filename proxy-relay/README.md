# UDP Relay — CFVPN Hub

Worker Cloudflare **tidak punya UDP keluar**, jadi datagram UDP non-DNS (QUIC/HTTP3,
WireGuard, game, NTP, …) diteruskan worker ke proses ini lewat TCP; proses inilah yang
benar-benar mengirim UDP ke tujuan. DNS **tidak** lewat sini (worker menjawabnya sendiri
lewat DoH, lebih cepat).

## Kenapa perlu relay sendiri

Versi lama template premium memakai relay pihak lain (`relay-server-production-*.up.railway.app`,
dan `udp-relay.hobihaus.space:7300` di template free). Keduanya sudah mati, dan relay
tanpa autentikasi juga berbahaya (bisa dipakai orang untuk refleksi/amplifikasi UDP).
Relay ini wajib memakai `RELAY_SECRET`.

## Menjalankan

```bash
# butuh Node >= 18, tanpa dependensi
RELAY_SECRET="rahasia-panjang-minimal-32-karakter" \
RELAY_PORT=7300 \
node proxy-relay/udp-relay.mjs
```

Opsi lain (env):

| Env | Arti | Bawaan |
|---|---|---|
| `RELAY_HOST` | alamat listen | `0.0.0.0` |
| `RELAY_PORT` | port listen | `7300` |
| `RELAY_SECRET` | **wajib**; dipakai worker saat menyambung | — |
| `RELAY_IDLE_MS` | tutup sesi yang tidak ada trafik | `60000` |
| `RELAY_MAX_DATAGRAM` | batas ukuran datagram | `8192` |
| `RELAY_TLS=1` + `RELAY_CERT`/`RELAY_KEY` | bungkus TCP dengan TLS (mis. Cloudflare `RELAY_SERVER_TLS=1` + port 443) | mati |

Contoh unit systemd (`/etc/systemd/system/cfvpn-udp-relay.service`):

```ini
[Unit]
Description=CFVPN Hub UDP relay
After=network-online.target
Wants=network-online.target

[Service]
Environment=RELAY_SECRET=ganti-dengan-rahasia-panjang
Environment=RELAY_PORT=7300
ExecStart=/usr/bin/node /opt/cfvpn/proxy-relay/udp-relay.mjs
Restart=always
RestartSec=3
User=nobody

[Install]
WantedBy=multi-user.target
```

## Memakai relay dari worker

Set env pada worker VPN (binding `plain_text`):

| Binding | Contoh | Arti |
|---|---|---|
| `RELAY_SERVER_UDP` | `relay.domainmu.com` | host relay (kosong = UDP non-DNS ditutup cepat seperti sebelumnya) |
| `RELAY_SERVER_PORT` | `7300` | port relay |
| `RELAY_SERVER_TLS` | `1` | relay memakai TLS |
| `RELAY_SECRET` | `rahasia-yang-sama` | harus sama dengan `RELAY_SECRET` relay |

Catatan: panel (halaman Deploy) saat ini hanya mengunggah kode, **tidak** mengirim binding
env — jadi untuk produksi ada dua pilihan: (a) tambahkan dukungan binding di
`functions/api/cf.js` + form Deploy, atau (b) relay dijalankan di port standar dan host
relay ditulis di template. Selama env belum diisi, perilaku worker tidak berubah.

## Protokol (TCP, satu koneksi = satu sesi UDP ke satu tujuan)

```
klien -> relay : "udp <alamat> <port> <rahasia>\n"
dua arah      : [2B panjang BE][payload]
```

Balasan dari tujuan dikirim balik dengan framing yang sama; koneksi ditutup saat klien
menutup, saat idle melewati `RELAY_IDLE_MS`, atau saat rahasia salah.

## Batas & biaya yang perlu diketahui

- **Satu hop tambahan**: latensi naik sekitar RTT worker→relay.
- **UDP di atas TCP**: untuk QUIC kinerjanya turun (TCP menganggap kehilangan paket sebagai
  kongesti, sedangkan QUIC tidak) — protokol UDP kecil (DNS, NTP, game ringan) jauh lebih
  enak daripada streaming QUIC berat.
- **DNS tetap di DoH** di worker; jangan arahkan port 53 ke relay.
- Relay harus punya **IP publik dengan UDP** (VPS). Port UDP keluar tidak diblokir.
- Ukuran datagram dibatasi (relay 8 KB, worker 8 KB); datagram lebih besar dibuang.
