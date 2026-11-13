# UDP Relay (salinan untuk uji)

Berkas `udp-relay.mjs` di direktori ini adalah **salinan** dari repo
[`Pan-VlessRelay`](../../Pan-VlessRelay) — sumber deploy + Docker + dokumentasi operasional
ada di sana. Salinan di sini dipakai oleh `tests/smoke-vpn-worker.mjs`, yang menjalankan relay
ini sebagai subprocess lalu membuktikan jalur `worker → relay → UDP → balik sebagai datagram
VLESS`.

**Aturan:** kedua berkas harus identik. Setelah mengubah salah satu:

```bash
sha256sum cfvpn-hub/proxy-relay/udp-relay.mjs Pan-VlessRelay/relay/udp-relay.mjs   # harus sama
```

Kalau protokolnya berubah (`RELAY_PROTOCOL` naik), sisi worker di template juga wajib berubah
(`udpRelayEnsure` / `udpRelayPipe` / `splitUdpDatagrams`) dan uji smoke harus diperbarui.

## Ringkas

- Worker Cloudflare tidak punya UDP keluar → datagram UDP non-DNS diteruskan ke relay ini
  lewat TCP, relay yang mengirim UDP nyata. DNS **tidak** lewat relay (worker menjawabnya
  sendiri lewat DoH).
- Protokol v1: `udp <alamat> <port> <rahasia>\n` lalu `[2B panjang][payload]` dua arah;
  `health <rahasia>` dijawab `OK` (dipakai healthcheck).
- Env worker: `RELAY_SERVER_UDP`, `RELAY_SERVER_PORT`, `RELAY_SERVER_TLS`, `RELAY_SECRET`.
  Tanpa itu, perilaku worker tidak berubah (UDP non-DNS ditutup cepat).
- `RELAY_SECRET` wajib — relay terbuka = alat refleksi UDP.

Detail lengkap (Docker, TLS, systemd, batas QUIC-di-atas-TCP): lihat `README.md` dan
`AGENTS.md` di repo `Pan-VlessRelay`.
