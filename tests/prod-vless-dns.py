#!/usr/bin/env python3
"""Uji produksi worker VLESS (WS): jalur DNS via DoH.

Pakai:
    python tests/prod-vless-dns.py [host] [path]

Klien WS-nya ada di tests/vless_ws.py. Skenario:
  1. DNS framing Xray  [2B panjang][query]  -> balasan 00 00 + [2B panjang][jawaban]
  2. DNS framing polos (tanpa panjang)      -> balasan 00 00 + jawaban polos
  3. header VLESS terpecah dua pesan WS
  4. dua datagram DNS dalam satu pesan WS   -> dua balasan
  5. UDP port non-53                        -> koneksi ditutup cepat
"""
import json
import struct
import sys
import urllib.request

sys.path.insert(0, __file__.rsplit("\\", 1)[0] if "\\" in __file__ else __file__.rsplit("/", 1)[0])
from vless_ws import UA, Ws, dns_query, parse_dns, prefixed, vless_frame  # noqa: E402

HOST = sys.argv[1] if len(sys.argv) > 1 else "vpn-worker-prem.adelia140845.workers.dev"
PATH = sys.argv[2] if len(sys.argv) > 2 else "/1.2.3.4:5678"

results = []


def record(name, ok, detail):
    results.append((name, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}\n    {detail}", flush=True)


def datagram_counter(mode):
    def enough(body):
        if body[:2] != b"\x00\x00":
            return False
        rest = body[2:]
        if mode == "raw":
            return len(rest) >= 45
        want = 2 if mode == "two" else 1
        count = 0
        while len(rest) >= 2:
            n = struct.unpack(">H", rest[:2])[0]
            if len(rest) < 2 + n:
                break
            count += 1
            rest = rest[2 + n:]
        return count >= want

    return enough


def scenario(mode):
    q1 = dns_query(0x1111, "example.com")
    q2 = dns_query(0x2222, "example.org")
    payload = q1 if mode == "raw" else (prefixed(q1) + prefixed(q2) if mode == "two" else prefixed(q1))
    frame = vless_frame(2, 53, payload)

    ws = Ws(HOST, PATH)
    if mode == "split":
        ws.send(frame[:8])
        ws.collect(lambda body: True, deadline=0.4)
        ws.send(frame[8:])
    else:
        ws.send(frame)
    frames, closed = ws.collect(datagram_counter(mode), deadline=8.0)
    ws.close()

    body = b"".join(frames)
    ok = body[:2] == b"\x00\x00"
    detail = f"status={ws.status} frame={len(frames)} byte={len(body)} header={body[:2].hex()} closed={closed}"
    if ok and mode == "raw":
        dns = parse_dns(body[2:])
        ok = bool(dns.get("ok")) and dns.get("txid") == 0x1111 and dns.get("answers")
        detail += f" txid={hex(dns.get('txid', 0))} ancount={dns.get('ancount')} A={dns.get('answers')}"
    elif ok:
        rest = body[2:]
        parsed = []
        while len(rest) >= 2:
            n = struct.unpack(">H", rest[:2])[0]
            if len(rest) < 2 + n:
                break
            parsed.append(parse_dns(rest[2:2 + n]))
            rest = rest[2 + n:]
        txids = [p.get("txid") for p in parsed]
        expected = [0x1111, 0x2222] if mode == "two" else [0x1111]
        ok = ok and txids == expected and all(p.get("answers") for p in parsed)
        detail += f" txids={[hex(t) for t in txids]} A={[p.get('answers') for p in parsed]}"
    names = {
        "prefixed": "DNS framing Xray (2B panjang)",
        "raw": "DNS framing polos",
        "split": "header VLESS terpecah 2 pesan WS",
        "two": "dua datagram DNS satu pesan WS",
    }
    record(f"WS/VLESS {names[mode]}", ok, detail)


def scenario_udp_other():
    ws = Ws(HOST, PATH)
    ws.send(vless_frame(2, 4444, b"\x01\x02\x03\x04"))
    _, closed = ws.collect(lambda body: False, deadline=5.0)
    ws.close()
    record("UDP non-53 ditutup cepat", closed, f"closed={closed}")


def main():
    print(f"target: wss://{HOST}{PATH}\n", flush=True)
    try:
        req = urllib.request.Request(f"https://{HOST}/health", headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=15) as r:
            record("HTTP /health", r.status == 200, f"status={r.status} body={json.loads(r.read().decode())}")
    except Exception as exc:  # noqa: BLE001
        record("HTTP /health", False, f"error: {exc}")
    for mode in ("prefixed", "raw", "split", "two"):
        try:
            scenario(mode)
        except Exception as exc:  # noqa: BLE001
            record(f"WS/VLESS {mode}", False, f"exception: {exc}")
    try:
        scenario_udp_other()
    except Exception as exc:  # noqa: BLE001
        record("UDP non-53 ditutup cepat", False, f"exception: {exc}")

    failed = [r for r in results if not r[1]]
    print("\n" + (f"SEMUA {len(results)} SKENARIO PASS" if not failed else f"{len(failed)} dari {len(results)} GAGAL"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
