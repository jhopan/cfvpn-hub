#!/usr/bin/env python3
"""Cari proxy yang benar-benar tembus dari worker VLESS ter-deploy (TCP lewat proxy).

Pakai:
    python tests/prod-proxy-check.py <host-worker> ip:port [ip:port ...]
    python tests/prod-proxy-check.py <host-worker> --jobs 8 --file kandidat.txt --json hasil.json

Untuk setiap kandidat: buka WS ke `/<ip>-<port>` (format panel), kirim frame VLESS cmd=1
target example.com:80, kirim HTTP GET, lalu cek muncul "HTTP/1." — artinya worker
berhasil membuat tunnel SOCKS5/HTTP CONNECT ke proxy itu.
"""
import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, __file__.rsplit("\\", 1)[0] if "\\" in __file__ else __file__.rsplit("/", 1)[0])
from vless_ws import Ws, vless_frame  # noqa: E402

REQUEST = b"GET / HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n"


def check(host, prx, timeout=8.0):
    # VLESS_PATH menimpa path per-kandidat: dipakai untuk menguji selector worker (/ID, /ALL)
    # yang memilih proxy sendiri, bukan proxy yang tertulis di path.
    path = os.environ.get("VLESS_PATH") or f"/{prx.replace(':', '-')}"
    started = time.time()
    ws = None
    try:
        ws = Ws(host, path, timeout=timeout)
        ws.send(vless_frame(1, 80, REQUEST, host=b"example.com"))
        frames, closed = ws.collect(lambda body: b"HTTP/1." in body, deadline=timeout + 4)
        body = b"".join(frames)
        ms = int((time.time() - started) * 1000)
        if len(body) < 3:
            return {"proxy": prx, "ok": False, "ms": ms, "detail": f"tanpa data (closed={closed})"}
        if body[:2] != b"\x00\x00":
            return {"proxy": prx, "ok": False, "ms": ms, "detail": f"header VLESS salah: {body[:2].hex()}"}
        ok = b"HTTP/1." in body[2:]
        first = body[2:].split(b"\r\n", 1)[0][:40].decode(errors="replace")
        return {"proxy": prx, "ok": ok, "ms": ms, "detail": first if ok else f"bukan HTTP ({body[2:18].hex()})"}
    except Exception as exc:  # noqa: BLE001
        return {"proxy": prx, "ok": False, "ms": int((time.time() - started) * 1000), "detail": f"exception: {exc}"}
    finally:
        if ws:
            ws.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("targets", nargs="*")
    ap.add_argument("--jobs", "-j", type=int, default=6)
    ap.add_argument("--file", "-f", help="file berisi ip:port per baris")
    ap.add_argument("--json", help="tulis hasil lengkap ke file JSON")
    ap.add_argument("--timeout", type=float, default=8.0)
    args = ap.parse_args()

    targets = list(args.targets)
    if args.file:
        targets += [l.strip() for l in open(args.file, encoding="utf-8") if l.strip()]
    seen, uniq = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    if not uniq:
        print("butuh daftar ip:port")
        return 2

    print(f"worker: {args.host}\nkandidat: {len(uniq)}  thread: {args.jobs}\n", flush=True)
    passed, failed = [], []
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        for res in pool.map(lambda p: check(args.host, p, args.timeout), uniq):
            (passed if res["ok"] else failed).append(res)
            print(f"[{'PASS' if res['ok'] else 'FAIL'}] {res['proxy']:<24} {res['ms']:>6} ms  {res['detail']}", flush=True)

    passed.sort(key=lambda r: r["ms"])
    print(f"\nHIDUP {len(passed)} / {len(uniq)}")
    for r in passed:
        print(f"   {r['proxy']:<24} {r['ms']:>6} ms")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"host": args.host, "checked": len(uniq), "alive": passed, "dead": failed}, fh, indent=2)
        print(f"hasil lengkap: {args.json}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
