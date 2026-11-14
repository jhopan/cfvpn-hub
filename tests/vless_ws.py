#!/usr/bin/env python3
"""Modul bersama untuk uji VLESS-over-WebSocket (stdlib saja, bisa jalan dari WSL/Windows).

Dipakai oleh tests/prod-vless-dns.py dan tests/prod-proxy-check.py.
"""
import base64
import os
import socket
import ssl
import struct
import time

# UUID default untuk worker uji; timpa lewat env VLESS_UUID kalau worker memakai
# UUID_ALLOWLIST (worker yang dikunci hanya menerima UUID itu).
UUID_HEX = os.environ.get("VLESS_UUID", "14df7aee041645a8a651e69de188deca").replace("-", "").lower()
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) vless-test/1.0"

# Port dan TLS bisa ditimpa supaya config NTLS (port 80) juga bisa diuji:
#   VLESS_PORT=80 VLESS_TLS=0 python tests/prod-proxy-check.py <host> <ip:port>
# Berguna saat perangkat klien tidak bisa memvalidasi rantai sertifikat Cloudflare.
PORT = int(os.environ.get("VLESS_PORT", "443"))
USE_TLS = os.environ.get("VLESS_TLS", "1").lower() not in ("0", "false", "no")


def dns_query(txid, name):
    labels = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.split("."))
    return struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack(">HH", 1, 1)


def vless_frame(cmd, port, payload, host=b"dns.local", uuid_hex=UUID_HEX):
    return (
        bytes([0x00]) + bytes.fromhex(uuid_hex) + bytes([0x00, cmd])
        + struct.pack(">H", port) + bytes([0x02, len(host)]) + host + payload
    )


def prefixed(message):
    return struct.pack(">H", len(message)) + message


def parse_dns(buf):
    """Header DNS = 6 short (12 byte): txid, flags, qd, an, ns, ar."""
    if len(buf) < 12:
        return {"ok": False, "why": "pendek"}
    txid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", buf[:12])
    i = 12
    for _ in range(qd):
        while i < len(buf) and buf[i] != 0:
            i += buf[i] + 1
        i += 5
    answers = []
    for _ in range(an):
        if i + 12 > len(buf):
            break
        i += 2 if buf[i] & 0xC0 else buf[i] + 1
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", buf[i:i + 10])
        rdata = buf[i + 10:i + 10 + rdlen]
        if rtype == 1 and rdlen == 4:
            answers.append(".".join(str(b) for b in rdata))
        i += 10 + rdlen
    return {"ok": bool(flags & 0x8000), "txid": txid, "ancount": an, "answers": answers}


class Ws:
    """Klien WebSocket minimal (masked send, baca frame) di atas TLS."""

    def __init__(self, host, path, timeout=15):
        raw = socket.create_connection((host, PORT), timeout=timeout)
        self.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=host) if USE_TLS else raw
        self.sock.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {UA}\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(req.encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("koneksi ditutup saat handshake")
            head += chunk
        self.status = head.split(b"\r\n")[0].decode(errors="replace")
        if head.split(b"\r\n")[0].split()[1] != b"101":
            raise RuntimeError("handshake gagal: " + self.status)
        self.buf = head.split(b"\r\n\r\n", 1)[1]

    def send(self, payload, opcode=0x2):
        mask = os.urandom(4)
        n = len(payload)
        header = bytes([0x80 | opcode])
        if n < 126:
            header += bytes([0x80 | n])
        elif n < 65536:
            header += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            header += bytes([0x80 | 127]) + struct.pack(">Q", n)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(header + mask + masked)

    def collect(self, enough, deadline=8.0):
        """Baca frame sampai `enough(body)` benar, koneksi ditutup, atau deadline habis."""
        payloads = []
        closed = False
        end = time.time() + deadline
        while time.time() < end:
            body = b"".join(payloads)
            if body and enough(body):
                return payloads, closed
            try:
                while len(self.buf) < 2:
                    chunk = self.sock.recv(65536)
                    if not chunk:
                        return payloads, True
                    self.buf += chunk
                b1 = self.buf[1]
                opcode = self.buf[0] & 0x0F
                length = b1 & 0x7F
                offset = 2
                if length == 126:
                    while len(self.buf) < 4:
                        self.buf += self.sock.recv(65536)
                    length = struct.unpack(">H", self.buf[2:4])[0]
                    offset = 4
                elif length == 127:
                    while len(self.buf) < 10:
                        self.buf += self.sock.recv(65536)
                    length = struct.unpack(">Q", self.buf[2:10])[0]
                    offset = 10
                if b1 & 0x80:
                    offset += 4
                while len(self.buf) < offset + length:
                    chunk = self.sock.recv(65536)
                    if not chunk:
                        return payloads, True
                    self.buf += chunk
                payload = self.buf[offset:offset + length]
                self.buf = self.buf[offset + length:]
                if opcode == 0x8:
                    return payloads, True
                if opcode in (0x0, 0x1, 0x2):
                    payloads.append(payload)
            except socket.timeout:
                return payloads, closed
        return payloads, closed

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass
