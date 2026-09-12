"""mock_cache — the compromised-but-cooperative upstream.

Models the incident's core assumption: *the one permitted egress is already
compromised.* It contains NO exploit and NO vulnerability. It is a yes-machine:
it proxies arbitrary requests, honours redirects, accepts uploads, and returns
whatever is asked. That cooperativeness is the whole point — it is what an
attacker-controlled cache proxy behaves like, and it is what SEP-1 must survive.

It ALSO logs everything it receives, so it doubles as the *receiver* for the
covert-channel measurement (control S9): whatever the sandbox pushes to it, it
records, and we can measure how many bits actually arrived.

Endpoints (all cooperative):
  GET  /pkg/<eco>/<name>/<ver>/<art>      -> package bytes (optionally poisoned)
  GET  /any?bytes=N                       -> N attacker-chosen bytes ("pull")
  GET  /any?redirect=<url>                -> 302 Location:<url>  (tests S6)
  GET  /any?size=big                      -> oversize body       (tests S7)
  ANY  /exfil            (POST/PUT body)  -> 200, body recorded  ("push"/canary)
  GET  /recv_log                          -> JSON of what was received (receiver)
  GET  /reset                            -> clear received log
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# Deterministic "package" registry the broker pulls through. Content is fixed so
# digests are stable; the lockfile pins these exact bytes.
PACKAGES: dict[str, bytes] = {}


def _make_packages() -> None:
    # 16 tiny deterministic artifacts across ecosystems -> gives the covert
    # channel log2(16)=4 bits of selection entropy per distinct request.
    specs = [
        ("pypi", "requests", "2.31.0", "wheel"),
        ("pypi", "urllib3", "2.2.1", "wheel"),
        ("pypi", "numpy", "1.26.4", "wheel"),
        ("pypi", "click", "8.1.7", "wheel"),
        ("pypi", "pyyaml", "6.0.1", "sdist"),
        ("pypi", "certifi", "2024.2.2", "wheel"),
        ("pypi", "idna", "3.6", "wheel"),
        ("pypi", "packaging", "24.0", "wheel"),
        ("npm", "left-pad", "1.3.0", "tarball"),
        ("npm", "lodash", "4.17.21", "tarball"),
        ("npm", "chalk", "5.3.0", "tarball"),
        ("npm", "express", "4.19.2", "tarball"),
        ("cargo", "serde", "1.0.197", "tarball"),
        ("cargo", "tokio", "1.36.0", "tarball"),
        ("maven", "guava", "33.0.0", "jar"),
        ("maven", "junit", "4.13.2", "jar"),
    ]
    for eco, name, ver, art in specs:
        key = f"/pkg/{eco}/{name}/{ver}/{art}"
        body = (f"SEP1-FIXTURE {eco} {name} {ver} {art}\n").encode() * 8
        PACKAGES[key] = body


_make_packages()

# Upstream behaviour toggles used by the broker-integrity structural checks.
POISON = {"on": False}          # tamper package bytes (tests S5 content pinning)
REDIRECT_PKG = {"on": False}    # 302 a /pkg request to an attacker host (tests S6)
OVERSIZE_PKG = {"on": False}    # return an over-limit body for /pkg (tests S7)

# Receiver log for the covert-channel measurement.
RECV: list[dict] = []
RECV_LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # quiet
        pass

    def _record(self, kind: str, extra: dict):
        with RECV_LOCK:
            RECV.append({"t": time.time(), "kind": kind, **extra})

    def _send(self, code: int, body: bytes = b"", headers: dict | None = None):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        # Cooperative upstream reflects an attacker-controllable header to prove
        # S7 (response-shape closure) must strip upstream headers in the broker.
        self.send_header("X-Upstream-Note", "attacker-controlled-value")
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        # Package pull-through (what the broker uses).
        if u.path in PACKAGES:
            self._record("pkg_get", {"path": u.path, "poison": POISON["on"]})
            if REDIRECT_PKG["on"]:
                return self._send(302, b"", {"Location": "http://attacker.invalid/evil"})
            if OVERSIZE_PKG["on"]:
                return self._send(200, b"B" * (6 * 1024 * 1024))
            body = PACKAGES[u.path]
            if POISON["on"]:
                body = body + b"POISONED"  # tampered => digest will mismatch
            return self._send(200, body)
        if u.path == "/recv_log":
            with RECV_LOCK:
                return self._send(200, json.dumps(RECV).encode(),
                                  {"Content-Type": "application/json"})
        if u.path == "/reset":
            with RECV_LOCK:
                RECV.clear()
            POISON["on"] = False
            REDIRECT_PKG["on"] = False
            OVERSIZE_PKG["on"] = False
            return self._send(200, b"reset")
        if u.path == "/poison_on":
            POISON["on"] = True
            return self._send(200, b"poison on")
        if u.path == "/redirect_pkg_on":
            REDIRECT_PKG["on"] = True
            return self._send(200, b"redirect on")
        if u.path == "/oversize_pkg_on":
            OVERSIZE_PKG["on"] = True
            return self._send(200, b"oversize on")
        if u.path == "/health":
            return self._send(200, b"ok")
        # Fully cooperative catch-all (the "return whatever is asked" behaviour).
        if "redirect" in q:
            # Honour redirect to an upstream-chosen destination (tests S6).
            self._record("redirect", {"to": q["redirect"][0]})
            return self._send(302, b"", {"Location": q["redirect"][0]})
        if q.get("size") == ["big"]:
            return self._send(200, b"A" * (5 * 1024 * 1024))  # 5 MiB
        n = int(q.get("bytes", ["32"])[0])
        n = max(0, min(n, 8 * 1024 * 1024))
        self._record("pull", {"path": u.path, "bytes": n})
        return self._send(200, b"\x5a" * n)  # attacker bytes

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or "0")
        return self.rfile.read(length) if length else b""

    def do_POST(self):
        body = self._read_body()
        self._record("upload", {"path": urlparse(self.path).path,
                                 "sha256": hashlib.sha256(body).hexdigest(),
                                 "len": len(body),
                                 "preview": body[:64].decode("latin1")})
        return self._send(200, b"stored")

    do_PUT = do_POST


def main():
    port = int(os.environ.get("MOCK_CACHE_PORT", "8080"))
    host = os.environ.get("MOCK_CACHE_HOST", "0.0.0.0")
    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"mock_cache (compromised-but-cooperative) on {host}:{port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
