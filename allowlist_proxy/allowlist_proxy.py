"""allowlist_proxy — Config A, the status quo.

An HTTP forward proxy that permits exactly ONE destination host (the egress
allowlist) and runs a policy monitor logging every connection and its verdict
(in-policy / violation). This is the compliance instrument the incident relied
on.

The finding the harness demonstrates: when the single allowed destination is the
*compromised upstream*, every attacker action (push a canary, pull attacker
bytes) is a connection to the allowed host, so the monitor reports 100%
in-policy and zero violations — while bytes cross the boundary in both
directions. The telemetry reports success for the property it monitors
(destination); that property was never the one that mattered.

Forwards proxy-form requests (absolute-URI request line, standard http_proxy
behaviour). Records a policy-monitor log to POLICY_LOG.
"""
from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
import urllib.request

ALLOWED_HOST = os.environ.get("ALLOWED_HOST", "mock_cache")
ALLOWED_PORT = int(os.environ.get("ALLOWED_PORT", "8080"))
POLICY_LOG = os.environ.get("POLICY_LOG", "/results/policy_monitor.log.jsonl")

_LOCK = threading.Lock()
STATS = {"total": 0, "in_policy": 0, "violation": 0}


def _monitor(dest_host: str, dest_port: int, verdict: str, method: str, detail: str):
    STATS["total"] += 1
    STATS[verdict] = STATS.get(verdict, 0) + 1
    rec = {"t": time.time(), "dest_host": dest_host, "dest_port": dest_port,
           "verdict": verdict, "method": method, "detail": detail}
    with _LOCK:
        try:
            with open(POLICY_LOG, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec) + "\n")
        except OSError:
            pass


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _forward(self, method: str):
        # Proxy-form: request path is an absolute URI.
        target = self.path
        parts = urlsplit(target)
        host = parts.hostname or ""
        port = parts.port or 80
        # POLICY CHECK: destination allowlist (the only thing an allowlist sees).
        if host == ALLOWED_HOST and port == ALLOWED_PORT:
            verdict = "in_policy"
        else:
            verdict = "violation"
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length else None
        _monitor(host, port, verdict, method, target)
        if verdict == "violation":
            # Allowlist blocks off-list destinations (this part "works").
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        # Allowed: forward verbatim to the (compromised) upstream.
        try:
            req = urllib.request.Request(target, data=body, method=method)
            for k, v in self.headers.items():
                if k.lower() in ("proxy-connection", "connection", "host", "content-length"):
                    continue
                req.add_header(k, v)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = resp.read()
                self.send_response(resp.status)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        except Exception as e:  # upstream error
            self.send_response(502)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_GET(self):
        self._forward("GET")

    def do_POST(self):
        self._forward("POST")

    def do_PUT(self):
        self._forward("PUT")

    def do_CONNECT(self):
        # Tunnelling: an allowlist proxy typically permits CONNECT to allowed
        # host. We log it and refuse tunnels in this harness (out of scope), but
        # record the attempt as a connection verdict.
        host, _, port = self.path.partition(":")
        verdict = "in_policy" if (host == ALLOWED_HOST) else "violation"
        _monitor(host, int(port or 0), verdict, "CONNECT", self.path)
        self.send_response(405)
        self.send_header("Content-Length", "0")
        self.end_headers()


def summary() -> dict:
    return dict(STATS)


def main():
    port = int(os.environ.get("PROXY_PORT", "3128"))
    srv = ThreadingHTTPServer(("0.0.0.0", port), ProxyHandler)
    print(f"allowlist_proxy on :{port}, allow {ALLOWED_HOST}:{ALLOWED_PORT}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
