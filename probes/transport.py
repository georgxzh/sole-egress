"""Transports the probe suite runs against.

The SAME probe suite faces both worlds; only the primitives available to the
sandbox interior differ. That is what makes the A-vs-B table apples-to-apples.

Config A (allowlist): the sandbox's ONE egress is the forward proxy. Every
destination attempt is expressed through it; the proxy's allowlist blocks
off-list hosts (verdict=violation, HTTP 403) and permits the single allowed host
(verdict=in_policy). The allowed host is the compromised upstream.

Config B (SEP-1): the sandbox has NO network interface. The transport exposes
NO general egress primitive at all — only fetch() over the broker socket. This
mirrors "the sandbox has no route out; its only channel is the broker socket"
(control S1). In Docker this is additionally enforced by network_mode: none.
"""
from __future__ import annotations

import base64
import json
import os
import socket
import urllib.error
import urllib.request

BLOCKED_NO_NETWORK = {"ok": False, "blocked": True, "reason": "no_network",
                      "status": None, "body": b""}


class AllowlistTransport:
    """Config A. Only egress is the forward proxy."""

    config = "A"

    def __init__(self, proxy_host: str, proxy_port: int,
                 allowed_host: str, allowed_port: int):
        self.proxy = f"http://{proxy_host}:{proxy_port}"
        self.allowed_host = allowed_host
        self.allowed_port = allowed_port
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": self.proxy})
        )

    def has_network(self) -> bool:
        return True

    def egress(self, method: str, host: str, port: int, path: str,
               body: bytes | None = None) -> dict:
        url = f"http://{host}:{port}{path}"
        req = urllib.request.Request(url, data=body, method=method)
        try:
            with self._opener.open(req, timeout=10) as resp:
                data = resp.read()
                return {"ok": True, "blocked": False, "status": resp.status,
                        "body": data, "headers": dict(resp.headers)}
        except urllib.error.HTTPError as e:
            # 403 from the proxy == allowlist violation blocked.
            return {"ok": False, "blocked": e.code == 403, "status": e.code,
                    "body": e.read() if hasattr(e, "read") else b""}
        except Exception as e:
            return {"ok": False, "blocked": True, "status": None, "reason": str(e), "body": b""}

    def fetch(self, eco: str, name: str, ver: str, art: str) -> dict:
        # Status-quo package use: a plain GET to the (allowed) cache.
        path = f"/pkg/{eco}/{name}/{ver}/{art}"
        r = self.egress("GET", self.allowed_host, self.allowed_port, path)
        return {"ok": r.get("status") == 200, "data": r.get("body", b"")}


class BrokerTransport:
    """Config B. Only channel is the broker socket; no general egress."""

    config = "B"

    def __init__(self, unix_path: str | None = None, tcp: tuple[str, int] | None = None):
        self.unix_path = unix_path
        self.tcp = tcp

    def has_network(self) -> bool:
        return False

    def egress(self, *a, **k) -> dict:
        # The sandbox has no network interface: there is no primitive to call.
        return dict(BLOCKED_NO_NETWORK)

    def _connect(self) -> socket.socket:
        if self.unix_path:
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(10)
                s.connect(self.unix_path)
                return s
            except (AttributeError, OSError):
                pass
        if self.tcp:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect(self.tcp)
            return s
        raise OSError("no broker transport configured")

    def fetch_raw(self, request: dict) -> dict:
        """Send an arbitrary object to the broker (used by grammar probes)."""
        s = self._connect()
        try:
            f = s.makefile("rwb")
            f.write((json.dumps(request) + "\n").encode())
            f.flush()
            line = f.readline()
            return json.loads(line.decode())
        finally:
            s.close()

    def fetch(self, eco: str, name: str, ver: str, art: str) -> dict:
        resp = self.fetch_raw({"verb": "fetch", "ecosystem": eco, "name": name,
                               "version": ver, "artifact": art})
        data = base64.b64decode(resp["data_b64"]) if resp.get("ok") else b""
        return {"ok": resp.get("ok", False), "data": data, "reason": resp.get("reason"),
                "served_from": resp.get("served_from")}
