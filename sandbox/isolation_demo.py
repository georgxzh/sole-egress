"""Real network-namespace isolation demo for Config B (controls S1/S2/S11).

Runs inside a container started with `network_mode: none`, whose ONLY channel to
the outside is the broker unix socket bind-mounted at /run/broker/broker.sock.

It asserts, against a kernel-enforced netns (not a simulation):
  - raw TCP to a public resolver fails            (S1 no general socket)
  - DNS resolution fails                          (S2 no name resolution)
  - the cloud IMDS IP is unreachable              (S1)
  - a pinned package fetch over the broker socket succeeds (broker channel works)

Exit code 0 iff all four hold; prints a JSON verdict.
"""
from __future__ import annotations

import base64
import json
import os
import socket
import sys


def _raw_tcp(host: str, port: int) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False


def _dns(name: str) -> bool:
    try:
        socket.getaddrinfo(name, 80)
        return True
    except Exception:
        return False


def _broker_fetch(sock_path: str, req: dict) -> dict:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(sock_path)
    f = s.makefile("rwb")
    f.write((json.dumps(req) + "\n").encode())
    f.flush()
    resp = json.loads(f.readline().decode())
    s.close()
    return resp


def main() -> int:
    sock = os.environ.get("BROKER_SOCKET", "/run/broker/broker.sock")
    result = {
        "raw_tcp_1.1.1.1:53_blocked": not _raw_tcp("1.1.1.1", 53),
        "dns_resolution_blocked": not _dns("example.com"),
        "imds_169.254.169.254_blocked": not _raw_tcp("169.254.169.254", 80),
    }
    fetch = _broker_fetch(sock, {"verb": "fetch", "ecosystem": "pypi",
                                 "name": "requests", "version": "2.31.0",
                                 "artifact": "wheel"})
    result["broker_pinned_fetch_ok"] = bool(fetch.get("ok"))
    if fetch.get("ok"):
        result["fetched_bytes"] = len(base64.b64decode(fetch["data_b64"]))
    # A grammar-violating request must be rejected even over the socket.
    smug = _broker_fetch(sock, {"verb": "fetch", "ecosystem": "pypi",
                                "name": "../../etc/passwd", "version": "1",
                                "artifact": "wheel"})
    result["grammar_smuggle_blocked"] = not smug.get("ok")

    ok = all([result["raw_tcp_1.1.1.1:53_blocked"], result["dns_resolution_blocked"],
              result["imds_169.254.169.254_blocked"], result["broker_pinned_fetch_ok"],
              result["grammar_smuggle_blocked"]])
    result["ISOLATION_VERDICT"] = "PASS" if ok else "FAIL"
    print(json.dumps(result, indent=2), flush=True)
    out = os.environ.get("ISOLATION_OUT")
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
