"""broker — Config B, the SEP-1 sole-egress package broker.

The sandbox has NO network interface. Its only channel is a unix-domain socket
to this broker. The broker serves ONLY entries of a pre-resolved, hash-pinned
lockfile supplied at sandbox creation, enforcing controls S3-S10.

Request wire format: one JSON object per line (newline-delimited):
    {"verb":"fetch","ecosystem":"pypi","name":"requests","version":"2.31.0","artifact":"wheel"}
Response: one JSON object per line:
    {"ok":true,"sha256":"..","size":N,"data_b64":".."}  or {"ok":false,"reason":".."}

Every request, digest and verdict is appended to a hash-chained transcript.
"""
from __future__ import annotations

import base64
import json
import os
import socket
import sys
import threading
import time
import http.client

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from sole_egress_common import (  # noqa: E402
    GrammarError, Transcript, load_lockfile, lockfile_digest, lock_key,
    parse_fetch, sha256_hex,
)

MAX_RESPONSE_BYTES = int(os.environ.get("MAX_RESPONSE_BYTES", str(1 * 1024 * 1024)))
# S9 knob: minimum seconds between UPSTREAM fetches (bounds the channel rate).
MIN_UPSTREAM_INTERVAL = float(os.environ.get("MIN_UPSTREAM_INTERVAL", "0.05"))


class Broker:
    def __init__(self, lockfile_path: str, upstream_host: str, upstream_port: int,
                 transcript_path: str | None = None, nocache: bool = False):
        self.lf = load_lockfile(lockfile_path)
        self.lf_digest = lockfile_digest(self.lf)
        self.entries = self.lf["entries"]  # key -> {sha256,size,path}
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port
        self.transcript = Transcript(transcript_path)
        self.cache: dict[str, bytes] = {}
        self.nocache = nocache  # S9 worst-case measurement: emit an upstream fetch every time
        self._last_upstream = 0.0
        self._lock = threading.Lock()

    # -- upstream fetch (S6 no-redirect, S7 shape closure, S8 fail-closed) --
    def _fetch_upstream(self, path: str) -> bytes | None:
        with self._lock:
            dt = MIN_UPSTREAM_INTERVAL - (time.time() - self._last_upstream)
            if dt > 0:
                time.sleep(dt)
            self._last_upstream = time.time()
        try:
            conn = http.client.HTTPConnection(self.upstream_host, self.upstream_port, timeout=10)
            # Fixed request line. No client headers, no method choice: the
            # upstream destination is static config, never request data (S6).
            conn.request("GET", path)
            resp = conn.getresponse()
            # S6: a 3xx is NEVER followed; Location is never honoured.
            if resp.status != 200:
                conn.close()
                return None
            # S7: bounded read, no chunked/streaming passthrough, upstream
            # headers are discarded (not forwarded to the sandbox).
            data = resp.read(MAX_RESPONSE_BYTES + 1)
            conn.close()
            if len(data) > MAX_RESPONSE_BYTES:
                return None  # oversize => fail closed
            return data
        except Exception:
            return None  # S8 fail-closed: never fall back to a direct fetch

    def handle(self, request: dict) -> dict:
        t0 = time.time()
        # S3 closed request grammar
        try:
            eco, name, ver, art = parse_fetch(request)
        except GrammarError as e:
            self.transcript.append("verdict", {"verdict": "grammar_violation",
                                               "reason": str(e)})
            return {"ok": False, "reason": f"grammar_violation: {e}"}
        key = lock_key(eco, name, ver, art)
        self.transcript.append("request", {"key": key})
        # S4 lockfile closure
        entry = self.entries.get(key)
        if entry is None:
            self.transcript.append("verdict", {"key": key, "verdict": "lockfile_miss"})
            return {"ok": False, "reason": "lockfile_miss"}
        # Serve from cache if present (repeat requests => no upstream signal).
        data = None if self.nocache else self.cache.get(key)
        served_from = "cache"
        if data is None:
            served_from = "upstream"
            data = self._fetch_upstream(entry["path"])
            if data is None:
                self.transcript.append("verdict", {"key": key, "verdict": "upstream_fail_closed"})
                return {"ok": False, "reason": "upstream_fail_closed"}
            # S5 content pinning — the control that survives upstream compromise.
            got = sha256_hex(data)
            if got != entry["sha256"]:
                self.transcript.append("verdict", {"key": key, "verdict": "digest_mismatch",
                                                   "expected": entry["sha256"], "got": got})
                return {"ok": False, "reason": "digest_mismatch"}
            if not self.nocache:
                self.cache[key] = data
        self.transcript.append("verdict", {"key": key, "verdict": "served",
                                           "sha256": entry["sha256"],
                                           "served_from": served_from,
                                           "ms": round((time.time() - t0) * 1000, 2)})
        return {"ok": True, "sha256": entry["sha256"], "size": len(data),
                "data_b64": base64.b64encode(data).decode(), "served_from": served_from}


# --------------------------------------------------------------------------
# Socket servers
# --------------------------------------------------------------------------

def _serve_conn(broker: Broker, conn: socket.socket):
    conn_file = conn.makefile("rwb")
    try:
        for line in conn_file:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except Exception:
                resp = {"ok": False, "reason": "grammar_violation: not json"}
            else:
                resp = broker.handle(req)
            conn_file.write((json.dumps(resp) + "\n").encode())
            conn_file.flush()
    except Exception:
        pass
    finally:
        try:
            conn_file.close()
            conn.close()
        except Exception:
            pass


def serve(broker: Broker, unix_path: str | None, tcp_port: int | None):
    servers = []
    if unix_path:
        try:
            if os.path.exists(unix_path):
                os.unlink(unix_path)
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.bind(unix_path)
            s.listen(64)
            servers.append(("unix", s))
            print(f"broker on unix:{unix_path}", flush=True)
        except (AttributeError, OSError) as e:
            print(f"broker: unix socket unavailable ({e})", flush=True)
    if tcp_port:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", tcp_port))
        s.listen(64)
        servers.append(("tcp", s))
        print(f"broker on tcp:127.0.0.1:{tcp_port}", flush=True)
    if not servers:
        raise SystemExit("broker: no transport available")

    def loop(sock):
        while True:
            conn, _ = sock.accept()
            threading.Thread(target=_serve_conn, args=(broker, conn), daemon=True).start()

    threads = [threading.Thread(target=loop, args=(s,), daemon=True) for _, s in servers]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


def main():
    lockfile_path = os.environ.get("LOCKFILE", "/app/lockfile.json")
    upstream_host = os.environ.get("UPSTREAM_HOST", "mock_cache")
    upstream_port = int(os.environ.get("UPSTREAM_PORT", "8080"))
    unix_path = os.environ.get("BROKER_SOCKET", "/run/broker/broker.sock")
    transcript_path = os.environ.get("TRANSCRIPT", "/results/transcript.jsonl")
    tcp_port = os.environ.get("BROKER_TCP")
    os.makedirs(os.path.dirname(transcript_path), exist_ok=True)
    if unix_path:
        os.makedirs(os.path.dirname(unix_path), exist_ok=True)
    broker = Broker(lockfile_path, upstream_host, upstream_port, transcript_path)
    print(f"broker: lockfile_digest={broker.lf_digest[:16]}.. entries={len(broker.entries)}", flush=True)
    serve(broker, unix_path, int(tcp_port) if tcp_port else None)


if __name__ == "__main__":
    sys.exit(main())
