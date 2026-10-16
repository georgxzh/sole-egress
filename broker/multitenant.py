"""Multi-tenant SEP-1 broker (Week-3 follow-up).

One broker process serves many sandboxes. Each tenant is a full, independent
SEP-1 `Broker`: its own lockfile, its own hash-chained transcript, its own cache
and its own upstream rate limiter. What is shared is only the static upstream
config.

Isolation by construction:
  * Tenant identity is bound to the *socket*, never to request data. Each tenant
    gets its own listener (in Docker, its own bind-mounted unix socket), so a
    sandbox cannot name another tenant; the closed grammar (S3) rejects any
    extra field such as "tenant".
  * A tenant can only be served entries of its OWN lockfile (S4 per tenant):
    another tenant's pins are a `lockfile_miss`, even when that tenant has the
    bytes cached.
  * Caches are per tenant, so one tenant's fetch history leaves no state another
    tenant can observe.
  * Transcripts are per tenant and each starts with a `tenant_bound` note, so a
    tenant's conformance evidence can be published without disclosing another
    tenant's requests.

Per-tenant quota (S9 per tenant): at most `quota` upstream fetch attempts per
sliding `window_s`. Cache hits are free; a miss beyond quota fails closed with
`quota_exceeded` and emits nothing upstream. Every upstream attempt is a
transcript verdict (served-from-upstream / upstream_fail_closed /
digest_mismatch), so the quota is checkable from the transcript alone, and the
upstream-observable events per tenant are bounded by config, not by behaviour.

Config (JSON): [{"id": "alpha", "lockfile": "...", "quota": 4, "window_s": 3600}, ...]
Env: TENANTS=<config path>, UPSTREAM_HOST, UPSTREAM_PORT, TENANT_SOCKET_DIR,
     TENANT_TRANSCRIPT_DIR
"""
from __future__ import annotations

import json
import math
import os
import sys
import threading
import time
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from broker import MIN_UPSTREAM_INTERVAL, Broker, serve  # noqa: E402

# Verdicts that mean the broker contacted the upstream (and so count against quota).
UPSTREAM_VERDICTS = ("upstream_fail_closed", "digest_mismatch")


class TenantBroker(Broker):
    def __init__(self, tenant_id: str, lockfile_path: str, upstream_host: str,
                 upstream_port: int, transcript_path: str | None, quota: int, window_s: float):
        super().__init__(lockfile_path, upstream_host, upstream_port, transcript_path)
        self.tenant_id = tenant_id
        self.quota = int(quota)
        self.window_s = float(window_s)
        self._attempts: deque[float] = deque()
        self._quota_lock = threading.Lock()
        self.upstream_gate = self._admit
        self.transcript.append("note", {"event": "tenant_bound", "tenant": tenant_id,
                                        "quota": self.quota, "window_s": self.window_s})
        self.note_lockfile(f"tenant {tenant_id}")

    def _admit(self) -> bool:
        now = time.time()
        with self._quota_lock:
            while self._attempts and now - self._attempts[0] >= self.window_s:
                self._attempts.popleft()
            if len(self._attempts) >= self.quota:
                return False
            self._attempts.append(now)
            return True

    def upstream_attempts(self) -> int:
        return len(self._attempts)

    def channel_bound(self) -> dict:
        """Upper bound on what one tenant's upstream-observable events can carry
        per window: each of at most `quota` events selects one of |L| entries and
        occupies one of window/min_interval rate-limit slots."""
        n = max(len(self.entries), 1)
        slots = max(self.window_s / MIN_UPSTREAM_INTERVAL, 1.0)
        per_event = math.log2(n) + math.log2(slots)
        bits = self.quota * per_event
        return {"tenant": self.tenant_id, "quota": self.quota, "window_s": self.window_s,
                "lockfile_entries": len(self.entries),
                "bits_per_event_bound": round(per_event, 3),
                "bits_per_window_bound": round(bits, 1),
                "bits_per_hour_bound": round(bits * 3600.0 / self.window_s, 1)}


class MultiTenantBroker:
    def __init__(self, tenants: list[dict], upstream_host: str, upstream_port: int,
                 transcript_dir: str | None, base: str = ""):
        self.tenants: dict[str, TenantBroker] = {}
        for t in tenants:
            tid = t["id"]
            if tid in self.tenants:
                raise ValueError(f"duplicate tenant {tid!r}")
            tpath = os.path.join(transcript_dir, tid, "transcript.jsonl") if transcript_dir else None
            if tpath:
                os.makedirs(os.path.dirname(tpath), exist_ok=True)
                if os.path.exists(tpath):
                    os.remove(tpath)
            self.tenants[tid] = TenantBroker(tid, os.path.join(base, t["lockfile"]),
                                             upstream_host, upstream_port, tpath,
                                             t["quota"], t["window_s"])

    def serve(self, tcp_ports: dict[str, int] | None = None, socket_dir: str | None = None):
        """One listener per tenant; returns immediately (daemon threads)."""
        for tid, b in self.tenants.items():
            unix = os.path.join(socket_dir, f"{tid}.sock") if socket_dir else None
            port = (tcp_ports or {}).get(tid)
            threading.Thread(target=serve, args=(b, unix, port), daemon=True).start()


def load_config(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def main():
    cfg = os.environ.get("TENANTS", "/app/tenants/tenants.json")
    mt = MultiTenantBroker(load_config(cfg), os.environ.get("UPSTREAM_HOST", "mock_cache"),
                           int(os.environ.get("UPSTREAM_PORT", "8080")),
                           os.environ.get("TENANT_TRANSCRIPT_DIR", "/results/tenants"),
                           base=os.path.dirname(os.path.dirname(os.path.abspath(cfg))))
    sock_dir = os.environ.get("TENANT_SOCKET_DIR", "/run/broker")
    os.makedirs(sock_dir, exist_ok=True)
    mt.serve(socket_dir=sock_dir)
    for tid, b in mt.tenants.items():
        print(f"tenant {tid}: lockfile {b.lf_digest[:16]}.. quota {b.quota}/{b.window_s:g}s", flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    sys.exit(main())
