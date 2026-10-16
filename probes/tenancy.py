"""Multi-tenant isolation and quota checks (Week-3 follow-up).

Two tenants (public config tenants/tenants.json) behind one MultiTenantBroker,
each on its own socket:
  alpha  main lockfile, tight quota (exercises enforcement)
  beta   Week-1 workload lockfile + one entry shared with alpha, quota = |L|

Isolation checks (T*) and quota checks (Q*) run in a fixed order so every count
is deterministic. Everything a check asserts about upstream behaviour is also
recorded in the per-tenant transcripts, which `sole-verify verify` re-derives.
"""
from __future__ import annotations

import json
import os
import time
import urllib.request

from multitenant import UPSTREAM_VERDICTS, MultiTenantBroker, load_config
from transport import BrokerTransport

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG = os.path.join(ROOT, "tenants", "tenants.json")
SHARED = ("pypi", "requests", "2.31.0", "wheel")


class CountingTransport(BrokerTransport):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.sent = 0

    def fetch_raw(self, request: dict) -> dict:
        self.sent += 1
        return super().fetch_raw(request)


def _pkg_gets(mock_base: str) -> int:
    with urllib.request.urlopen(mock_base + "/recv_log", timeout=5) as r:
        return sum(1 for e in json.loads(r.read().decode()) if e.get("kind") == "pkg_get")


def _scan(path: str) -> dict:
    out = {"requests": 0, "served": [], "upstream_ts": [], "quota_exceeded": 0, "notes": []}
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            e = json.loads(line)
            p = e["payload"]
            if e["kind"] == "note":
                out["notes"].append(p)
            elif e["kind"] == "request" or p.get("verdict") == "grammar_violation":
                out["requests"] += 1
            if p.get("verdict") == "served":
                out["served"].append(p["key"])
            if (p.get("verdict") == "served" and p.get("served_from") == "upstream") or \
                    p.get("verdict") in UPSTREAM_VERDICTS:
                out["upstream_ts"].append(e["ts"])
            if p.get("verdict") == "quota_exceeded":
                out["quota_exceeded"] += 1
    return out


def max_in_window(ts: list[float], window: float) -> int:
    """Largest number of events inside any sliding window of `window` seconds."""
    best, j = 0, 0
    for i in range(len(ts)):
        while ts[i] - ts[j] >= window:
            j += 1
        best = max(best, i - j + 1)
    return best


def run_tenancy_checks(results_dir: str, upstream_host: str, upstream_port: int,
                       ports: dict[str, int]) -> dict:
    from workload.runner import run_task
    from workload.experiment import _final_view

    mock_base = f"http://{upstream_host}:{upstream_port}"
    urllib.request.urlopen(mock_base + "/reset", timeout=5).read()
    cfg = load_config(CONFIG)
    out_dir = os.path.join(results_dir, "tenants")
    mt = MultiTenantBroker(cfg, upstream_host, upstream_port, out_dir, base=ROOT)
    mt.serve(tcp_ports=ports)
    time.sleep(0.4)
    A, B = mt.tenants["alpha"], mt.tenants["beta"]
    tA = CountingTransport(unix_path=None, tcp=("127.0.0.1", ports["alpha"]))
    tB = CountingTransport(unix_path=None, tcp=("127.0.0.1", ports["beta"]))
    alpha_only = sorted(set(A.entries) - set(B.entries))
    beta_only = sorted(set(B.entries) - set(A.entries))
    checks = []

    def add(cid, name, passed, detail):
        checks.append({"id": cid, "name": name, "passed": bool(passed), "detail": detail})

    # T1 tenant identity cannot be claimed in-band (closed grammar, S3)
    r = tA.fetch_raw({"verb": "fetch", "ecosystem": "pypi", "name": "requests",
                      "version": "2.31.0", "artifact": "wheel", "tenant": "beta"})
    add("T1", "tenant_not_claimable_in_band",
        not r.get("ok") and str(r.get("reason", "")).startswith("grammar_violation"),
        {"reason": r.get("reason")})

    # T2 a tenant cannot read another tenant's pinned entries (per-tenant S4)
    eco, name, ver, art = alpha_only[0].split(":")
    rb = tB.fetch(eco, name, ver, art)
    eco, name, ver, art = beta_only[0].split(":")
    ra = tA.fetch(eco, name, ver, art)
    add("T2", "cross_tenant_entry_refused",
        rb.get("reason") == "lockfile_miss" and ra.get("reason") == "lockfile_miss",
        {"beta_requests_alpha_entry": rb.get("reason"), "alpha_requests_beta_entry": ra.get("reason"),
         "alpha_only_entries": len(alpha_only), "beta_only_entries": len(beta_only)})

    # T3 no shared cache state: alpha warming a shared entry does not warm beta's
    s1 = tA.fetch(*SHARED).get("served_from")
    s2 = tB.fetch(*SHARED).get("served_from")
    s3 = tB.fetch(*SHARED).get("served_from")
    add("T3", "no_cross_tenant_cache_state", (s1, s2, s3) == ("upstream", "upstream", "cache"),
        {"alpha_first": s1, "beta_first": s2, "beta_second": s3})

    # Q1 alpha's quota bounds its upstream fetches; excess fails closed upstream-silent
    before = _pkg_gets(mock_base)
    wanted = [k for k in alpha_only if k != ":".join(SHARED)][:A.quota + 1]
    verdicts = []
    for k in wanted:
        r = tA.fetch(*k.split(":"))
        verdicts.append("served" if r.get("ok") else r.get("reason"))
    delta = _pkg_gets(mock_base) - before
    served = verdicts.count("served")
    add("Q1", "quota_bounds_upstream_fetches",
        A.upstream_attempts() == A.quota and served == A.quota - 1 and delta == served
        and verdicts.count("quota_exceeded") == len(wanted) - served,
        {"quota": A.quota, "requested_uncached": len(wanted), "served": served,
         "quota_exceeded": verdicts.count("quota_exceeded"), "upstream_requests_observed": delta,
         "alpha_upstream_attempts": A.upstream_attempts()})

    # Q2 cache hits never consume quota: legitimate repeat use survives exhaustion
    r = tA.fetch(*SHARED)
    add("Q2", "cache_hits_free_after_quota", r.get("ok") and r.get("served_from") == "cache",
        {"served_from": r.get("served_from"), "reason": r.get("reason")})

    # Q3 quota exhaustion is per tenant: beta's real eval task still goes green
    res = run_task(tB)
    add("Q3", "quota_isolated_between_tenants",
        res["ok"] and B.upstream_attempts() <= B.quota,
        {"beta_task_ok": res["ok"], "beta_upstream_attempts": B.upstream_attempts(),
         "beta_quota": B.quota})

    tenants = []
    for t in cfg:
        b = mt.tenants[t["id"]]
        tr = os.path.join(out_dir, t["id"], "transcript.jsonl")
        scan = _scan(tr)
        tenants.append({
            "id": t["id"], "lockfile": t["lockfile"], "lockfile_digest": b.lf_digest,
            "quota": b.quota, "window_s": b.window_s,
            "transcript_file": os.path.relpath(tr, ROOT).replace(os.sep, "/"),
            "transcript_root": b.transcript.root,
            "requests_sent": (tA if t["id"] == "alpha" else tB).sent,
            "upstream_attempts": b.upstream_attempts(),
            "quota_exceeded": scan["quota_exceeded"],
            "channel_bound": b.channel_bound(),
        })
    # T4 transcripts are per tenant: each logs exactly its own socket's requests
    # and serves only keys from its own lockfile
    t4 = []
    for t in tenants:
        scan = _scan(os.path.join(ROOT, t["transcript_file"]))
        own = mt.tenants[t["id"]].entries
        t4.append(scan["requests"] == t["requests_sent"] and all(k in own for k in scan["served"]))
    add("T4", "per_tenant_transcripts_disjoint", all(t4),
        {t["id"]: t["requests_sent"] for t in tenants})

    return {"config": os.path.relpath(CONFIG, ROOT).replace(os.sep, "/"),
            "tenants": tenants, "checks": checks, "beta_workload": _final_view(res)}
