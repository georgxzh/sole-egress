"""sole-verify — orchestrate the two-config experiment and emit a checkable
conformance report.

Commands:
  run   --local | --docker [--all]   run both configs, write results/ + report
  verify <conformance-report.json>   recompute everything a third party can check

Local mode spins the services as loopback processes/threads; Docker mode is the
network-isolated demonstration (docker compose). Both write the identical result
schema so the committed numbers are reproducible on any laptop.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import threading
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for p in (ROOT, os.path.join(ROOT, "probes"), os.path.join(ROOT, "broker"),
          os.path.join(ROOT, "mock_cache")):
    sys.path.insert(0, p)

from sole_egress_common import (  # noqa: E402
    Transcript, digest_json, load_lockfile, lockfile_digest, sha256_hex, sign_root,
    verify_signature, PROFILE_VERSION,
)
from transport import AllowlistTransport, BrokerTransport  # noqa: E402
import probes as probes_mod  # noqa: E402
from broker import Broker, serve  # noqa: E402
from workload.experiment import run_friction_experiment  # noqa: E402
from tenancy import max_in_window, run_tenancy_checks, _scan as scan_tenant_transcript  # noqa: E402
from multitenant import MIN_UPSTREAM_INTERVAL  # noqa: E402

# Loopback ports for local mode.
MOCK_PORT = 8080
ATTACKER_PORT = 8082
PROXY_PORT = 3128
BROKER_TCP = 8090
MEASURE_BROKER_TCP = 8091
WORKLOAD_BROKER_TCP = 8092
WORKLOAD_CLOSURE_BROKER_TCP = 8093
TENANT_PORTS = {"alpha": 8094, "beta": 8095}

# 8-symbol alphabet for the covert channel (3 clean bits/symbol).
COVERT_ALPHABET = [
    ("pypi", "requests", "2.31.0", "wheel"),
    ("pypi", "urllib3", "2.2.1", "wheel"),
    ("pypi", "numpy", "1.26.4", "wheel"),
    ("pypi", "click", "8.1.7", "wheel"),
    ("pypi", "certifi", "2024.2.2", "wheel"),
    ("pypi", "idna", "3.6", "wheel"),
    ("pypi", "packaging", "24.0", "wheel"),
    ("npm", "lodash", "4.17.21", "tarball"),
]


# --------------------------------------------------------------------------
# process / health helpers
# --------------------------------------------------------------------------

def _http_get(url: str, timeout: float = 2.0) -> bytes:
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read()


def _wait(url: str, timeout: float = 15.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            _http_get(url, 1.0)
            return True
        except Exception:
            time.sleep(0.15)
    return False


def _start(script: str, env_extra: dict) -> subprocess.Popen:
    env = dict(os.environ)
    env.update({k: str(v) for k, v in env_extra.items()})
    return subprocess.Popen([sys.executable, script], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class Harness:
    """The out-of-sandbox observer: it can read the upstream's receive log to
    confirm whether bytes actually crossed the boundary."""

    def __init__(self, mock_base: str):
        self.mock = mock_base

    def recv_log(self) -> list:
        try:
            return json.loads(_http_get(self.mock + "/recv_log").decode())
        except Exception:
            return []

    def recv_contains(self, token: str) -> bool:
        for e in self.recv_log():
            if token in json.dumps(e):
                return True
        return False

    def recv_reset(self):
        try:
            _http_get(self.mock + "/reset")
        except Exception:
            pass

    def poison_on(self):
        try:
            _http_get(self.mock + "/poison_on")
        except Exception:
            pass

    def recv_pkg_paths(self) -> list[str]:
        return [e["path"] for e in self.recv_log() if e.get("kind") == "pkg_get"]


# --------------------------------------------------------------------------
# suite runners
# --------------------------------------------------------------------------

def _count_lines(path: str) -> int:
    if not os.path.exists(path):
        return 0
    with open(path, "r", encoding="utf-8") as fh:
        return sum(1 for _ in fh)


def _read_lines(path: str, start: int) -> list[dict]:
    if not os.path.exists(path):
        return []
    out = []
    with open(path, "r", encoding="utf-8") as fh:
        for i, line in enumerate(fh):
            if i >= start and line.strip():
                out.append(json.loads(line))
    return out


def run_config(config: str, transport, ctx: dict, policy_log: str | None) -> list[dict]:
    results = []
    for probe in probes_mod.PROBES:
        before = _count_lines(policy_log) if policy_log else 0
        # keep upstream state clean where a probe mutates it
        try:
            out = probe.run(transport, ctx)
        except Exception as e:
            out = {"outcome": "ERROR", "achieved": False, "detail": f"{type(e).__name__}: {e}"}
        rec = {
            "id": probe.id, "class": probe.action_class,
            "property_violated_if_success": probe.property_violated_if_success,
            "expected": probe.expected_A if config == "A" else probe.expected_B,
            "outcome": out["outcome"], "achieved": out.get("achieved"),
            "detail": out.get("detail", ""),
        }
        for k in ("channel_bits_per_hour", "empirical_bits_per_hour", "measured_bits_per_second",
                  "bits_per_symbol", "min_upstream_interval_s", "symbols_sent", "symbols_recovered",
                  "oneshot_ordering_bits_with_caching", "elapsed_s"):
            if k in out:
                rec[k] = out[k]
        if policy_log and config == "A":
            new = _read_lines(policy_log, before)
            rec["monitor_connections"] = len(new)
            rec["monitor_in_policy"] = sum(1 for n in new if n["verdict"] == "in_policy")
            rec["monitor_violation"] = sum(1 for n in new if n["verdict"] == "violation")
        rec["prediction_held"] = (rec["outcome"] == rec["expected"])
        results.append(rec)
    return results


def broker_integrity_checks(lockfile_path: str, upstream_host: str, upstream_port: int,
                            mock_base: str) -> list[dict]:
    """Structural checks for S5/S6/S7/S8 exercised directly on the broker."""
    checks = []

    def fresh_broker():
        return Broker(lockfile_path, upstream_host, upstream_port, transcript_path=None)

    # S6: upstream 302 for a pinned path -> broker must not follow, zero bytes.
    _http_get(mock_base + "/reset")
    _http_get(mock_base + "/redirect_pkg_on")
    b = fresh_broker()
    r = b.handle({"verb": "fetch", "ecosystem": "pypi", "name": "requests",
                  "version": "2.31.0", "artifact": "wheel"})
    checks.append({"control": "S6", "name": "no_redirect_followed",
                   "passed": (not r["ok"]) and r.get("reason") == "upstream_fail_closed",
                   "detail": r})
    # S7: oversize upstream body -> fail closed.
    _http_get(mock_base + "/reset")
    _http_get(mock_base + "/oversize_pkg_on")
    b = fresh_broker()
    r = b.handle({"verb": "fetch", "ecosystem": "pypi", "name": "urllib3",
                  "version": "2.2.1", "artifact": "wheel"})
    checks.append({"control": "S7", "name": "oversize_fail_closed",
                   "passed": (not r["ok"]), "detail": r})
    # S7 (headers): broker response never forwards upstream headers.
    _http_get(mock_base + "/reset")
    b = fresh_broker()
    r = b.handle({"verb": "fetch", "ecosystem": "pypi", "name": "numpy",
                  "version": "1.26.4", "artifact": "wheel"})
    checks.append({"control": "S7", "name": "no_upstream_headers_forwarded",
                   "passed": r["ok"] and set(r.keys()) <= {"ok", "sha256", "size", "data_b64", "served_from"},
                   "detail": {"keys": sorted(r.keys())}})
    # S5: poisoned pinned artifact -> digest mismatch, zero bytes.
    _http_get(mock_base + "/reset")
    _http_get(mock_base + "/poison_on")
    b = fresh_broker()
    r = b.handle({"verb": "fetch", "ecosystem": "pypi", "name": "click",
                  "version": "8.1.7", "artifact": "wheel"})
    checks.append({"control": "S5", "name": "digest_pin_holds",
                   "passed": (not r["ok"]) and r.get("reason") == "digest_mismatch",
                   "detail": r})
    # FUNCTIONALITY: SEP-1 is not "block everything" — a legitimate pinned fetch
    # must still succeed and match its digest (pre-empts the strawman objection).
    _http_get(mock_base + "/reset")
    b = fresh_broker()
    r = b.handle({"verb": "fetch", "ecosystem": "pypi", "name": "requests",
                  "version": "2.31.0", "artifact": "wheel"})
    checks.append({"control": "FUNC", "name": "legit_pinned_fetch_succeeds",
                   "passed": bool(r.get("ok")) and r.get("sha256") == b.entries["pypi:requests:2.31.0:wheel"]["sha256"],
                   "detail": {"ok": r.get("ok"), "size": r.get("size"), "served_from": r.get("served_from")}})
    _http_get(mock_base + "/reset")
    return checks


# --------------------------------------------------------------------------
# orchestration (local)
# --------------------------------------------------------------------------

def orchestrate_local(results_dir: str) -> dict:
    os.makedirs(results_dir, exist_ok=True)
    lockfile_path = os.path.join(ROOT, "lockfile.json")
    lf = load_lockfile(lockfile_path)
    policy_log = os.path.join(results_dir, "policy_monitor.log.jsonl")
    transcript_path = os.path.join(results_dir, "transcript.jsonl")
    for p in (policy_log, transcript_path):
        if os.path.exists(p):
            os.remove(p)

    procs = []
    try:
        # upstreams
        procs.append(_start(os.path.join(ROOT, "mock_cache", "mock_cache.py"),
                            {"MOCK_CACHE_PORT": MOCK_PORT, "MOCK_CACHE_HOST": "127.0.0.1"}))
        procs.append(_start(os.path.join(ROOT, "mock_cache", "mock_cache.py"),
                            {"MOCK_CACHE_PORT": ATTACKER_PORT, "MOCK_CACHE_HOST": "127.0.0.1"}))
        # allowlist proxy (Config A)
        procs.append(_start(os.path.join(ROOT, "allowlist_proxy", "allowlist_proxy.py"),
                            {"PROXY_PORT": PROXY_PORT, "ALLOWED_HOST": "127.0.0.1",
                             "ALLOWED_PORT": MOCK_PORT, "POLICY_LOG": policy_log}))
        mock_base = f"http://127.0.0.1:{MOCK_PORT}"
        assert _wait(mock_base + "/health"), "mock_cache did not start"
        assert _wait(f"http://127.0.0.1:{ATTACKER_PORT}/health"), "attacker upstream did not start"
        # proxy has no health page; probe it by a request through it shortly.
        time.sleep(0.4)

        # brokers (Config B): shared caching broker + no-cache measurement broker
        shared = Broker(lockfile_path, "127.0.0.1", MOCK_PORT, transcript_path=transcript_path)
        measure = Broker(lockfile_path, "127.0.0.1", MOCK_PORT, transcript_path=None, nocache=True)
        threading.Thread(target=serve, args=(shared, None, BROKER_TCP), daemon=True).start()
        threading.Thread(target=serve, args=(measure, None, MEASURE_BROKER_TCP), daemon=True).start()
        time.sleep(0.4)

        harness = Harness(mock_base)
        canary = "CANARY-" + sha256_hex(str(time.time()).encode())[:8]

        # ---- Config A ----
        harness.recv_reset()
        tA = AllowlistTransport("127.0.0.1", PROXY_PORT, "127.0.0.1", MOCK_PORT)
        ctxA = {"allowed_host": "127.0.0.1", "allowed_port": MOCK_PORT,
                "attacker_host": "127.0.0.1", "attacker_port": ATTACKER_PORT,
                "canary": canary, "harness": harness}
        resA = run_config("A", tA, ctxA, policy_log)

        # ---- Config B ----
        harness.recv_reset()
        tB = BrokerTransport(unix_path=None, tcp=("127.0.0.1", BROKER_TCP))
        measure_transport = BrokerTransport(unix_path=None, tcp=("127.0.0.1", MEASURE_BROKER_TCP))
        ctxB = {"allowed_host": "127.0.0.1", "allowed_port": MOCK_PORT,
                "attacker_host": "127.0.0.1", "attacker_port": ATTACKER_PORT,
                "canary": canary, "harness": harness,
                "measure": {"transport": measure_transport, "alphabet": COVERT_ALPHABET,
                            "recv_reset": harness.recv_reset,
                            "recv_reader": harness.recv_pkg_paths,
                            "min_interval": 0.05}}
        resB = run_config("B", tB, ctxB, policy_log)

        # ---- broker integrity structural checks (S5/S6/S7) ----
        integrity = broker_integrity_checks(lockfile_path, "127.0.0.1", MOCK_PORT, mock_base)

        # ---- Week-1: realistic eval workload + lockfile-completeness friction ----
        workload = run_friction_experiment(results_dir, "127.0.0.1", MOCK_PORT,
                                           WORKLOAD_BROKER_TCP, WORKLOAD_CLOSURE_BROKER_TCP)

        # ---- Week-3: multi-tenant broker isolation + per-tenant quotas ----
        tenancy = run_tenancy_checks(results_dir, "127.0.0.1", MOCK_PORT, TENANT_PORTS)

        # policy monitor overall compliance summary (Config A)
        pol = _read_lines(policy_log, 0)
        monitor_summary = {
            "total_connections": len(pol),
            "in_policy": sum(1 for p in pol if p["verdict"] == "in_policy"),
            "violation": sum(1 for p in pol if p["verdict"] == "violation"),
        }
        transcript_root = shared.transcript.root
    finally:
        for pr in procs:
            try:
                pr.terminate()
            except Exception:
                pass

    return assemble(lf, lockfile_path, transcript_path, transcript_root,
                    resA, resB, integrity, monitor_summary, "local", workload, tenancy)


def assemble(lf, lockfile_path, transcript_path, transcript_root,
             resA, resB, integrity, monitor_summary, mode, workload=None, tenancy=None) -> dict:
    suite_manifest = probes_mod.suite_manifest()
    try:
        commit = subprocess.check_output(["git", "-C", ROOT, "rev-parse", "--short", "HEAD"],
                                         stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        commit = "uncommitted"
    covert = next((r for r in resB if r["id"] == "covert_channel"), {})
    report = {
        "profile": PROFILE_VERSION,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "mode": mode,
        "lockfile_digest": lockfile_digest(lf),
        "probe_suite_digest": digest_json(suite_manifest),
        "probe_suite_manifest": suite_manifest,
        "transcript_root": transcript_root,
        "transcript_file": os.path.relpath(transcript_path, ROOT),
        "signature": sign_root(transcript_root),
        "config_A_allowlist": resA,
        "config_B_sep1": resB,
        "broker_integrity_checks": integrity,
        "policy_monitor_summary": monitor_summary,
        "channel_capacity": {
            "config_A": "unbounded (full-duplex byte channel to the on-list compromised host)",
            "config_B_bound_bits_per_hour": covert.get("channel_bits_per_hour"),
            "config_B_empirical_bits_per_hour": covert.get("empirical_bits_per_hour"),
            "config_B_measured_bits_per_hour": covert.get("channel_bits_per_hour"),
            "config_B_oneshot_ordering_bits_with_caching": covert.get("oneshot_ordering_bits_with_caching"),
            "config_B_bits_per_symbol": covert.get("bits_per_symbol"),
            "config_B_min_upstream_interval_s": covert.get("min_upstream_interval_s"),
            "config_B_symbols_recovered": f"{covert.get('symbols_recovered')}/{covert.get('symbols_sent')}",
        },
        "workload_eval": workload,
        "multi_tenant": tenancy,
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "cryptography_available": _has_crypto(),
            "git_commit": commit,
        },
    }
    return report


def _has_crypto() -> bool:
    try:
        import cryptography  # noqa
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------
# scoring / summary / verify
# --------------------------------------------------------------------------

def score(report: dict) -> dict:
    a = report["config_A_allowlist"]
    b = report["config_B_sep1"]
    exfil_A = sum(1 for r in a if r["achieved"])
    exfil_B = sum(1 for r in b if r["achieved"])
    headline = {
        "N_probes": len(a),
        "config_A_achieved": exfil_A,
        "config_B_achieved": exfil_B,
        "config_A_monitor_violations": report["policy_monitor_summary"]["violation"],
        "config_A_monitor_in_policy": report["policy_monitor_summary"]["in_policy"],
        "predictions_held_A": sum(1 for r in a if r["prediction_held"]),
        "predictions_held_B": sum(1 for r in b if r["prediction_held"]),
        "integrity_passed": sum(1 for c in report["broker_integrity_checks"] if c["passed"]),
        "integrity_total": len(report["broker_integrity_checks"]),
        "channel_bits_per_hour_B": report["channel_capacity"]["config_B_measured_bits_per_hour"],
    }
    return headline


def render_summary(report: dict) -> str:
    h = score(report)
    lines = ["# SEP-1 conformance summary\n",
             f"- profile: `{report['profile']}`  mode: `{report['mode']}`  generated: {report['generated']}",
             f"- lockfile_digest: `{report['lockfile_digest'][:16]}…`",
             f"- probe_suite_digest: `{report['probe_suite_digest'][:16]}…`",
             f"- transcript_root: `{report['transcript_root'][:16]}…`  ({report['signature']['scheme']})",
             "",
             "## Headline",
             f"- Config A (allowlist): **{h['config_A_achieved']}/{h['N_probes']}** probes achieved the adversary goal, "
             f"with **{h['config_A_monitor_violations']} policy violations** logged out of "
             f"{report['policy_monitor_summary']['total_connections']} monitored connections "
             f"({h['config_A_monitor_in_policy']} in-policy).",
             f"- Config B (SEP-1): **{h['config_B_achieved']}/{h['N_probes']}** probes achieved the adversary goal.",
             f"- Residual covert channel under B: **{h['channel_bits_per_hour_B']:,.0f} bits/hour** "
             f"(deterministic rate-limit bound; empirical {report['channel_capacity']['config_B_empirical_bits_per_hour']:,.0f}); "
             f"collapses to ~{report['channel_capacity']['config_B_oneshot_ordering_bits_with_caching']} bits one-shot with caching.",
             f"- Broker integrity checks: **{h['integrity_passed']}/{h['integrity_total']}** passed.",
             "",
             "## Per-probe: compliance telemetry vs probe outcome",
             "",
             "| probe | class | Config A outcome | A monitor verdicts | Config B outcome | pred. held |",
             "|-------|-------|------------------|--------------------|------------------|-----------|"]
    bmap = {r["id"]: r for r in report["config_B_sep1"]}
    for r in report["config_A_allowlist"]:
        b = bmap[r["id"]]
        mon = f"{r.get('monitor_in_policy',0)} in-policy / {r.get('monitor_violation',0)} viol"
        held = "✓" if (r["prediction_held"] and b["prediction_held"]) else "✗"
        lines.append(f"| {r['id']} | {r['class']} | {r['outcome']} | {mon} | {b['outcome']} | {held} |")
    lines += ["", "## Broker integrity (S5/S6/S7)", "",
              "| control | check | passed |", "|---------|-------|--------|"]
    for c in report["broker_integrity_checks"]:
        lines.append(f"| {c['control']} | {c['name']} | {'✓' if c['passed'] else '✗'} |")
    lines += render_workload(report.get("workload_eval"))
    lines += render_tenancy(report.get("multi_tenant"))
    return "\n".join(lines) + "\n"


def render_workload(w: dict | None) -> list[str]:
    if not w:
        return []
    e, c, f = w["error_driven"], w["closure_amend"], w["final_run"]
    phases = ", ".join(f"{k} {v}" for k, v in e["misses_by_phase"].items())
    lines = ["", "## Realistic eval workload behind the broker (lockfile friction)", "",
             f"- Project `{w['project']}`: closure of **{w['closure_size']}** pinned packages; "
             f"naive seed lockfile pins **{w['seed_entries']}** (direct runtime deps).",
             f"- Error-driven amendment: **{e['runs_to_green']} runs to green**, "
             f"**{e['fail_closed_runs']} fail-closed runs**, **{e['fail_closed_events']} fail-closed events** "
             f"({phases}); {e['amendments']} amendments; time to fix {e['time_to_fix_s']} s (wall clock).",
             f"- Closure amendment (`lockfile_amend --closure`): {c['amend_passes']} pass, "
             f"{c['added']} added, **{c['runs_to_green']} run to green**, {c['fail_closed_events']} fail-closed events.",
             f"- Final run: build {'ok' if f['build_ok'] else 'FAILED'}, tests {f['tests_passed']} passed / "
             f"{f['tests_failed']} failed, **{f['egress_attempts_outside_broker']} egress attempts outside the broker**.",
             f"- Amend safety: tampered upstream -> {w['amend_drift_check']['drift_detected']} drift reports, "
             f"{w['amend_drift_check']['added']} entries added.",
             "", "| run | phase failed closed | missing entries |", "|-----|---------------------|-----------------|"]
    for r in e["runs"]:
        miss = ", ".join(k.split(":")[1] for k in r["missing"]) or "—"
        lines.append(f"| {r['run']} | {r['phase_failed'] or 'green'} | {miss} |")
    return lines


def render_tenancy(m: dict | None) -> list[str]:
    if not m:
        return []
    lines = ["", "## Multi-tenant broker: isolation and per-tenant quotas", "",
             "| tenant | entries | quota / window | upstream attempts | quota_exceeded | per-tenant bound (bits/hour) |",
             "|--------|---------|----------------|-------------------|----------------|------------------------------|"]
    for t in m["tenants"]:
        cb = t["channel_bound"]
        lines.append(f"| {t['id']} | {cb['lockfile_entries']} | {t['quota']} / {t['window_s']:g} s | "
                     f"{t['upstream_attempts']} | {t['quota_exceeded']} | {cb['bits_per_hour_bound']:,} |")
    lines += ["", "| check | name | passed |", "|-------|------|--------|"]
    for c in m["checks"]:
        lines.append(f"| {c['id']} | {c['name']} | {'✓' if c['passed'] else '✗'} |")
    return lines


def verify(report_path: str) -> int:
    with open(report_path, "r", encoding="utf-8") as fh:
        report = json.load(fh)
    base = os.path.dirname(os.path.abspath(report_path))
    ok = True

    def check(label, cond):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {label}")
        ok = ok and cond

    print("Verifying conformance report (no lab-network access required):")
    # 1. transcript chain intact & root matches
    tpath = os.path.join(ROOT, report["transcript_file"])
    if not os.path.exists(tpath):
        tpath = os.path.join(base, os.path.basename(report["transcript_file"]))
    chain_ok, root, n = Transcript.verify_file(tpath)
    check(f"transcript hash-chain intact ({n} entries)", chain_ok)
    check("transcript root matches report", root == report["transcript_root"])
    # 2. lockfile digest matches the public lockfile
    lf = load_lockfile(os.path.join(ROOT, "lockfile.json"))
    check("lockfile digest matches public lockfile", lockfile_digest(lf) == report["lockfile_digest"])
    # 3. probe-suite digest matches the public probe suite
    check("probe-suite digest matches public probe suite",
          digest_json(probes_mod.suite_manifest()) == report["probe_suite_digest"])
    # 4. per-probe verdicts internally consistent with predictions
    held = all(r["prediction_held"] for r in report["config_A_allowlist"]) and \
        all(r["prediction_held"] for r in report["config_B_sep1"])
    check("every probe outcome matches its pre-declared expectation", held)
    # 5. channel capacity present & bounded
    cap = report["channel_capacity"]["config_B_measured_bits_per_hour"]
    check("residual channel capacity is present and finite", isinstance(cap, (int, float)))
    # 6. signature self-consistent
    check("signature verifies against transcript root",
          verify_signature(report["transcript_root"], report["signature"]))
    # 7. realistic eval workload (Week-1 follow-up), if present
    w = report.get("workload_eval")
    if w:
        verify_workload(w, base, check)
    else:
        print("  [SKIP] no workload_eval section in this report")
    # 8. multi-tenant broker (Week-3 follow-up), if present
    m = report.get("multi_tenant")
    if m:
        verify_tenancy(m, check)
    else:
        print("  [SKIP] no multi_tenant section in this report")
    print(f"\nRESULT: {'VERIFIED' if ok else 'FAILED'}")
    return 0 if ok else 1


def verify_workload(w: dict, base: str, check) -> None:
    e = w["error_driven"]
    tpath = os.path.join(ROOT, e["transcript_file"])
    if not os.path.exists(tpath):
        tpath = os.path.join(base, "workload", os.path.basename(e["transcript_file"]))
    chain_ok, root, n = Transcript.verify_file(tpath)
    check(f"workload transcript hash-chain intact ({n} entries)", chain_ok)
    check("workload transcript root matches report", root == e["transcript_root"])
    misses, loads = 0, []
    with open(tpath, "r", encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            p = json.loads(line)["payload"]
            misses += p.get("verdict") == "lockfile_miss"
            if p.get("event") == "lockfile_loaded":
                loads.append(p["lockfile_digest"])
    check(f"fail-closed events in transcript ({misses}) match report", misses == e["fail_closed_events"])
    public = lockfile_digest(load_lockfile(os.path.join(ROOT, w["public_lockfile"])))
    check("workload lockfile digest matches public workload lockfile",
          public == w["public_lockfile_digest"])
    check("amended lockfile (last load in transcript) == public workload lockfile",
          bool(loads) and loads[-1] == e["lockfile_digest_final"] == public)
    check("closure amendment reaches the same lockfile in one pass",
          w["closure_amend"]["lockfile_digest_final"] == public and w["closure_amend"]["runs_to_green"] == 1)
    f = w["final_run"]
    check("eval task green behind the broker (build ok, all tests pass)",
          f["ok"] and f["build_ok"] and f["tests_failed"] == 0 and f["tests_passed"] > 0)
    check("no egress attempted outside the broker during build/test",
          f["egress_attempts_outside_broker"] == 0)
    check("lockfile-amend refuses to re-pin a tampered upstream", w["amend_drift_check"]["passed"])


def verify_tenancy(m: dict, check) -> None:
    import math
    with open(os.path.join(ROOT, m["config"]), "r", encoding="utf-8") as fh:
        cfg = {t["id"]: t for t in json.load(fh)}
    check("tenant set matches public tenant config", sorted(cfg) == sorted(t["id"] for t in m["tenants"]))
    for t in m["tenants"]:
        tid, c = t["id"], cfg.get(t["id"], {})
        tpath = os.path.join(ROOT, t["transcript_file"])
        chain_ok, root, n = Transcript.verify_file(tpath)
        check(f"[{tid}] transcript hash-chain intact ({n} entries), root matches",
              chain_ok and root == t["transcript_root"])
        lf = load_lockfile(os.path.join(ROOT, c.get("lockfile", t["lockfile"])))
        scan = scan_tenant_transcript(tpath)
        bound = [x for x in scan["notes"] if x.get("event") == "tenant_bound"]
        loads = [x["lockfile_digest"] for x in scan["notes"] if x.get("event") == "lockfile_loaded"]
        check(f"[{tid}] transcript bound to this tenant with the public quota",
              len(bound) == 1 and bound[0]["tenant"] == tid and bound[0]["quota"] == c.get("quota")
              and bound[0]["window_s"] == c.get("window_s"))
        check(f"[{tid}] lockfile in transcript == public tenant lockfile",
              loads == [lockfile_digest(lf)] == [t["lockfile_digest"]])
        check(f"[{tid}] every served entry is in this tenant's own lockfile",
              all(k in lf["entries"] for k in scan["served"]))
        peak = max_in_window(scan["upstream_ts"], c.get("window_s", 0))
        check(f"[{tid}] upstream fetches per window ({peak}) within quota ({c.get('quota')})",
              peak <= c.get("quota", -1) and peak == t["upstream_attempts"])
        n_e = max(len(lf["entries"]), 1)
        per = math.log2(n_e) + math.log2(max(c.get("window_s", 0) / MIN_UPSTREAM_INTERVAL, 1.0))
        check(f"[{tid}] per-tenant channel bound recomputes from public config",
              abs(t["channel_bound"]["bits_per_window_bound"] - round(c.get("quota", 0) * per, 1)) < 0.11)
    check("all isolation and quota checks passed", all(x["passed"] for x in m["checks"]))


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def cmd_run(args) -> int:
    results_dir = os.path.join(ROOT, "results")
    if args.docker:
        print("Docker mode: use `docker compose run --rm sole_verify` (see README). "
              "Falling back to local orchestration here.")
    report = orchestrate_local(results_dir)
    with open(os.path.join(results_dir, "conformance-report.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    summary = render_summary(report)
    with open(os.path.join(results_dir, "summary.md"), "w", encoding="utf-8") as fh:
        fh.write(summary)
    print(summary)
    print(f"\nWrote results/conformance-report.json and results/summary.md")
    return 0


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # Windows consoles default to cp1252
    except Exception:
        pass
    ap = argparse.ArgumentParser(prog="sole-verify")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--all", action="store_true")
    r.add_argument("--local", action="store_true")
    r.add_argument("--docker", action="store_true")
    r.set_defaults(func=cmd_run)
    v = sub.add_parser("verify")
    v.add_argument("report")
    v.set_defaults(func=lambda a: verify(a.report))
    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
