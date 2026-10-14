"""Lockfile-completeness friction experiment (Week-1 follow-up).

Starting from a naive seed lockfile that pins only the project's direct runtime
dependencies (what a lab gets from hash-pinning its top-level requirements), we
measure what it costs to get a realistic eval task green behind SEP-1:

  error-driven  run -> fail closed -> amend exactly the misses the BROKER logged
                -> reload -> rerun, until green. One broker, one hash-chained
                transcript across all runs; every lockfile load is a transcript
                note, every miss a `lockfile_miss` verdict.
  closure       one `lockfile_amend --manifest --closure` pass from the
                project's declared roots, then a single run.

Plus a safety check on the amend tool itself: with the upstream tampering bytes,
a closure amend over the complete lockfile must report drift and add nothing.

Counts (runs, fail-closed events, missing deps per phase) are deterministic; wall
clock "time to fix" is reported but is environment-dependent (D10 discipline).
"""
from __future__ import annotations

import json
import os
import shutil
import threading
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

from sole_egress_common import load_lockfile, lockfile_digest  # noqa: E402
from broker import Broker, serve  # noqa: E402
from transport import BrokerTransport  # noqa: E402
from workload.runner import DEFAULT_PROJECT, run_task  # noqa: E402
from tools.lockfile_amend import amend, manifest_keys, misses_from_transcript  # noqa: E402

SEED_LOCKFILE = os.path.join(HERE, "lockfile.seed.json")
PUBLIC_LOCKFILE = os.path.join(HERE, "lockfile.json")
MAX_RUNS = 30


def _mock(base: str, path: str) -> None:
    with urllib.request.urlopen(base + path, timeout=5) as r:
        r.read()


def _serve(broker: Broker, port: int) -> BrokerTransport:
    threading.Thread(target=serve, args=(broker, None, port), daemon=True).start()
    time.sleep(0.3)
    return BrokerTransport(unix_path=None, tcp=("127.0.0.1", port))


def _final_view(res: dict) -> dict:
    test = res["phases"].get("test", {})
    return {"ok": res["ok"], "project": res["project"],
            "build_ok": res["phases"].get("build", {}).get("status") == "ok",
            "tests_passed": test.get("passed", 0), "tests_failed": test.get("failed", 0),
            "egress_attempts_outside_broker": res["egress_attempts_outside_broker"],
            "installed_packages": res["installed"], "broker_fetches": res["broker_fetches"],
            "elapsed_s": res["elapsed_s"]}


def run_friction_experiment(results_dir: str, upstream_host: str, upstream_port: int,
                            port_iterative: int, port_closure: int) -> dict:
    out_dir = os.path.join(results_dir, "workload")
    os.makedirs(out_dir, exist_ok=True)
    upstream = (upstream_host, upstream_port)
    mock_base = f"http://{upstream_host}:{upstream_port}"
    _mock(mock_base, "/reset")
    seed = load_lockfile(SEED_LOCKFILE)

    # ---- error-driven amendment loop ----
    live = os.path.join(out_dir, "lockfile.json")
    shutil.copyfile(SEED_LOCKFILE, live)
    tpath = os.path.join(out_dir, "transcript.jsonl")
    if os.path.exists(tpath):
        os.remove(tpath)
    broker = Broker(live, upstream_host, upstream_port, transcript_path=tpath)
    broker.note_lockfile("seed: direct runtime dependencies only")
    transport = _serve(broker, port_iterative)

    runs, final, agree = [], None, True
    t0 = time.time()
    for i in range(1, MAX_RUNS + 1):
        res = run_task(transport, DEFAULT_PROJECT)
        reported = [m["key"] for m in res["misses"]]
        runs.append({"run": i, "ok": res["ok"], "phase_failed": res["phase_failed"],
                     "missing": reported, "elapsed_s": res["elapsed_s"]})
        if res["ok"] or not reported:
            final = res
            break
        logged = misses_from_transcript(tpath)          # broker-side record
        agree = agree and sorted(logged) == sorted(reported)
        amend(live, logged, upstream,
              reason=f"run {i}: {res['phase_failed']} phase failed closed")
        broker.reload_lockfile(live, reason=f"amended after run {i}")
    time_to_fix = time.time() - t0

    by_phase: dict[str, int] = {}
    for r in runs:
        if r["phase_failed"]:
            by_phase[r["phase_failed"]] = by_phase.get(r["phase_failed"], 0) + len(r["missing"])
    fail_closed_events = 0
    with open(tpath, "r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip() and json.loads(line)["payload"].get("verdict") == "lockfile_miss":
                fail_closed_events += 1
    lf_final = load_lockfile(live)

    # ---- closure amendment: one pass from the manifest ----
    live_c = os.path.join(out_dir, "lockfile.closure.json")
    shutil.copyfile(SEED_LOCKFILE, live_c)
    t1 = time.time()
    am = amend(live_c, manifest_keys(os.path.join(DEFAULT_PROJECT, "manifest.json")), upstream,
               closure=True, reason="closure from project manifest (all groups)")
    broker_c = Broker(live_c, upstream_host, upstream_port, transcript_path=None)
    res_c = run_task(_serve(broker_c, port_closure), DEFAULT_PROJECT)
    time_c = time.time() - t1
    lf_closure = load_lockfile(live_c)

    # ---- amend-tool safety: tampered upstream must not re-pin or extend ----
    _mock(mock_base, "/reset")
    _mock(mock_base, "/poison_on")
    probe = amend(PUBLIC_LOCKFILE, manifest_keys(os.path.join(DEFAULT_PROJECT, "manifest.json")),
                  upstream, closure=True, dry_run=True, reason="drift check")
    _mock(mock_base, "/reset")

    public = load_lockfile(PUBLIC_LOCKFILE)
    return {
        "project": res_c["project"],
        "public_lockfile": os.path.relpath(PUBLIC_LOCKFILE, ROOT).replace(os.sep, "/"),
        "public_lockfile_digest": lockfile_digest(public),
        "closure_size": len(public["entries"]),
        "seed_entries": len(seed["entries"]),
        "error_driven": {
            "runs_to_green": len(runs) if final and final["ok"] else None,
            "fail_closed_runs": sum(1 for r in runs if not r["ok"]),
            "fail_closed_events": fail_closed_events,
            "missing_deps_total": sum(len(r["missing"]) for r in runs),
            "misses_by_phase": by_phase,
            "amendments": len(lf_final.get("amendments", [])) - len(seed.get("amendments", [])),
            "sandbox_report_matches_transcript": agree,
            "time_to_fix_s": round(time_to_fix, 2),
            "runs": runs,
            "lockfile_digest_final": lockfile_digest(lf_final),
            "transcript_file": os.path.relpath(tpath, ROOT).replace(os.sep, "/"),
            "transcript_root": broker.transcript.root,
        },
        "closure_amend": {
            "amend_passes": 1,
            "added": len(am["added"]),
            "runs_to_green": 1 if res_c["ok"] else None,
            "fail_closed_events": len(res_c["misses"]),
            "time_to_fix_s": round(time_c, 2),
            "lockfile_digest_final": lockfile_digest(lf_closure),
        },
        "final_run": _final_view(final or res_c),
        "amend_drift_check": {
            "upstream_tampered": True,
            "drift_detected": len(probe["drift"]),
            "added": len(probe["added"]),
            "passed": len(probe["drift"]) > 0 and not probe["added"],
        },
    }
