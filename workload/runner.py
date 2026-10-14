"""Eval task runner: resolve -> build -> test a dependency-heavy project with the
SEP-1 broker as its ONLY dependency source (Week-1 follow-up).

Runs inside the sandbox. It is handed a BrokerTransport and nothing else: every
artifact comes from `transport.fetch(eco, name, ver, art)`, and the build and
test steps run in isolated child interpreters (`-I`) with an audit hook that
refuses and counts any socket/DNS/urllib egress, so a green run demonstrates the
real build+test loop needs no network beyond the broker.

Phases mirror a CI job:
  resolve  runtime closure of manifest["requires"]
  build    closure of manifest["build_requires"], then the build backend
  test     closure of manifest["test_requires"], then the test suite
Resolution is breadth-first in sorted order (deterministic). A missing entry is
fail-closed at the broker (`lockfile_miss`); the runner records every miss on the
reachable frontier of the failing phase and stops, exactly like a CI job would.

CLI (standalone use against a running broker):
  python workload/runner.py --broker-tcp 127.0.0.1:8092 [--project workload/project]
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for p in (ROOT, os.path.join(ROOT, "probes")):
    if p not in sys.path:
        sys.path.insert(0, p)

from workload.wheelmeta import parse_req, requires_of, safe_extract  # noqa: E402

ECO, ART = "pypi", "wheel"
PHASES = (("resolve", "requires"), ("build", "build_requires"), ("test", "test_requires"))
DEFAULT_PROJECT = os.path.join(HERE, "project")

# Prepended to every build/test child: refuse and count egress that bypasses the
# broker. Audit hooks cannot be removed once installed.
EGRESS_GUARD = r'''
import sys as _sys
_EGRESS = []
def _no_egress(event, args):
    if event in ("socket.connect", "socket.getaddrinfo", "socket.gethostbyname",
                 "socket.sendto", "urllib.Request"):
        _EGRESS.append(event)
        raise PermissionError("SEP-1 sandbox: no egress outside the broker (" + event + ")")
_sys.addaudithook(_no_egress)
'''

BUILD_CODE = r'''
import json
from fx_buildcore import build
out = build(SRC, DIST)
print(json.dumps({"ok": True, "files": out["files"], "egress_attempts": len(_EGRESS)}))
'''

TEST_CODE = r'''
import json
from fx_minitest import run_path
res = run_path(TESTS)
res["egress_attempts"] = len(_EGRESS)
print(json.dumps(res))
'''


def key(name: str, ver: str) -> str:
    return f"{ECO}:{name}:{ver}:{ART}"


def resolve(transport, roots, have: dict, stats: dict) -> list[dict]:
    """Fetch the closure of `roots` via the broker into `have`; return misses."""
    misses = []
    queue = sorted(roots)            # (name, version, required_by)
    seen = set()
    while queue:
        name, ver, parent = queue.pop(0)
        k = key(name, ver)
        if k in have or k in seen:
            continue
        seen.add(k)
        r = transport.fetch(ECO, name, ver, ART)
        stats["broker_fetches"] += 1
        if not r.get("ok"):
            misses.append({"key": k, "reason": r.get("reason"), "required_by": parent})
            continue
        have[k] = r["data"]
        queue.extend((n, v, name) for n, v in requires_of(r["data"]))
    return misses


def _child(code: str, paths: list[str], consts: dict, cwd: str) -> dict:
    prelude = EGRESS_GUARD + f"\n_sys.path[:0] = {paths!r}\n"
    prelude += "".join(f"{k} = {v!r}\n" for k, v in consts.items())
    p = subprocess.run([sys.executable, "-I", "-c", prelude + code], cwd=cwd,
                       capture_output=True, text=True, timeout=120)
    lines = [ln for ln in p.stdout.splitlines() if ln.strip()]
    if p.returncode != 0 or not lines:
        return {"ok": False, "error": (p.stderr or p.stdout)[-2000:]}
    return json.loads(lines[-1])


def run_task(transport, project_dir: str = DEFAULT_PROJECT, work_dir: str | None = None) -> dict:
    with open(os.path.join(project_dir, "manifest.json"), "r", encoding="utf-8") as fh:
        manifest = json.load(fh)
    t0 = time.time()
    own = work_dir is None
    work = work_dir or tempfile.mkdtemp(prefix="sep1-workload-")
    site, dist = os.path.join(work, "site"), os.path.join(work, "dist")
    stats = {"broker_fetches": 0}
    have: dict[str, bytes] = {}
    installed: set[str] = set()
    result = {"project": f"{manifest['name']} {manifest['version']}", "ok": False,
              "phase_failed": None, "misses": [], "phases": {},
              "egress_attempts_outside_broker": 0}
    try:
        for phase, group in PHASES:
            roots = [parse_req(r) + (manifest["name"],) for r in manifest.get(group, [])]
            misses = resolve(transport, roots, have, stats)
            info = {"closure_so_far": len(have)}
            result["phases"][phase] = info
            if misses:
                result["phase_failed"], result["misses"] = phase, misses
                info["status"] = "fail_closed"
                return result
            for k in sorted(have):
                if k not in installed:
                    safe_extract(have[k], site)
                    installed.add(k)
            if phase == "build":
                out = _child(BUILD_CODE, [site], {
                    "SRC": os.path.join(project_dir, manifest.get("src", "src")),
                    "DIST": dist}, work)
                result["egress_attempts_outside_broker"] += out.get("egress_attempts", 0)
                info.update(status="ok" if out.get("ok") else "build_error", built_files=out.get("files"))
                if not out.get("ok"):
                    result["phase_failed"], info["error"] = phase, out.get("error")
                    return result
            elif phase == "test":
                out = _child(TEST_CODE, [dist, site], {
                    "TESTS": os.path.join(project_dir, manifest["tests"])}, work)
                result["egress_attempts_outside_broker"] += out.get("egress_attempts", 0)
                info.update(passed=out.get("passed", 0), failed=out.get("failed", 0),
                            failures=out.get("failures", []))
                ok = "passed" in out and out["failed"] == 0 and out["passed"] > 0
                info["status"] = "ok" if ok else "test_failure"
                if not ok:
                    result["phase_failed"] = phase
                    info.setdefault("error", out.get("error"))
                    return result
            else:
                info["status"] = "ok"
        result["ok"] = True
        return result
    finally:
        result["installed"] = len(installed)
        result["broker_fetches"] = stats["broker_fetches"]
        result["elapsed_s"] = round(time.time() - t0, 3)
        if own:
            shutil.rmtree(work, ignore_errors=True)


def main(argv=None) -> int:
    from transport import BrokerTransport
    ap = argparse.ArgumentParser(prog="workload-runner")
    ap.add_argument("--broker-socket")
    ap.add_argument("--broker-tcp", help="host:port")
    ap.add_argument("--project", default=DEFAULT_PROJECT)
    a = ap.parse_args(argv)
    tcp = None
    if a.broker_tcp:
        h, p = a.broker_tcp.rsplit(":", 1)
        tcp = (h, int(p))
    res = run_task(BrokerTransport(unix_path=a.broker_socket, tcp=tcp), a.project)
    print(json.dumps(res, indent=2))
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
