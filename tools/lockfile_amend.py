"""lockfile-amend — grow a SEP-1 lockfile between runs, on the lab side.

SEP-1 fails closed on a missing dependency (S4/S8). This tool is the sanctioned
way to fix that: run by the lab, OUTSIDE the sandbox and BETWEEN runs, it pins
the missing entries (SHA-256 + size) from the lab's resolve source and appends an
amendment record. It never runs inside a live sandbox — an auto-amending broker
would be live resolution, i.e. the open door S4 exists to close.

Sources of keys to add:
  --keys K [K ...]            explicit lock keys (eco:name:version:artifact)
  --from-transcript T.jsonl   `lockfile_miss` verdicts the BROKER recorded since
                              the last lockfile load (broker-side, not the
                              sandbox's own claim of what it needed)
  --manifest M.json [--groups requires,build_requires,test_requires]
                              the project's own declared roots (lab-controlled;
                              the recommended path, use with --closure)
  --closure                   follow each wheel's Requires-Dist to a full closure,
                              so one amendment fixes the lockfile in one pass

Safety properties:
  * Append-only for pins: an already-pinned key is never re-pinned. In --closure
    mode existing entries are re-fetched only to read their requirements, and if
    the upstream bytes no longer match the pin the key is reported as DRIFT and
    its subtree is not followed (a tampered upstream cannot smuggle new deps in).
  * Trust-on-first-use is stated, not hidden: new pins trust the lab's resolve
    source at amend time. `--expect DIGESTS.json` cross-checks new pins against an
    independent digest list (e.g. hashes published by the index) and refuses any
    mismatch.
  * Sandbox-reported misses are untrusted input: every amendment prints a diff
    for review; nothing about the miss list widens the grammar or the upstream.

Usage:
  python tools/lockfile_amend.py --lockfile L.json --from-transcript T.jsonl --upstream 127.0.0.1:8080
  python tools/lockfile_amend.py --lockfile L.json --manifest workload/project/manifest.json --closure --upstream 127.0.0.1:8080
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from sole_egress_common import (  # noqa: E402
    PROFILE_VERSION, GrammarError, lock_key, lockfile_digest, parse_fetch, sha256_hex,
)
from workload.wheelmeta import parse_req, requires_of  # noqa: E402

MAX_BYTES = 1024 * 1024
ALL_GROUPS = ("requires", "build_requires", "test_requires")


def split_key(k: str) -> tuple[str, str, str, str]:
    parts = k.split(":")
    if len(parts) != 4:
        raise GrammarError(f"bad lock key {k!r}")
    eco, name, ver, art = parts
    # Same closed grammar as the broker: a key that could not be fetched cannot be pinned.
    return parse_fetch({"verb": "fetch", "ecosystem": eco, "name": name,
                        "version": ver, "artifact": art})


def upstream_path(eco: str, name: str, ver: str, art: str) -> str:
    return f"/pkg/{eco}/{name}/{ver}/{art}"


def fetch_upstream(upstream: tuple[str, int], path: str) -> bytes | None:
    try:
        conn = http.client.HTTPConnection(upstream[0], upstream[1], timeout=10)
        conn.request("GET", path)
        resp = conn.getresponse()
        data = resp.read(MAX_BYTES + 1)
        conn.close()
        if resp.status != 200 or len(data) > MAX_BYTES:
            return None
        return data
    except Exception:
        return None


def load_or_init(path: str) -> dict:
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            lf = json.load(fh)
        if lf.get("profile") != PROFILE_VERSION:
            raise SystemExit(f"{path}: lockfile profile mismatch")
        return lf
    return {"profile": PROFILE_VERSION, "generated_note": "pre-resolved closure; public",
            "entries": {}}


def manifest_keys(manifest_path: str, groups=ALL_GROUPS) -> list[str]:
    with open(manifest_path, "r", encoding="utf-8") as fh:
        m = json.load(fh)
    keys = []
    for g in groups:
        for spec in m.get(g, []):
            name, ver = parse_req(spec)
            keys.append(lock_key("pypi", name, ver, "wheel"))
    return keys


def misses_from_transcript(path: str) -> list[str]:
    """`lockfile_miss` keys recorded by the broker since its last lockfile load."""
    keys: list[str] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            e = json.loads(line)
            p = e["payload"]
            if e["kind"] == "note" and p.get("event") == "lockfile_loaded":
                keys = []
            elif e["kind"] == "verdict" and p.get("verdict") == "lockfile_miss":
                if p["key"] not in keys:
                    keys.append(p["key"])
    return keys


def amend(lockfile_path: str, keys: list[str], upstream: tuple[str, int], *,
          closure: bool = False, out_path: str | None = None, reason: str = "",
          expect: dict | None = None, dry_run: bool = False) -> dict:
    lf = load_or_init(lockfile_path)
    entries = lf["entries"]
    before = lockfile_digest(lf)
    added, drift, unresolved, refused, seen = [], [], [], [], set()
    queue = list(keys)
    while queue:
        k = queue.pop(0)
        if k in seen:
            continue
        seen.add(k)
        eco, name, ver, art = split_key(k)
        pinned = entries.get(k)
        if pinned and not closure:
            continue                                   # already pinned; nothing to do
        path = upstream_path(eco, name, ver, art)
        data = fetch_upstream(upstream, path)
        if data is None:
            unresolved.append(k)
            continue
        digest = sha256_hex(data)
        if pinned:
            if digest != pinned["sha256"]:
                drift.append({"key": k, "pinned": pinned["sha256"], "upstream": digest})
                continue                               # never re-pin, never follow
        else:
            if expect is not None and expect.get(k) != digest:
                refused.append({"key": k, "upstream": digest, "expected": expect.get(k)})
                continue
            entries[k] = {"path": path, "sha256": digest, "size": len(data)}
            added.append(k)
        if closure and eco == "pypi" and art == "wheel":
            queue.extend(lock_key("pypi", n, v, "wheel") for n, v in requires_of(data))
    lf["entries"] = dict(sorted(entries.items()))
    after = lockfile_digest(lf)
    record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "reason": reason, "method": "cross-checked" if expect is not None
              else "tofu-lab-resolve-at-amend-time",
              "closure": closure, "added": added,
              "lockfile_digest_before": before, "lockfile_digest_after": after}
    if added:
        lf.setdefault("amendments", []).append(record)
    if not dry_run:
        with open(out_path or lockfile_path, "w", encoding="utf-8") as fh:
            json.dump(lf, fh, indent=2, sort_keys=True)
            fh.write("\n")
    return {"added": added, "drift": drift, "unresolved": unresolved, "refused": refused,
            "entries": len(entries), "lockfile_digest_before": before,
            "lockfile_digest_after": after,
            "diff": [f"+ {k}  sha256={entries[k]['sha256'][:16]}..  size={entries[k]['size']}"
                     for k in added]}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="lockfile-amend", description=__doc__.split("\n")[0])
    ap.add_argument("--lockfile", required=True)
    ap.add_argument("--out")
    ap.add_argument("--upstream", required=True, help="host:port of the lab's resolve source")
    ap.add_argument("--keys", nargs="*", default=[])
    ap.add_argument("--from-transcript")
    ap.add_argument("--manifest")
    ap.add_argument("--groups", default=",".join(ALL_GROUPS))
    ap.add_argument("--closure", action="store_true")
    ap.add_argument("--expect", help="JSON {lock_key: sha256} independent digest list")
    ap.add_argument("--reason", default="")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args(argv)
    keys = list(a.keys)
    if a.from_transcript:
        keys += misses_from_transcript(a.from_transcript)
    if a.manifest:
        keys += manifest_keys(a.manifest, [g for g in a.groups.split(",") if g])
    expect = None
    if a.expect:
        with open(a.expect, "r", encoding="utf-8") as fh:
            expect = json.load(fh)
    h, p = a.upstream.rsplit(":", 1)
    res = amend(a.lockfile, keys, (h, int(p)), closure=a.closure, out_path=a.out,
                reason=a.reason, expect=expect, dry_run=a.dry_run)
    for line in res["diff"]:
        print(line)
    for d in res["drift"]:
        print(f"! DRIFT {d['key']}: pinned {d['pinned'][:16]}.. upstream {d['upstream'][:16]}.. (not re-pinned)")
    for r in res["refused"]:
        print(f"! REFUSED {r['key']}: upstream digest does not match --expect")
    for k in res["unresolved"]:
        print(f"! UNRESOLVED {k}")
    print(f"{len(res['added'])} added, {len(res['drift'])} drift, {len(res['refused'])} refused, "
          f"{len(res['unresolved'])} unresolved; {res['entries']} entries; "
          f"digest {res['lockfile_digest_before'][:12]}.. -> {res['lockfile_digest_after'][:12]}.."
          + (" (dry run)" if a.dry_run else ""))
    return 1 if (res["drift"] or res["refused"] or res["unresolved"]) else 0


if __name__ == "__main__":
    sys.exit(main())
