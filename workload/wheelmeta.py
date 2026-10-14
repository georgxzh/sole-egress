"""Minimal, stdlib-only reader for the fixture wheels (zip + dist-info/METADATA).

Shared by the in-sandbox task runner (to discover transitive requirements of a
fetched artifact) and the lab-side lockfile-amend tool (to compute a closure).
SEP-1's grammar has no version ranges, so only exact `name==version` pins are
resolvable; anything else is a lock-time problem, not a run-time one.
"""
from __future__ import annotations

import io
import os
import re
import zipfile

_REQ = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9][A-Za-z0-9.+_-]*)$")


def parse_req(spec: str) -> tuple[str, str]:
    m = _REQ.match(spec.strip())
    if not m:
        raise ValueError(f"only exact 'name==version' pins are resolvable under SEP-1: {spec!r}")
    return m.group(1), m.group(2)


def metadata(data: bytes) -> str:
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        names = [n for n in z.namelist() if n.endswith(".dist-info/METADATA")]
        if len(names) != 1:
            raise ValueError("artifact must contain exactly one dist-info/METADATA")
        return z.read(names[0]).decode("utf-8")


def requires_of(data: bytes) -> list[tuple[str, str]]:
    """Exact-pinned runtime requirements declared by a wheel, sorted."""
    out = []
    for line in metadata(data).splitlines():
        if line.startswith("Requires-Dist:"):
            out.append(parse_req(line.split(":", 1)[1]))
    return sorted(out)


def safe_extract(data: bytes, dest: str) -> list[str]:
    """Extract a wheel into `dest`, refusing absolute or parent-relative members."""
    os.makedirs(dest, exist_ok=True)
    root = os.path.realpath(dest)
    written = []
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for member in z.namelist():
            target = os.path.realpath(os.path.join(root, member))
            if os.path.isabs(member) or ".." in member.split("/") or \
                    os.path.commonpath([root, target]) != root:
                raise ValueError(f"unsafe archive member: {member!r}")
            z.extract(member, root)
            written.append(member)
    return written
