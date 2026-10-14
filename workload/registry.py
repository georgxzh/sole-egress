"""Benign fixture registry for the Week-1 eval workload.

Seventeen tiny, pure-Python packages (CSV parsing, statistics, text tables, a
build backend, a test helper) with a realistic transitive dependency graph across
three groups: runtime, build-backend and test-extra. They are served by the mock
upstream at /pkg/pypi/<name>/<version>/wheel exactly like the main fixtures, and
are deliberately NOT part of the main lockfile (they have their own, see
workload/lockfile.json), so the headline SEP-1 numbers are unaffected.

Artifacts are byte-deterministic zips (fixed timestamps, fixed create_system,
ZIP_STORED) so their SHA-256 pins are stable on every OS. Nothing here touches
the network or any real package index; the names carry an `fx-` prefix so they
cannot be confused with real distributions.
"""
from __future__ import annotations

import io
import zipfile

VERSIONS: dict[str, str] = {
    # runtime
    "fx-strutil": "1.2.0",
    "fx-text": "1.0.3",
    "fx-iterutil": "0.8.0",
    "fx-csvparse": "2.1.0",
    "fx-mathcore": "0.5.1",
    "fx-numeric": "1.3.0",
    "fx-stats": "1.4.2",
    "fx-tables-data": "15.1.0",
    "fx-unicodewidth": "0.2.6",
    "fx-colwidth": "1.0.0",
    "fx-table": "0.9.1",
    # build backend
    "fx-hashing": "2.0.0",
    "fx-manifest": "1.1.4",
    "fx-buildcore": "3.0.1",
    # test extras
    "fx-diffutil": "0.4.0",
    "fx-assertutil": "1.0.2",
    "fx-minitest": "1.1.0",
}

REQUIRES: dict[str, list[str]] = {
    "fx-text": ["fx-strutil"],
    "fx-csvparse": ["fx-text", "fx-iterutil"],
    "fx-numeric": ["fx-mathcore"],
    "fx-stats": ["fx-numeric", "fx-iterutil"],
    "fx-unicodewidth": ["fx-tables-data"],
    "fx-colwidth": ["fx-unicodewidth"],
    "fx-table": ["fx-text", "fx-colwidth"],
    "fx-manifest": ["fx-hashing"],
    "fx-buildcore": ["fx-manifest"],
    "fx-diffutil": ["fx-strutil"],
    "fx-assertutil": ["fx-diffutil"],
    "fx-minitest": ["fx-assertutil"],
}

SOURCES: dict[str, str] = {
    "fx-strutil": '''
def squeeze(s):
    """Collapse runs of whitespace to single spaces and trim."""
    return " ".join(str(s).split())


def pad(s, width, cur=None, align="left"):
    """Pad `s` to `width` display columns; `cur` is its current display width."""
    s = str(s)
    gap = max(0, width - (len(s) if cur is None else cur))
    return s + " " * gap if align == "left" else " " * gap + s
''',
    "fx-text": '''
from fx_strutil import squeeze, pad  # noqa: F401  (pad re-exported)


def normalize_cell(s):
    return squeeze(s)


def is_blank(s):
    return not squeeze(s)
''',
    "fx-iterutil": '''
def transpose(rows):
    return [list(c) for c in zip(*rows)]


def compact(xs):
    return [x for x in xs if x is not None]
''',
    "fx-csvparse": '''
import csv
import io

from fx_iterutil import transpose
from fx_text import is_blank, normalize_cell


def parse(text):
    rows = [[normalize_cell(c) for c in r] for r in csv.reader(io.StringIO(text))]
    rows = [r for r in rows if r and not all(is_blank(c) for c in r)]
    if not rows:
        return [], []
    return rows[0], rows[1:]


def columns(text):
    header, rows = parse(text)
    if not rows:
        return {h: [] for h in header}
    return dict(zip(header, transpose(rows)))
''',
    "fx-mathcore": '''
import math


def fsum(xs):
    return math.fsum(xs)


def sqrt(x):
    return math.sqrt(x)
''',
    "fx-numeric": '''
from fx_mathcore import fsum, sqrt


def to_float(s):
    try:
        return float(s)
    except (TypeError, ValueError):
        return None


def mean(xs):
    return fsum(xs) / len(xs)


def stdev(xs):
    """Sample standard deviation."""
    if len(xs) < 2:
        return 0.0
    m = mean(xs)
    return sqrt(fsum((x - m) ** 2 for x in xs) / (len(xs) - 1))
''',
    "fx-stats": '''
from fx_iterutil import compact
from fx_numeric import mean, stdev, to_float


def describe(values):
    xs = compact(to_float(v) for v in values)
    if not xs:
        return {"count": 0}
    return {"count": len(xs), "mean": mean(xs), "stdev": stdev(xs),
            "min": min(xs), "max": max(xs)}
''',
    "fx-tables-data": '''
# (start, end) code-point ranges rendered double-width in a terminal (subset).
WIDE = (
    (0x1100, 0x115F), (0x2E80, 0x303E), (0x3041, 0x33FF), (0x3400, 0x4DBF),
    (0x4E00, 0x9FFF), (0xAC00, 0xD7A3), (0xF900, 0xFAFF), (0xFF00, 0xFF60),
    (0xFFE0, 0xFFE6),
)
''',
    "fx-unicodewidth": '''
from fx_tables_data import WIDE


def char_width(ch):
    o = ord(ch)
    for a, b in WIDE:
        if a <= o <= b:
            return 2
    return 1


def width(s):
    return sum(char_width(c) for c in str(s))
''',
    "fx-colwidth": '''
from fx_unicodewidth import width


def column_widths(rows):
    ws = []
    for r in rows:
        for i, c in enumerate(r):
            w = width(c)
            if i >= len(ws):
                ws.append(w)
            elif w > ws[i]:
                ws[i] = w
    return ws
''',
    "fx-table": '''
from fx_colwidth import column_widths, width
from fx_text import normalize_cell, pad


def render(header, rows):
    cells = [[normalize_cell(c) for c in r] for r in [header] + list(rows)]
    ws = column_widths(cells)

    def line(r):
        return " | ".join(pad(c, ws[i], width(c)) for i, c in enumerate(r)).rstrip()

    out = [line(cells[0]), "-+-".join("-" * w for w in ws)]
    out += [line(r) for r in cells[1:]]
    return "\\n".join(out)
''',
    "fx-hashing": '''
import hashlib


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()
''',
    "fx-manifest": '''
import json
import os

from fx_hashing import file_sha256


def write_manifest(root, name="MANIFEST.json"):
    files = {}
    for d, _, fs in os.walk(root):
        for f in sorted(fs):
            p = os.path.join(d, f)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            if rel != name:
                files[rel] = file_sha256(p)
    with open(os.path.join(root, name), "w", encoding="utf-8") as fh:
        json.dump(dict(sorted(files.items())), fh, indent=1)
    return files
''',
    "fx-buildcore": '''
import os
import shutil

from fx_manifest import write_manifest


def build(src_dir, out_dir):
    """Copy a source tree into out_dir and stamp a hash manifest."""
    if os.path.exists(out_dir):
        shutil.rmtree(out_dir)
    shutil.copytree(src_dir, out_dir, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    files = write_manifest(out_dir)
    return {"out_dir": out_dir, "files": len(files)}
''',
    "fx-diffutil": '''
import difflib

from fx_strutil import squeeze


def text_diff(a, b):
    return "\\n".join(difflib.unified_diff(a.splitlines(), b.splitlines(),
                                          "expected", "actual", lineterm=""))


def same_words(a, b):
    return squeeze(a) == squeeze(b)
''',
    "fx-assertutil": '''
from fx_diffutil import text_diff


def assert_text_equal(actual, expected):
    if actual != expected:
        raise AssertionError("text differs:\\n" + text_diff(expected, actual))


def assert_close(a, b, tol=1e-9):
    if abs(a - b) > tol:
        raise AssertionError(f"{a} != {b} (tol {tol})")
''',
    "fx-minitest": '''
import importlib.util
import traceback

from fx_assertutil import assert_close, assert_text_equal  # noqa: F401  (re-exported)


def run_path(path):
    """Import a test module by path and run its test_* functions."""
    spec = importlib.util.spec_from_file_location("_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    res = {"passed": 0, "failed": 0, "failures": []}
    for name in sorted(dir(mod)):
        fn = getattr(mod, name)
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                res["passed"] += 1
            except Exception:
                res["failed"] += 1
                res["failures"].append({"test": name, "error": traceback.format_exc(limit=1)})
    return res
''',
}


def import_name(name: str) -> str:
    return name.replace("-", "_")


def _zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        for path in sorted(files):
            zi = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
            zi.create_system = 3          # fixed so bytes do not vary by host OS
            zi.external_attr = 0o644 << 16
            z.writestr(zi, files[path].encode("utf-8"))
    return buf.getvalue()


def build_wheel(name: str) -> bytes:
    ver = VERSIONS[name]
    mod = import_name(name)
    meta = ["Metadata-Version: 2.1", f"Name: {name}", f"Version: {ver}",
            "Summary: SEP-1 benign workload fixture"]
    meta += [f"Requires-Dist: {d}=={VERSIONS[d]}" for d in sorted(REQUIRES.get(name, []))]
    return _zip({
        f"{mod}/__init__.py": SOURCES[name].lstrip("\n"),
        f"{mod}-{ver}.dist-info/METADATA": "\n".join(meta) + "\n",
    })


def artifacts() -> dict[str, bytes]:
    """Upstream path -> artifact bytes for every workload fixture."""
    return {f"/pkg/pypi/{n}/{v}/wheel": build_wheel(n) for n, v in sorted(VERSIONS.items())}
