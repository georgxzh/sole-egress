"""Generate lockfile.json from the mock_cache fixtures.

The lockfile is the pre-resolved, hash-pinned closure supplied at sandbox
creation (controls S4/S5). It is PUBLIC: a third-party verifier uses it to check
a conformance report without any access to the lab network.

We deliberately leave a small number of fixtures OUT of the lockfile so the
`lockfile_miss` probe (S4) has an unlisted-but-real package to request.
"""
from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "mock_cache"))

from mock_cache import PACKAGES  # noqa: E402
from sole_egress_common import PROFILE_VERSION, sha256_hex  # noqa: E402

# Fixtures intentionally excluded from the lockfile (real upstream, unlisted).
EXCLUDE = {"/pkg/maven/junit/4.13.2/jar"}


def main():
    entries = {}
    for path, body in sorted(PACKAGES.items()):
        if path in EXCLUDE:
            continue
        _, _, eco, name, ver, art = path.split("/")
        key = f"{eco}:{name}:{ver}:{art}"
        entries[key] = {"sha256": sha256_hex(body), "size": len(body), "path": path}
    lf = {"profile": PROFILE_VERSION, "generated_note": "pre-resolved closure; public",
          "entries": entries}
    out = os.path.join(ROOT, "lockfile.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(lf, fh, indent=2, sort_keys=True)
    print(f"wrote {out} with {len(entries)} entries (excluded {len(EXCLUDE)})")


if __name__ == "__main__":
    main()
