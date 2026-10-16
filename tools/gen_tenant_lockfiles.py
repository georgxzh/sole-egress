"""Generate the public per-tenant lockfiles and tenant config (Week-3).

  alpha  the Track-1 probe sandbox: the main lockfile.json (15 entries), with a
         deliberately tight quota so enforcement is exercised.
  beta   the Week-1 eval-workload sandbox: workload/lockfile.json (17 entries)
         plus one entry it shares with alpha (requests), quota = |lockfile| per
         hour — enough for a full cold resolve with a caching broker.

Derived only from public lockfiles, so a verifier can regenerate and compare.
"""
from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from sole_egress_common import PROFILE_VERSION, load_lockfile  # noqa: E402

SHARED_KEY = "pypi:requests:2.31.0:wheel"
ALPHA_QUOTA = 4
WINDOW_S = 3600


def _write(path: str, obj) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
        fh.write("\n")


def main():
    main_lf = load_lockfile(os.path.join(ROOT, "lockfile.json"))
    wl = load_lockfile(os.path.join(ROOT, "workload", "lockfile.json"))
    alpha = dict(main_lf["entries"])
    beta = dict(wl["entries"])
    beta[SHARED_KEY] = main_lf["entries"][SHARED_KEY]
    out = os.path.join(ROOT, "tenants")
    os.makedirs(out, exist_ok=True)
    for tid, entries in (("alpha", alpha), ("beta", beta)):
        _write(os.path.join(out, f"{tid}.lockfile.json"),
               {"profile": PROFILE_VERSION, "generated_note": f"tenant {tid}; public",
                "entries": dict(sorted(entries.items()))})
    cfg = [
        {"id": "alpha", "lockfile": "tenants/alpha.lockfile.json",
         "quota": ALPHA_QUOTA, "window_s": WINDOW_S},
        {"id": "beta", "lockfile": "tenants/beta.lockfile.json",
         "quota": len(beta), "window_s": WINDOW_S},
    ]
    _write(os.path.join(out, "tenants.json"), cfg)
    print(f"wrote tenants/: alpha {len(alpha)} entries (quota {ALPHA_QUOTA}), "
          f"beta {len(beta)} entries (quota {len(beta)}), shared {SHARED_KEY}")


if __name__ == "__main__":
    main()
