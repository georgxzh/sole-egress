"""Render the report figures from results/conformance-report.json.

Fig 1 (centrepiece): per-probe compliance telemetry vs probe outcome, both
configs. Fig 2: residual channel capacity. Colour-blind-safe palette; renders
identically in the PDF regardless of the machine.
"""
from __future__ import annotations

import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT = os.path.join(ROOT, "report")

# accessible palette
C_SUCCESS = "#b2182b"   # boundary crossed (bad)
C_PARTIAL = "#ef8a62"   # partially crossed
C_VIOL = "#fddbc7"      # blocked but flagged
C_BLOCK = "#2166ac"     # contained (good)
TXT = "#111111"

OUTCOME_COLOR = {"SUCCESS": C_SUCCESS, "PARTIAL": C_PARTIAL,
                 "VIOLATION_BLOCKED": C_VIOL, "BLOCKED": C_BLOCK, "ERROR": "#999999"}


def load():
    with open(os.path.join(ROOT, "results", "conformance-report.json")) as fh:
        return json.load(fh)


def fig_telemetry(report):
    a = report["config_A_allowlist"]
    b = {r["id"]: r for r in report["config_B_sep1"]}
    ids = [r["id"] for r in a]
    n = len(ids)
    fig, ax = plt.subplots(figsize=(9.2, 6.2))
    ax.set_xlim(0, 3)
    ax.set_ylim(0, n + 0.9)
    for i, ra in enumerate(a):
        y = n - 1 - i
        rb = b[ra["id"]]
        # Config A cell
        ax.add_patch(plt.Rectangle((1, y + 0.08), 1, 0.84,
                                   color=OUTCOME_COLOR[ra["outcome"]]))
        ax.text(1.5, y + 0.5, ra["outcome"].replace("_", "\n"), ha="center",
                va="center", fontsize=7.5, color="white" if ra["outcome"] in ("SUCCESS", "BLOCKED") else TXT,
                weight="bold")
        # Config B cell
        ax.add_patch(plt.Rectangle((2, y + 0.08), 1, 0.84,
                                   color=OUTCOME_COLOR[rb["outcome"]]))
        ax.text(2.5, y + 0.5, rb["outcome"], ha="center", va="center", fontsize=7.5,
                color="white" if rb["outcome"] in ("SUCCESS", "BLOCKED") else TXT, weight="bold")
        # probe label + monitor telemetry
        ax.text(0.98, y + 0.5, ra["id"], ha="right", va="center", fontsize=8.5, color=TXT)
        mon = f"mon: {ra.get('monitor_in_policy',0)} in-policy / {ra.get('monitor_violation',0)} viol"
        ax.text(1.5, y + 0.02, mon, ha="center", va="bottom", fontsize=5.6, color="#333333")
    ax.text(1.5, n + 0.2, "Config A — Allowlist", ha="center", fontsize=10.5, weight="bold")
    ax.text(2.5, n + 0.2, "Config B — SEP-1", ha="center", fontsize=10.5, weight="bold")
    ms = report["policy_monitor_summary"]
    ach = sum(1 for r in a if r["achieved"])
    contained = len(a) - sum(1 for r in report['config_B_sep1'] if r['achieved'])
    fig.suptitle(f"Allowlist telemetry: {ms['in_policy']}/{ms['total_connections']} connections in-policy, "
                 f"{ms['violation']} violation  —  yet {ach}/{len(a)} probes crossed the boundary.\n"
                 f"SEP-1 contains {contained}/{len(a)} (covert_channel remains, measured).",
                 fontsize=11, y=0.99)
    ax.axis("off")
    legend = [Patch(color=C_SUCCESS, label="attack succeeded (boundary crossed)"),
              Patch(color=C_PARTIAL, label="partial (measured residual)"),
              Patch(color=C_VIOL, label="blocked, monitor flagged"),
              Patch(color=C_BLOCK, label="contained")]
    ax.legend(handles=legend, loc="upper center", bbox_to_anchor=(0.5, -0.02),
              ncol=2, fontsize=7.5, frameon=False)
    fig.tight_layout()
    out = os.path.join(REPORT, "fig1_telemetry_vs_outcome.png")
    fig.savefig(out, dpi=200, bbox_inches="tight")
    plt.close(fig)
    return out


def fig_channel(report):
    cap = report["channel_capacity"]
    bph = cap["config_B_measured_bits_per_hour"]
    oneshot = cap["config_B_oneshot_ordering_bits_with_caching"]
    fig, ax = plt.subplots(figsize=(6.4, 4.0))
    bars = ax.bar(["Config A\n(allowlist)", "Config B\n(SEP-1, no-cache\nworst case)",
                   "Config B\n(SEP-1, caching\none-shot)"],
                  [1e9, bph, max(oneshot, 1)],
                  color=[C_SUCCESS, C_PARTIAL, C_BLOCK])
    ax.set_yscale("log")
    ax.set_ylabel("residual exfiltration channel (bits/hour, log)")
    ax.set_title("Egress capacity to a compromised upstream")
    ax.text(0, 1.3e9, "unbounded\n(full-duplex)", ha="center", fontsize=8, color=TXT)
    ax.text(1, bph * 1.3, f"{bph:,.0f}", ha="center", fontsize=8, color=TXT)
    ax.text(2, max(oneshot, 1) * 1.3, f"~{oneshot:.0f} bits\nper lifetime", ha="center", fontsize=8, color=TXT)
    ax.set_ylim(1, 5e9)
    fig.tight_layout()
    out = os.path.join(REPORT, "fig2_channel.png")
    fig.savefig(out, dpi=200, bbox_inches="tight")
    plt.close(fig)
    return out


def main():
    os.makedirs(REPORT, exist_ok=True)
    report = load()
    print(fig_telemetry(report))
    print(fig_channel(report))


if __name__ == "__main__":
    main()
