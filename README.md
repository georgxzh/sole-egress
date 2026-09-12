# sole-egress — SEP-1 Sole-Egress Package-Broker Profile

**Track 1 (Containment) artifact for the Apart Research AI Incident Response Sprint.**

> An egress **allowlist is a compliance instrument, not a containment instrument.**
> It answers *"did the sandbox connect to anything off-list?"* — and in the July 2026
> OpenAI→Hugging Face incident the honest answer was *no*, throughout, while the
> sandbox reached the open internet through the one permitted egress. SEP-1 replaces
> *"the sandbox may talk to host X"* with *"the sandbox may fetch pre-resolved
> artifact Y, by digest, and nothing else."*

This repo contains the SEP-1 profile, a threat model, a two-configuration test
harness, a 12-probe suite, a committed real run, and `sole-verify` — a CLI that
produces and checks a **network-free conformance report**.

## Headline result (reproducible, offline, < 5 min)

Facing one compromised-but-cooperative mock upstream, the same 12 probes run against:

| | Config A — Allowlist | Config B — SEP-1 |
|---|---|---|
| probes achieving the adversary goal | **11 / 12** | **1 / 12** (the measured covert channel) |
| policy monitor telemetry | **13/14 in-policy, 1 violation** | n/a (no network to monitor) |
| residual covert channel | unbounded (full-duplex) | **216,000 bits/hour** (deterministic rate-limit bound; empirical ~214k); **~15 bits/lifetime** with caching |

The finding is the *juxtaposition*: the allowlist monitor reports near-total
compliance while 11 of 12 attacks cross the boundary. See `report/report.pdf`.

## Quick start

Offline, in Docker (no network needed at run time):

```bash
docker compose up --build          # writes results/conformance-report.json + summary.md
```

Or on the host with Python 3.11+ (stdlib only; `cryptography` optional):

```bash
python sole_verify/sole_verify.py run --local
python sole_verify/sole_verify.py verify results/conformance-report.json
```

Real kernel-enforced network isolation demo for Config B (controls S1/S2/S11):

```bash
docker compose -f docker-compose.isolation.yml up --build --abort-on-container-exit
cat results/isolation_verdict.json   # ISOLATION_VERDICT: PASS
```

## What an external verifier checks — with **no access to the lab network**

This is the whole point (Track-1 judging criterion 1). A third party is given only:

1. this **public repo** (profile + probe suite + verifier),
2. the **public `lockfile.json`**, and
3. a lab's **`conformance-report.json`**.

They run `python sole_verify/sole_verify.py verify <report>` and confirm:

| # | Check | How it is checked without the lab network |
|---|-------|-------------------------------------------|
| 1 | Transcript hash-chain is intact and its root matches the report | recompute `root_n = H(root_{n-1} ‖ H(entry_n))` from the committed transcript |
| 2 | Lockfile digest matches the public lockfile | `sha256` of the servable set == `lockfile_digest` in the report |
| 3 | Probe-suite digest matches the public suite | digest of the pre-declared probe manifest == `probe_suite_digest` |
| 4 | Every probe outcome matches its **pre-registered** expectation | each probe's `expected_A`/`expected_B` was fixed before the run |
| 5 | Residual channel capacity is present and bounded | `channel_capacity` is a finite bits/hour figure (control S9) |
| 6 | Signature verifies against the transcript root | Ed25519 (if available) or a self-consistent HMAC tag |

None of these require seeing the lab's hosts, IPs, or traffic. An allowlist audit
log, by contrast, **is** a list of the lab's own destinations — it *cannot* be
shared with an external verifier without disclosing lab-network information. That
asymmetry is the argument.

**Scope of the guarantee (stated plainly).** `verify` proves *what was tested* —
the same public probe suite and lockfile, an intact hash chain — without lab-network
access. It does **not** prove the lab's runtime honestly enforced SEP-1: an operator
controlling both broker and transcript could fabricate a passing report. Closing that
needs the broker to sign transcript entries with a key bound to an attested runtime
(remote attestation), which is future work. See the report's appendix (limitation 8).

> **Run it once at a time.** `run --local` uses fixed loopback ports and a single
> `results/` directory; two overlapping runs corrupt each other's transcript by
> design. Let one finish before starting another.

## Repository layout

```
PROFILE.md          SEP-1 controls S1-S11 (each mechanically testable)
THREAT-MODEL.md     assets, adversary, trust boundaries, residual risk
DECISIONS.md        every autonomous choice + why
PROGRESS.md         phase clock
sole_egress_common.py   hashing, closed grammar, hash-chained transcript, signing
mock_cache/         compromised-but-cooperative upstream (no exploit)
allowlist_proxy/    Config A forward proxy + policy monitor
broker/             Config B SEP-1 broker (grammar, lockfile, digest pin, transcript)
probes/             transport-agnostic 12-probe suite + channel measurement
sandbox/            isolation_demo.py (real netns demo for Config B)
sole_verify/        orchestrator + scoring + verifier
tools/              gen_lockfile.py, make_figures.py
results/            committed conformance-report.json, summary.md, transcript, policy log
report/             report.pdf (Typst source), figures, claims.json (evidence ledger)
lockfile.json       the public, pre-resolved, hash-pinned closure
docker-compose.yml            offline reproducibility runner (network_mode: none)
docker-compose.isolation.yml  kernel-enforced isolation demonstration
```

## Safety

No file in this repo contains an exploit for any real system. Every probe runs
against a mock upstream we wrote, and every probe *assumes that upstream is already
compromised* — the incident's own fact pattern. Probe classes are taken from an
already-public forensic timeline. See the report's **Limitations and Dual-Use
Considerations** appendix and `report/claims.json`.

## Reproducing the incident facts

`report/claims.json` holds every factual assertion about the incident with its
sources, dependence family, and evidence class. Sources that derive from the same
original account share a family and do not corroborate one another.
