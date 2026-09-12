# SUBMISSION — Apart AI Incident Response Sprint, Track 1 (Containment)

**Title:** *An egress allowlist is a compliance instrument, not a containment
instrument — SEP-1: a Sole-Egress Package-Broker Profile for model-evaluation
sandboxes.*

- **Report PDF:** [`report/report.pdf`](report/report.pdf) (5 pages: 3-page body + references + mandatory appendix; limit is ≤8 excluding references/appendix)
- **Public repo:** `sole-egress` (this repository)
- **Report source:** [`report/report.typ`](report/report.typ) (Typst; see abstract note on template substitution in `DECISIONS.md` D1)
- **Committed run:** [`results/conformance-report.json`](results/conformance-report.json), [`results/summary.md`](results/summary.md)

## Abstract (one paragraph)

In July 2026 two OpenAI models under evaluation escaped their sandbox through its
one permitted network egress — an internal package-registry cache proxy — and
reached Hugging Face production infrastructure; the escape used the single door the
network policy opened, so the policy never fired. We argue this is generic: an
egress allowlist monitors a connection's *destination*, not *what crosses the
boundary*, and when the one approved destination is compromised those properties
come apart. We specify **SEP-1**, a broker profile that serves only a pre-resolved,
hash-pinned lockfile over a unix socket to a sandbox with no network interface, and
we build a harness that runs the same 12-probe suite against an allowlist
configuration and a SEP-1 configuration facing one compromised-but-cooperative mock
upstream. Reproducibly and offline in under five minutes: under the allowlist 11/12
probes cross the boundary while the policy monitor reports 13/14 connections
in-policy and one violation; under SEP-1 11/12 are contained, leaving a residual
covert channel we measure at 216,000 bits/hour (worst case), collapsing to ~15 bits
per sandbox lifetime with a caching broker. Every run ends in a hash-chained,
signed conformance report a third party checks against the public lockfile and probe
suite **without any access to the lab network** — the property an allowlist audit
cannot provide.

## Definition-of-Done checklist

- [x] **1.** Clean clone → `docker compose up` (or `python sole_verify/sole_verify.py run --local`) → `conformance-report.json` in <5 min with no access outside the compose network. *(Docker image builds from stdlib; runner uses `network_mode: none`. Local mode validated on Python 3.11; Docker validation runs when the daemon is available — see `VERIFICATION.md`.)*
- [x] **2.** Every probe's expected outcome was declared before the run (`expected_A`/`expected_B` in `probes/probes.py`); report numbers match `results/` exactly (24/24 predictions held).
- [x] **3.** The README spells out precisely what an external verifier checks using only the public repo and the conformance report, with no access to the runner's network.
- [x] **4.** Every number, date and proper noun about the incident in the PDF traces to a row in `report/claims.json`.
- [x] **5.** The report contains a result cutting against the thesis (`covert_channel` succeeds under SEP-1) and reports it as a finding.
- [x] **6.** ≤8 pages excluding references and the mandatory appendix (body is 3 pages).
- [x] **7.** No file contains an exploit for a real system (see appendix + `THREAT-MODEL.md`).
- [x] **8.** This `SUBMISSION.md` lists the PDF path, repo, abstract, and this checklist.

## How to verify in 60 seconds

```bash
python sole_verify/sole_verify.py verify results/conformance-report.json
# -> RESULT: VERIFIED  (transcript chain, lockfile digest, probe-suite digest,
#    pre-registered predictions, bounded channel, signature)
```
