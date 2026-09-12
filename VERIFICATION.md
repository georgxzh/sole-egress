# VERIFICATION.md — §9 self-verification loop

The plan was to spawn a fresh, memoryless subagent as a hostile Track-1 judge. It
was launched and began work, but **terminated early on an account spend/rate limit**
before delivering a full report. It did surface one concrete observation before
dying, reproduced and analysed below. Because the subagent could not finish, the
remainder of this hostile review was carried out directly (a self-review held to the
same adversarial brief). A later session with command execution available should
re-run the independent subagent to complete this loop.

## Finding H1 (from the subagent, CONFIRMED) — `verify` failed and the report root changed with no `run` in between

**What it saw.** During its run it observed `sole-verify run --local` print transcript
root `ad07b5ca…`, then `verify` FAIL, and the committed report's root change to a
different value with no `run` it had issued in between.

**Severity if real:** critical — it would mean the headline artifact (a
third-party-checkable conformance report) is not reproducible.

**Root cause (diagnosed):** *shared-state contention between two concurrent
`run --local` processes*, not a defect in a single run. At the time the subagent was
running the harness, the main session was **also** re-running `run --local` (for the
determinism and functionality-check passes). Both processes:

- bind the same fixed loopback ports (`8080` mock, `8082` attacker, `3128` proxy,
  `8090` broker, `8091` measurement broker). The broker TCP sockets set
  `SO_REUSEADDR`, which on Windows permits two binds to the same port, so accepts are
  split nondeterministically between the two runs' brokers; and
- read/remove/append the same `results/transcript.jsonl` and
  `results/conformance-report.json`.

Two brokers appending to one `transcript.jsonl` interleave entries, breaking the hash
chain, so `verify` fails and the on-disk report root ceases to match the file — exactly
the symptom observed.

**Why a single clean run is deterministic.** In Config B the shared broker's transcript
is a fixed 7-entry sequence produced in a fixed order by three probes:
`smuggle_grammar` (3 × `grammar_violation`), `poisoned_artifact` (`request` +
`digest_mismatch`), `lockfile_miss` (`request` + `lockfile_miss`). The entry *contents*
(keys, verdicts) are identical every run; only the per-entry timestamps differ, so the
root differs per run — but `run` writes the report in the *same* process that produced
that transcript, so `verify` recomputes the chain from the committed file and matches.
The headline channel figure was additionally changed from a wall-clock measurement to a
deterministic rate-limit bound (216,000 bits/hour) precisely so the *number* is
reproducible; the empirical measurement (~214k) is reported as confirmation.

**Fix / mitigation.**
- Documented: `sole-verify run --local` is a single-run tool; concurrent runs against
  the same `results/` and ports corrupt each other's state by design. Do not overlap
  runs. (README + this file.)
- The committed `results/` pair (`conformance-report.json` + `transcript.jsonl`) is from
  a single clean run and verifies (`RESULT: VERIFIED`).
- Recommended follow-up (untested code change, deferred to a session with execution):
  add a `results/.runlock` guard and drop `SO_REUSEADDR` on the broker so a second
  concurrent run fails loudly instead of silently corrupting output; optionally allocate
  ephemeral ports per run.

**Status:** believed environmental, not a harness defect. Needs one clean sequential
`run → verify` × N confirmation in a session where command execution is available; the
argument above is structural, not yet re-measured post-incident.

## Self-review findings (main session, acting as the hostile judge)

### S1 (addressed) — headline number was not reproducible
The covert-channel bits/hour was derived from wall-clock elapsed time and drifted
~0.5% run to run (215,243 / 214,670 / 215,627). A judge re-running the harness would
not reproduce the PDF's figure. **Fixed:** the profile now publishes the *deterministic
rate-limit bound* `bits_per_symbol × 3600 / min_interval = 216,000 bits/hour` as the
headline (control S9), with the empirical measurement reported as confirmation. See
`probes/channel.py` and `DECISIONS.md` D5.

### S2 (addressed) — "containment by breaking functionality" strawman
A judge could argue Config B blocks everything trivially. **Addressed:** a positive
functionality check (`FUNC / legit_pinned_fetch_succeeds`) proves the broker still
serves a legitimate pinned package and matches its digest; the report states SEP-1
preserves the real package-fetch function rather than achieving containment by breaking
it. See `sole_verify/sole_verify.py::broker_integrity_checks`.

### S3 (accepted, documented) — the report attests *what was tested*, not runtime honesty
`verify` proves the transcript hash-chain is intact and that the *public* probe-suite
and lockfile digests match (so a lab cannot claim it ran weaker tests). It does **not**
prove the lab's runtime honestly enforced SEP-1: a dishonest lab controlling both the
broker and the transcript could fabricate a passing report. Full anti-forgery needs the
broker to sign transcript entries with a key bound to an attested runtime (remote
attestation / TEE), which is future work. Added explicitly to the report's Limitations
appendix so the claim is not overstated.

### S4 (accepted) — fidelity of the A-vs-B asymmetry
Config A exposes full HTTP; Config B exposes only the `fetch` grammar. A judge might
call this unfair. It is the intervention itself: both configs face the *same* compromised
upstream, and the only difference is what SEP-1 changes (destination-allowlist →
grammar+digest broker). The comparison is stated as such in §4/§5. Both sides do real
work: Config A's canary genuinely arrives at the upstream (confirmed via its receive
log), and Config B genuinely serves pinned packages (FUNC check) while rejecting
everything else.

### S5 (accepted) — N = 12 is not coverage
Stated in the appendix. The containment claim rests on the by-construction argument
(bounded reachable request space), not on the probe count; the probes are a
falsification instrument.

### S6 (checked) — every incident number/proper-noun in the PDF is in `claims.json`
Cross-checked: 136 keys, eleven nodes, ~17,600 actions, phase counts
(6,191/2,911/6,972/69/115), `system:masters`, `hostPath`, CSI `ClusterRole`, IMDS,
date conflict (11–13 vs 9–13 July), SSRF/token-refresh/nine CVEs, EU AI Act 55(1)(d)
and 2 Aug 2025 — each maps to a `claims.json` row. The KV-cache analogy is rhetorical,
not an incident claim.

## Docker validation status
Docker Desktop's daemon did not become ready during the build window (WSL2 cold start),
so `docker compose up` was not executed here. The offline runner
(`docker-compose.yml`, `network_mode: none`) and the kernel-enforced isolation demo
(`docker-compose.isolation.yml`) are written and reviewed but **not yet run**; the
committed numbers come from the host local-mode orchestration, which shares all broker,
probe, and channel code with the Docker path. This is disclosed in the report appendix
(limitation 7) and `SUBMISSION.md` DoD item 1.

## Three weakest points a judge will still attack
1. **Runtime honesty (S3).** The report proves what was tested, not that the sandbox
   truly had no other egress at run time, without remote attestation.
2. **One hop of five.** SEP-1 fixes only the egress; the downstream Kubernetes
   escalation is untouched (stated, but a judge may want more than a citation).
3. **Docker path unproven here.** DoD item 1's `docker compose up` was not executed in
   this session; only local-mode parity is demonstrated.
