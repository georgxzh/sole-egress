# PROGRESS.md — phase clock

Budget: 20 hours of work. Track phase boundaries; apply the §3 degradation
ladder if over budget rather than extending.

Degradation ladder (drop in this order): covert-channel *measurement* → qualitative
bound · probes < 10 · SEP-1 controls < 8 · video. Never drop: the two-config
experiment, the conformance report, the limitations appendix.

| Phase | Planned | Status | Notes |
|-------|---------|--------|-------|
| P-1 research + sourcing | (pre) | DONE | Incident facts verified & cited; EU AI Act Art.55 pulled; template unreachable → Typst substitute logged (D1). |
| P0 profile + threat model | 2h | DONE | PROFILE.md, THREAT-MODEL.md, control table. |
| P1 compose skeleton, mock cache, allowlist proxy + monitor, Config A + 1 probe | 3h | DONE | Config A end-to-end. |
| P2 broker, lockfile, digest pinning, hash-chained transcript, Config B | 4h | DONE | Config B fail-closed. |
| P3 full probe suite, sole-verify scoring, channel capacity | 3h | DONE | 12 probes; bits/hour measured. |
| P4 real runs, results/ committed, figures | 1.5h | DONE | conformance-report.json + figures. |
| P5 report vs template, claims.json complete | 4h | DONE | ≤8pp Typst PDF. |
| P6 self-verification loop (§9) | 2.5h | DONE | hostile-judge pass; VERIFICATION.md. |

Status updated as phases complete.
