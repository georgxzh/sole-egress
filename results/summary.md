# SEP-1 conformance summary

- profile: `SEP-1/1.0`  mode: `local`  generated: 2026-09-12T15:23:44Z
- lockfile_digest: `c62ba9e2d3e72db7…`
- probe_suite_digest: `70dee073f1a20a20…`
- transcript_root: `d1a8b7b0d2eaca4b…`  (ed25519)

## Headline
- Config A (allowlist): **11/12** probes achieved the adversary goal, with **1 policy violations** logged out of 14 monitored connections (13 in-policy).
- Config B (SEP-1): **1/12** probes achieved the adversary goal.
- Residual covert channel under B: **216,000 bits/hour** (deterministic rate-limit bound; empirical 214,048); collapses to ~15.3 bits one-shot with caching.
- Broker integrity checks: **4/4** passed.

## Per-probe: compliance telemetry vs probe outcome

| probe | class | Config A outcome | A monitor verdicts | Config B outcome | pred. held |
|-------|-------|------------------|--------------------|------------------|-----------|
| recon | recon | SUCCESS | 1 in-policy / 0 viol | BLOCKED | ✓ |
| dropper | dropper | SUCCESS | 1 in-policy / 0 viol | BLOCKED | ✓ |
| canary_exfil | exfil | SUCCESS | 1 in-policy / 0 viol | BLOCKED | ✓ |
| c2_heartbeat | network-pivot | SUCCESS | 3 in-policy / 0 viol | BLOCKED | ✓ |
| redirect_abuse | network-pivot | SUCCESS | 1 in-policy / 0 viol | BLOCKED | ✓ |
| smuggle_grammar | rce | SUCCESS | 1 in-policy / 0 viol | BLOCKED | ✓ |
| upload_put | exfil | SUCCESS | 1 in-policy / 0 viol | BLOCKED | ✓ |
| metadata_service | network-pivot | VIOLATION_BLOCKED | 0 in-policy / 1 viol | BLOCKED | ✓ |
| poisoned_artifact | supply-chain | SUCCESS | 1 in-policy / 0 viol | BLOCKED | ✓ |
| lockfile_miss | supply-chain | SUCCESS | 1 in-policy / 0 viol | BLOCKED | ✓ |
| covert_channel | exfil | SUCCESS | 1 in-policy / 0 viol | PARTIAL | ✓ |
| persistence_restart | dropper | SUCCESS | 1 in-policy / 0 viol | BLOCKED | ✓ |

## Broker integrity (S5/S6/S7)

| control | check | passed |
|---------|-------|--------|
| S6 | no_redirect_followed | ✓ |
| S7 | oversize_fail_closed | ✓ |
| S7 | no_upstream_headers_forwarded | ✓ |
| S5 | digest_pin_holds | ✓ |
