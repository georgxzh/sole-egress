# SEP-1 conformance summary

- profile: `SEP-1/1.0`  mode: `local`  generated: 2026-10-16T15:34:01Z
- lockfile_digest: `c62ba9e2d3e72db7…`
- probe_suite_digest: `70dee073f1a20a20…`
- transcript_root: `6cf806b409f97e6a…`  (ed25519)

## Headline
- Config A (allowlist): **11/12** probes achieved the adversary goal, with **1 policy violations** logged out of 14 monitored connections (13 in-policy).
- Config B (SEP-1): **1/12** probes achieved the adversary goal.
- Residual covert channel under B: **216,000 bits/hour** (deterministic rate-limit bound; empirical 215,859); collapses to ~15.3 bits one-shot with caching.
- Broker integrity checks: **5/5** passed.

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
| FUNC | legit_pinned_fetch_succeeds | ✓ |

## Realistic eval workload behind the broker (lockfile friction)

- Project `tidyreport 0.3.0`: closure of **17** pinned packages; naive seed lockfile pins **3** (direct runtime deps).
- Error-driven amendment: **10 runs to green**, **9 fail-closed runs**, **14 fail-closed events** (resolve 8, build 3, test 3); 9 amendments; time to fix 6.66 s (wall clock).
- Closure amendment (`lockfile_amend --closure`): 1 pass, 14 added, **1 run to green**, 0 fail-closed events.
- Final run: build ok, tests 6 passed / 0 failed, **0 egress attempts outside the broker**.
- Amend safety: tampered upstream -> 5 drift reports, 0 entries added.

| run | phase failed closed | missing entries |
|-----|---------------------|-----------------|
| 1 | resolve | fx-iterutil, fx-text, fx-numeric, fx-colwidth |
| 2 | resolve | fx-strutil, fx-mathcore, fx-unicodewidth |
| 3 | resolve | fx-tables-data |
| 4 | build | fx-buildcore |
| 5 | build | fx-manifest |
| 6 | build | fx-hashing |
| 7 | test | fx-minitest |
| 8 | test | fx-assertutil |
| 9 | test | fx-diffutil |
| 10 | green | — |

## Multi-tenant broker: isolation and per-tenant quotas

| tenant | entries | quota / window | upstream attempts | quota_exceeded | per-tenant bound (bits/hour) |
|--------|---------|----------------|-------------------|----------------|------------------------------|
| alpha | 15 | 4 / 3600 s | 4 | 2 | 80.2 |
| beta | 18 | 18 / 3600 s | 18 | 0 | 365.5 |

| check | name | passed |
|-------|------|--------|
| T1 | tenant_not_claimable_in_band | ✓ |
| T2 | cross_tenant_entry_refused | ✓ |
| T3 | no_cross_tenant_cache_state | ✓ |
| Q1 | quota_bounds_upstream_fetches | ✓ |
| Q2 | cache_hits_free_after_quota | ✓ |
| Q3 | quota_isolated_between_tenants | ✓ |
| T4 | per_tenant_transcripts_disjoint | ✓ |
