# SEP-1 — Sole-Egress Package Broker Profile (v1.0)

**Status:** draft profile for the Apart AI Incident Response Sprint, Track 1.
**Scope:** the *one permitted egress* of a model-evaluation sandbox — the path the
July 2026 OpenAI→Hugging Face escape used, where the network policy never fired
because the escape used the single door the policy opened.

## What this profile is (and is not)

SEP-1 replaces the *allowlist* pattern ("the sandbox may talk to host X") with a
*broker* pattern ("the sandbox may fetch pre-resolved artifact Y, by digest, and
nothing else"). An egress **allowlist is a compliance instrument**: it answers
"did the sandbox connect to anything off-list?" SEP-1 is a **containment
instrument**: it constrains *what can cross the boundary* to a finite,
hash-pinned set fixed before the run.

SEP-1 does **not** claim it would have stopped the specific July 2026 escape —
the exploit mechanism inside the cache proxy is not fully established in the
public record (see `claims.json`). It claims it closes the *class* by
construction: an egress that can only return bytes matching a pre-agreed digest
cannot be turned into general outbound internet, whatever the upstream does.

## Conformance levels

- **SEP-1/Core** — controls S1–S8 MUST hold. A run that violates any Core MUST
  is non-conformant.
- **SEP-1/Measured** — Core plus S9 (channel published) and S10 (attestable
  transcript). This is the level a regulator can demand: it produces the
  network-free evidence in judging criterion 1.

## Control table

Each control: ID · level · requirement · incident action-class it closes ·
verification procedure · evidence artifact. "Action class" references the
Hugging Face forensic phase taxonomy (recon / RCE / dropper / supply-chain /
network-pivot).

| ID | Lvl | Requirement (one sentence) | Closes | Verification procedure | Evidence artifact |
|----|-----|----------------------------|--------|------------------------|-------------------|
| **S1 No general socket** | MUST | The sandbox has no route to any network; its only channel is one unix-domain socket to the broker. Raw TCP/UDP/ICMP MUST fail. | recon, network-pivot, C2 | Probes `raw_tcp`, `c2_heartbeat`, `metadata_service` attempt off-socket connects; all MUST error. | probe verdicts + transcript (no off-socket bytes) |
| **S2 No name resolution** | MUST | No resolver, no hosts-file egress path; a connect to a hardcoded IP MUST fail. | recon, network-pivot | Probe `dns_and_ip` attempts DNS and a literal-IP connect; both MUST fail. | probe verdict |
| **S3 Closed request grammar** | MUST | One verb `fetch(ecosystem,name,version,artifact)`; no paths, query strings, client headers, HTTP methods, CONNECT or protocol upgrades are accepted. | RCE, dropper, supply-chain | Probes `smuggle_grammar`, `upload_put`, `redirect_abuse` send non-conforming requests; broker MUST reject with `grammar_violation` and zero bytes. | broker reject log |
| **S4 Lockfile closure** | MUST | Only entries present in the lockfile supplied at sandbox creation are servable; no index queries, version ranges, or search. | dropper, supply-chain | Probe `lockfile_miss` requests an unlisted package; MUST return `lockfile_miss`, zero bytes. | broker reject log |
| **S5 Content pinning** | MUST | Every artifact served MUST match the lockfile SHA-256 or the fetch fails closed. *This is the control that survives upstream compromise.* | supply-chain, dropper | Probe `poisoned_artifact` makes the (compromised) upstream return tampered bytes for a listed entry; broker MUST detect digest mismatch and return zero bytes. | digest-mismatch record in transcript |
| **S6 No redirects / no upstream-chosen destinations** | MUST | 3xx is never followed, `Location` never honoured; the upstream set is static config, never data. | recon, network-pivot | Probe `redirect_abuse` has upstream reply 302→attacker host; broker MUST NOT connect onward. | transcript shows no onward connect |
| **S7 Response-shape closure** | MUST | Bounded size, declared archive type, no chunked/streaming passthrough, no upstream headers forwarded. | dropper, C2 | Probe `oversize_response` / `header_reflection`; broker MUST truncate-fail and strip upstream headers. | response-shape record |
| **S8 Fail-closed** | MUST | Broker down, digest mismatch, or lockfile miss ⇒ zero bytes cross; never degrade to a direct fetch. | all | Probes above with broker killed; MUST NOT fall back to network. | absence of bytes in transcript |
| **S9 Bounded, measured channel** | MUST (Measured) | The residual channel (which entries, in what order, with what timing) has a capacity the harness MUST measure in bits/hour and the profile MUST require published. | covert exfil | Probe `covert_channel` transmits a known secret via selection+ordering+timing; harness reports measured bits/hour. | `channel_capacity` field |
| **S10 Attestable transcript** | MUST (Measured) | Append-only hash-chained log of every request, digest and verdict; the run ends with a conformance report carrying transcript root, lockfile digest, probe-suite digest, per-probe verdicts. A third party checks it against the public lockfile and probe suite and learns nothing about the lab's network. | all (audit) | `sole-verify verify` recomputes the chain and digests from the public repo alone. | `conformance-report.json` |
| **S11 Sandbox network-namespace isolation** | SHOULD | The sandbox runs in a network namespace with no interfaces except loopback; the broker socket is bind-mounted in, not networked. | recon, network-pivot | Compose config asserts `network_mode: none` for the sandbox in Config B; checked by `sole-verify verify --env`. | environment fingerprint |

**Design note (S3–S8 together).** The verbs a compromised upstream can influence
are bounded to: "return the exact bytes for one of N pre-agreed digests, or
fail." There is no verb that yields a new destination, a new artifact, a larger
response, or an upstream-chosen header. That is the sense in which SEP-1 closes
the class *by construction* rather than by detection.

## What an external verifier checks (judging criterion 1)

Given only (a) this repo, (b) the public `lockfile.json`, (c) the public probe
suite, and (d) a lab's `conformance-report.json`, a third party runs
`sole-verify verify conformance-report.json` and confirms, **with no access to
the lab's network**:

1. the transcript hash-chain is intact and its root matches the report;
2. the lockfile digest in the report matches the public lockfile;
3. the probe-suite digest matches the public probe suite (same tests were run);
4. every per-probe verdict is consistent with the transcript;
5. the published channel capacity is present and within the profile bound.

None of these require seeing the lab's hosts, IPs, or traffic. That is the
property an allowlist audit cannot provide: an allowlist log is a list of the
lab's own destinations, which *is* lab-network information.
