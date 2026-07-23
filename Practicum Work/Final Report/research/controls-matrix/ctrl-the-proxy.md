<!-- LTeX: enabled=false -->
# The proxy — row 7

**Axis:** Authorization of the registry publish, artifact-bound
**Verdicts:** Stolen credential `✓` · Trusted insider `✓` · Compromised CI `✓` · Direct publish `✓*`

Scenario names and verdicts are fixed by [evaluation-plan.md §1, Move 1](../../../../docs/evaluation-plan.md).

## Primary sources
- Multi-Party Authorization proxy — System Constraints §3, §6, §9 — [constraints.md](../../../../docs/constraints.md) (repo spec)
- Threat catalog — [CORE-1](../../../../docs/threat-model/CORE-1-single-approver-account-compromise.md), [CORE-3](../../../../docs/threat-model/CORE-3-insider-collusion.md), [PUB-2](../../../../docs/threat-model/PUB-2-proxy-bypass.md) (repo)
- Palo Alto Unit 42, "'Shai-Hulud' Worm Compromises npm Ecosystem in Supply Chain Attack" — https://unit42.paloaltonetworks.com/npm-supply-chain-attack/ (accessed 2026-07-15) → `shai-hulud-unit42`
- A. Freund, "backdoor in upstream xz/liblzma leading to ssh server compromise" (oss-security), CVE-2024-3094 — https://www.openwall.com/lists/oss-security/2024/03/29/4 (accessed 2026-07-15) → `openwall-xz-backdoor`

## What it actually gates
The proxy gates **whether an artifact reaches the public registry**. Unlike every other row — which gates a login (rows 1–2), an origin attestation (row 3), a repo merge (row 4), or an internal pipeline/repo (rows 5–6) — the proxy's decision sits *at the publish point itself*. It holds the sole publish credential and will not release it until **m independent, re-authenticated approvals, each Ed25519-bound to the artifact's SHA-256**, are cast. That is the axis: *may these exact bytes be published*, decided by m humans who each inspected them. Two structural consequences follow, and they are the reason the proxy scores where rows 1–6 cannot. First, the gate is **bound to the artifact, not to a platform** — approvers approve `hash(X)`, so a poisoned-but-authentically-attested build (the gap that sinks provenance in row 3) still faces a human quorum on the exact bytes. Second, the gate sits **on the credential at the publish point**, so there is no upstream stage to route around — the direct-publish escape that leaves rows 4–6 all `✗` on column D has nowhere to land, *provided* the proxy is genuinely the sole credential holder and network path. That proviso is the `✓*` asterisk (caveat 1); the ceiling of human review is the other honest limit (caveat 2). The proxy is not a detector of malice — it never claims to spot a malicious insider — it is an authorization gate that forbids unilateral action and binds the decision to the bytes.

## Documented behavior (anchored)
> "Quorum is mandatory; the action does not proceed without it."
— *System Constraints* §3 ([constraints.md](../../../../docs/constraints.md)). No publish without m approvals — the gate cannot be satisfied by a single identity.

> "the proxy hashes the payload (SHA-256) at upload time and binds that hash to the approval request. Approvers approve the specific hash, not the package name or version. If the payload is modified after upload, the hash will not match and publication is blocked."
— *System Constraints* §6. The approval is bound to the exact bytes, so the m humans authorize *what actually ships*, not a name or a future upload.

> "the trust model depends on the proxy being the **only** holder of the upstream upload credential … If any maintainer also holds a working upload token, they can publish directly and bypass quorum entirely … an **operator-enforced operational precondition**, not something the proxy can verify."
— *System Constraints* §9. Column D's `✓` is conditional on this precondition, which the proxy cannot self-enforce — the substance of caveat 1.

## Per-column analysis

| Scenario | Verdict | Catches / Misses | Source |
|---|:--:|---|---|
| Stolen credential | `✓` | **Catches** the Shai-Hulud archetype — one stolen seat casts one vote of *m*, bound to the artifact; *m*−1 independent barriers still stand, so the token-harvest that republished under a legitimate identity finds no unilateral path here ([CORE-1](../../../../docs/threat-model/CORE-1-single-approver-account-compromise.md), executably demonstrated, bucket ①). **Misses** nothing at this cell — a colluding quorum is caveat 2, not column A. | `shai-hulud-unit42`, CORE-1 |
| Trusted insider | `✓` | **Catches** the *lone* insider — they hold exactly one vote of *m*, bound to the exact published artifact, and must recruit or deceive *m*−1 independent, re-authenticated approvers; no unilateral publish. **Misses** the colluding quorum and the review-surviving payload — a *ceiling* on human review, not a coverage gap. ⚠ (caveat 2) | `openwall-xz-backdoor`, CORE-3 |
| Compromised CI | `✓` | **Catches** the authentically-built poisoned artifact — approvers download and inspect *these exact bytes by hash* at the publish point, so the origin≠behavior gap that leaves provenance `✗` in row 3 is covered by the human gate. **Misses** the same human-review ceiling as the insider column. ⚠ (caveat 2) | `constraints.md` §6, CORE-3 |
| Direct publish | `✓*` | **Catches** by construction — the gate sits *on* the sole publish credential, so there is no upstream stage to skip and no `twine upload` path that routes around it. **Misses** only where the sole-credential precondition is violated — a retained or missed credential publishes unmediated. ⚠ (caveat 1) | `constraints.md` §9, PUB-2 |

> ⚠ **Caveat 1 — the sole-credential precondition (Direct publish `✓*`, [PUB-2](../../../../docs/threat-model/PUB-2-proxy-bypass.md)).** Column D's `✓` is complete only under an **operator-enforced** precondition — the proxy holds the *only* upload credential and is the *only* network path ([constraints.md](../../../../docs/constraints.md) §5, §9) — which the proxy **cannot self-verify**: it cannot tell whether a second copy of the token exists elsewhere. out-of-band publish reconciliation now **detects** a release the proxy never performed (bucket ① detection tier) and bounds the exposure window, but **prevention stays operator credential-topology hygiene (③)**. Detection is post-hoc — the artifact has already reached the index — so a retained or missed credential still ships (severity residual critical). The matrix claims authorization coverage at the publish point, not that the operator placed the proxy correctly.

> ⚠ **Caveat 2 — the colluding / review-surviving quorum (Trusted insider & Compromised CI, [CORE-3](../../../../docs/threat-model/CORE-3-insider-collusion.md), bucket ④).** The `✓` on columns B and C buys *no unilateral action* plus *a human gate on the exact artifact* — **not immunity**. It does not buy (a) resistance to a **colluding quorum of ≥ *m*** approvers: *m* genuine votes from *m* genuine accounts is a legitimate approval by construction, and the proxy cannot distinguish coordinated malice from honest consensus (L9); nor (b) resistance to a payload **engineered to survive honest review** — the XZ shape, whose backdoor was "obfuscated in repository test files" and built to pass a trusted committer's normal flow; if the *m*−1 reviewers cannot spot it, quorum approves it. The honest answer here is deterrence — every vote is Ed25519-signed and non-repudiable, so each colluder's participation is permanent and provable — plus quorum topology (approvers from independent units, thresholds high enough that collusion requires meaningful coordination), both operator configuration. This is the accepted limitation the whole matrix rests against: quorum *raises the bar* on the insider — one defector becomes *m* mutually-exposed co-signers — but it is not prevention.
