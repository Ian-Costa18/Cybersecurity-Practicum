---
id: CORE-3
title: "Insider Collusion"
stride: ["Elevation of Privilege"]
attack: [T1078]
capability: [L9]
delta: improved
likelihood_baseline: medium
likelihood_residual: low
severity_baseline: critical
severity_residual: critical
bucket: 4
related: [CORE-1, IDENT-1]
---

# CORE-3 — Insider Collusion

| | |
|---|---|
| **Category** | Elevation of Privilege |
| **Capability** | L9 — at least m-of-n approvers coordinate maliciously |
| **What the attacker gains** | Any request they want, published. m genuine votes from m genuine accounts is a legitimate approval by construction — the proxy cannot distinguish coordinated malice from honest consensus. |
| **What they cannot do** | Deny having approved. Every colluder leaves an Ed25519-signed, non-repudiable vote; post-incident forensics prove exactly who approved what and when. This holds as long as the colluders are approvers rather than database administrators — evidence destruction requires a different role (database write access) and is a different threat; keep those roles separated (see Operator configuration). |
| **Current defenses** | Signed audit trail: every approval is Ed25519-signed and independently verifiable. This is deterrence, not prevention — it does not stop a quorum from colluding, but it prices participation: each member's involvement is permanent and provable. |
| **Operator configuration** | Treat collusion primarily as an organizational-security problem. Select approvers from independent organizational units. Set thresholds high enough that collusion requires meaningful coordination (e.g., 4-of-7 across teams). Periodically audit the approval log; review high-value approvals after the fact. Keep the approver and database-administrator roles in separate hands — the accountability guarantee above assumes the colluders cannot also destroy the evidence. |

The ATT&CK mapping is T1078 (Valid Accounts) — the same tag as
[CORE-1](CORE-1-single-approver-account-compromise.md), deliberately: in CORE-1 the valid account is
stolen; here the valid accounts are wielded by their own malicious owners. Both are the
front door used against the system, which is what T1078 describes. The downstream
supply-chain consequence for consumers stays untagged prose, per the catalog convention.

## Delta story

Collusion is not a new surface — it is the residual of the core improvement. In the
direct-publish baseline, a malicious insider publishes alone: likelihood **medium** (a
deliberate deviation *up* from the capability default for a single insider — exactly one
defector suffices, coordination costs nothing, and attribution is near zero because
nothing signs a direct PyPI publish; the lone insider is the routine incident class).
Under the proxy, the same outcome requires m approvers conspiring covertly while each
permanently signs their own participation: likelihood **low**. Severity is **critical** in
both worlds — a colluding quorum ships an artifact to PyPI — so the improvement lives
entirely on the likelihood axis: the proxy raises the price of an insider publish from one
defector to m mutually-exposed co-signers.

Bucket ④, and deliberately so: at L9, multi-party authorization is definitionally
defeated — no mechanism inside the proxy can tell a corrupt consensus from a real one.
The system's honest answer is deterrence (signatures) plus quorum topology (operator
configuration). This is the catalog's clearest accepted limitation, stated rather than
papered over.

## Planned defenses

- **Approval content preview (in-browser package file browser)** — #33 — no bucket change (makes approving malicious content *unknowingly* harder; likelihood reducer).
- **Screen-share auditing during sensitive operations** — #23 — no bucket change (raises the evidence trail around each vote; deterrence reinforcement).
- **Fine-grained authorization (per-user / disjoint-group thresholds)** — #27 — no bucket change (forces collusion to span independent groups; likelihood reducer).
- **Formal verification of the approval protocol (Tamarin/ProVerif)** — #26 — no bucket change (strengthens the non-repudiation argument; does not move the ④ boundary).
