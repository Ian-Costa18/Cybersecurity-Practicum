---
id: CORE-1
title: "Single Approver Account Compromise"
stride: ["Elevation of Privilege"]
attack: [T1078]
capability: [L2, L3]
delta: improved
likelihood_baseline: high
likelihood_residual: high
severity_baseline: critical
severity_residual: high
bucket: 1
related: [DOS-3, PUB-2, CORE-3, IDENT-5, CORE-2]
---

# CORE-1 — Single Approver Account Compromise

| | |
|---|---|
| **Category** | Elevation of Privilege |
| **Capability** | L2 or L3 — theft of one approver's password + TOTP pair (commodity credential theft, or malware on one approver's machine) |
| **What the attacker gains** | One vote: the ability to submit a single approval as the compromised approver. The same position also permits a malicious deny or a withdrawal — the denial direction is [DOS-3](DOS-3-compromised-approver-as-denial-of-service.md)'s threat. |
| **What they cannot do** | Reach quorum. m-of-n requires at least m approvals from distinct identities, so a single compromised identity is insufficient to publish — m−1 independent barriers still stand. |
| **Current defenses** | m-of-n quorum, executably demonstrated: `test_quorum_reached_only_at_the_threshold`, `test_two_approvals_over_http_reach_quorum`, `test_a_non_eligible_user_cannot_vote` (`tests/approvals/test_votes.py`, `test_approve.py`), plus the Act 2 demo (#114) as the black-box showcase. Password + TOTP two-factor authentication — but see [IDENT-5](IDENT-5-no-anti-automation-on-authentication-endpoints.md): absent rate limiting, the TOTP factor can be brute-forced online once the password is known, so this factor is weaker than it appears until anti-automation lands. Ed25519 signing: approvals are cryptographically bound to the authenticated identity and cannot be transferred or replayed against a different request. |
| **Operator configuration** | Set quorum thresholds with the expected breach rate in mind: 2-of-3 is weaker than 3-of-5. Keep approver rosters small (a tight quorum beats a large pool). Use unique, strong passwords and a hardware TOTP device where feasible. Immediately deactivate accounts at the first sign of compromise via the admin portal. |

The ATT&CK mapping is T1078 (Valid Accounts): the attacker operates through a legitimate
stolen account rather than an exploit. The downstream supply-chain consequence for package
consumers (T1195.002 territory) is a consequence, not an operation against this system, and
is deliberately not tagged.

## Delta story

This is the catalog's flagship *improved* threat. The baseline equivalent is stealing the
one maintainer's PyPI credential: likelihood **high** (a single commodity credential),
severity **critical** (unilateral publish — nothing else stands in the way). Under the
proxy, the same theft is exactly as likely — residual likelihood stays **high**, because
the proxy does nothing to make credential theft harder, and IDENT-5's missing rate limiting
keeps the TOTP factor from buying the rating down — but the outcome collapses from
"publish anything" to "cast one vote": residual severity **high** (an authorization input
is corrupted while ≥1 independent barrier stands).

**The proxy doesn't make approver compromise less likely — it makes it matter less.** The
improvement lives entirely on the severity axis — and it rests on credential exclusivity:
the real PyPI token must live only in the proxy, or the quorum gate is simply walked
around. That completeness condition is [PUB-2](PUB-2-proxy-bypass.md)'s threat.

Bucket ① (black-box tier): the adversarial claim — one compromised approver cannot cause a
publish — is driven at the HTTP edge, and quorum is reached only at the threshold; below
it, the PyPI mock is never invoked.

## Planned defenses

- **SSO / external identity provider integration** — #35 — no bucket change (layers an organization's IdP MFA in front of the proxy's own factors; likelihood reducer).
- **Per-user credential wrapping (threshold decryption)** — #25 — no bucket change (moves the compromise requirement from one approver toward m simultaneously; likelihood reducer).
