---
id: T24
title: "External Account Recovery Bypass"
stride: ["Elevation of Privilege"]
attack: [T1078]
capability: [L2, L7]
delta: introduced
likelihood_baseline: N/A
likelihood_residual: low
severity_baseline: N/A
severity_residual: critical
bucket: 3
related: [T4]
---

# T24 — External Account Recovery Bypass

| | |
|---|---|
| **Category** | Elevation of Privilege |
| **Capability** | L2 (an external attacker who compromises the one recovery inbox) or L7 (an insider approver / co-owner who already controls it) |
| **What the attacker gains** | The proxy funnels publishing authority through a single external account it does **not** own the recovery flow for — for package publishing, the **PyPI publisher account** whose upload token the proxy holds. That account's out-of-band recovery (password reset, recovery codes, SMS-2FA SIM-swap, support-desk social engineering) is entirely outside the proxy's data path. Whoever controls the recovery channel resets the account, mints a fresh upload token at the service directly, and publishes at will — defeating the m-of-n quorum without ever touching the proxy. |
| **What they cannot do** | Legitimize the action *through* the proxy — the attack bypasses it entirely, so it produces no Approval Request, no Vote, and no `AuditLog` row. (That same fact is why the proxy cannot detect it: the event never enters its data path.) |
| **Current defenses** | None in the proxy — structurally, the proxy cannot gate an external service's recovery flow. What constrains the threat is operator control of the recovery channel (below). One structural note: the proxy actually *reduces* the number of recovery single-points-of-failure — from every maintainer's own PyPI account in a direct-publish baseline to the one funnel account — but it converts that single SPOF from "publish as one maintainer" into "silently defeat the entire quorum." |
| **Operator configuration** | Enforce 2FA on the PyPI publisher account (prefer a PyPI **organization** account with a 2FA policy). Register a recovery inbox that **no single party controls** — a group inbox, not one person's personal mail — and document who controls it as an explicit trust boundary. Audit the account's registered email and recovery methods periodically. |

The ATT&CK mapping is **T1078 (Valid Accounts)**, tagged with a noted weak fit: after recovery the attacker holds the account's genuine credentials and operates as a valid account, but the *recovery act itself* has no crisp single ATT&CK technique. This is a taxonomies.md judgment call, recorded as such (cf. [T23](T23-timing-attack-on-bcrypt-verification.md)'s T1040).

## The invariant, and its package-publishing instance

Stated generally, this is **External Account Recovery Bypass**: any external account the proxy funnels authority through carries an out-of-band recovery flow the proxy cannot gate, and recovering that account bypasses the quorum. The package-publishing instance is the **PyPI publisher account**; in the general-purpose vision (#54, #109) the same invariant covers an arbitrary shared SaaS or cloud account. The threat is the invariant; PyPI is today's concrete case. (The file is retitled from its original "Shared Account Password Reset Bypass" — the rename of the file path itself is deferred to the Phase D reference sweep.)

## Rating rationale

`delta: introduced` — the funnel account and the quorum it bypasses are **both proxy constructs**. Without the proxy there is no single concentrating account and no quorum to bypass; a baseline team publishes from individually-managed maintainer accounts, which has no shared-account-recovery single point of failure. Both baselines are therefore N/A. Residual likelihood is **low**, anchored to the precondition — control of one specific, privileged recovery inbox. The insider path (L7) is a narrow overlap of role and access and a trust betrayal (L7 default: low); the external path (L2) does *not* inherit L2's usual "high," because it is a *targeted* compromise of one identified inbox, not an opportunistically-leaked credential. That low rests on the narrowness of the precondition plus ordinary operator email hygiene — not on any proxy mechanism, which is precisely why the mitigation is operator-enforced. Residual severity is **critical**: a successful recovery is a direct, unauthorized publish-at-will, the top of the mission ladder.

## Bucket

Bucket ③ (operator-enforced). The proxy provides no mechanism on this surface — by construction it cannot gate an external service's recovery flow — so the only real mitigation is operator hygiene on the external account (2FA, a recovery channel no single party controls). A gated intermediary inbox — routing the account's recovery mail to an inbox itself behind multi-party approval — could close it, but that is a service layer outside the proxy and out of scope for the package-publishing MVP (future work, #54 / #109).
