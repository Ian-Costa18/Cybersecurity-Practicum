---
id: PUB-3
title: "External Account Recovery Bypass"
stride: ["Elevation of Privilege"]
attack: [T1078]
capability: [L2, L7]
delta: inherited
likelihood_baseline: low
likelihood_residual: low
severity_baseline: critical
severity_residual: critical
bucket: N/A
related: [HOST-1, PUB-2, CORE-1]
---

# PUB-3 — External Account Recovery Bypass

| | |
|---|---|
| **Category** | Elevation of Privilege |
| **Capability** | L2 (an external attacker who compromises the one recovery inbox) or L7 (an insider approver / co-owner who already controls it) |
| **What the attacker gains** | The proxy funnels publishing authority through a single external account it does **not** own the recovery flow for — for package publishing, the **PyPI publisher account** whose upload token the proxy holds. That account's out-of-band recovery (password reset, recovery codes, SMS-2FA SIM-swap, support-desk social engineering) is entirely outside the proxy's data path. Whoever controls the recovery channel resets the account, mints a fresh upload token at the service directly, and publishes at will — defeating the m-of-n quorum without ever touching the proxy. |
| **What they cannot do** | Legitimize the action *through* the proxy — the attack bypasses it entirely, so it produces no Approval Request, no Vote, and no `AuditLog` row. (That same fact is why the proxy cannot detect it: the event never enters its data path.) |
| **Current defenses** | None in the proxy — structurally, the proxy cannot gate an external service's recovery flow. What constrains the threat is operator control of the recovery channel (below). One structural note: the proxy narrows the recovery surface from every maintainer's own PyPI account to the one funnel account — but any improvement credit for that narrowing is [CORE-1](CORE-1-single-approver-account-compromise.md)'s story, counted once there; what PUB-3 owns is the flip side, that the one remaining recovery channel now silently defeats the entire quorum instead of one maintainer's account. |
| **Operator configuration** | Enforce 2FA on the PyPI publisher account (prefer a PyPI **organization** account with a 2FA policy). Register a recovery inbox that **no single party controls** — a group inbox, not one person's personal mail — and document who controls it as an explicit trust boundary. Audit the account's registered email and recovery methods periodically. |

The ATT&CK mapping is **T1078 (Valid Accounts)**, tagged with a noted weak fit: after recovery the attacker holds the account's genuine credentials and operates as a valid account, but the *recovery act itself* has no crisp single ATT&CK technique. This is a taxonomies.md judgment call, recorded as such (cf. [CRYPTO-2](CRYPTO-2-cryptographic-side-channel-leakage.md)'s T1040).

## The invariant, and its package-publishing instance

Stated generally, this is **External Account Recovery Bypass**: any external account the proxy funnels authority through carries an out-of-band recovery flow the proxy cannot gate, and recovering that account bypasses the quorum. The package-publishing instance is the **PyPI publisher account**; in the general-purpose vision (#54, #109) the same invariant covers an arbitrary shared SaaS or cloud account. The threat is the invariant; PyPI is today's concrete case.

## Rating rationale

`delta: inherited` — reclassified from `introduced` in the 2026-07-03 catalog audit, and the
re-derivation is worth spelling out because the original reasoning was the exact form the
net-cancellation rule bans. The old story argued "the funnel account and the quorum it
bypasses are both proxy constructs" — surface-counting. But a surface being proxy-shaped
doesn't make a threat introduced; *failing to cancel against the baseline's equivalent*
does, and this one cancels cleanly. The baseline runs the identical mechanism: recover a
maintainer's PyPI account out-of-band (password reset, recovery codes, SIM-swap,
support-desk social engineering) and publish unilaterally. The proxy structurally cannot
and does not touch that flow — the Current-defenses row says so in as many words — so the
threat passes through it unchanged. **Likelihood low = low** (both sides require a targeted
compromise of one identified recovery channel — not L2's usual opportunistic "high") and
**severity critical = critical** (either way the outcome is direct, unauthorized
publish-at-will — [HOST-1](HOST-1-proxy-host-compromise.md)'s rung, which is why the two are
linked). Equal on both axes → the threat cancels, and the mitigations that remain (2FA, a
recovery inbox no single party controls) are baseline PyPI-account hygiene — the defining
trait of the inherited class. The one thing the proxy *does* change — narrowing the
recovery surface from every maintainer's account to the single funnel account — is
containment credited once, to [CORE-1](CORE-1-single-approver-account-compromise.md), not a
second time here.

Contrast the sibling [PUB-2](PUB-2-proxy-bypass.md), which correctly **stays introduced**:
its likelihoods differ (baseline high vs residual medium), so it fails to cancel. That
asymmetry — not which world the surface belongs to — is the principled line between the
two bypass threats.

## Bucket

`N/A` — inherited threats carry no defense-claim bucket: the proxy makes no claim on this
surface because, by construction, it cannot gate an external service's recovery flow. The
operator row is baseline account hygiene, not a proxy defense. A gated intermediary inbox —
routing the account's recovery mail through an inbox itself behind multi-party approval —
could genuinely change the classification, but that is a service layer outside the proxy
and out of scope for the package-publishing MVP (future work, #54 / #109).
