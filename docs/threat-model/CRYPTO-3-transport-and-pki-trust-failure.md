---
id: CRYPTO-3
title: "Transport & PKI Trust Failure"
stride: ["Spoofing", "Information Disclosure"]
attack: [T1557]
capability: [L1]
delta: inherited
likelihood_baseline: low
likelihood_residual: low
severity_baseline: critical
severity_residual: high
bucket: N/A
related: [IDENT-3, IDENT-4, VOTE-2, CRYPTO-2, CORE-1]
---

# CRYPTO-3 — Transport & PKI Trust Failure

| | |
|---|---|
| **Category** | Spoofing (impersonate the origin), Information Disclosure (read the traffic) |
| **Capability** | L1 — a network attacker holding a mis-issued certificate for the proxy's origin, a hijacked DNS answer, or an on-path position against a client that can be downgraded. No proxy standing required. |
| **What the attacker gains** | The ability to terminate TLS as the proxy: read and modify approver traffic in flight — credentials typed into the login and vote ceremonies, session cookies, request content. This is the trust layer *underneath* every "TLS everywhere" assumption the catalog makes: [IDENT-3](IDENT-3-notification-channel-interception.md) assumes transport encryption on the mail path, [IDENT-4](IDENT-4-phishable-approver-authentication.md)'s address-bar check assumes the address bar means something, and [VOTE-2](VOTE-2-captured-credential-replay.md) forecloses L1 capture *given* TLS. A PKI failure pulls that floor out — the identical pre-existing failure mode that applies to `pypi.org` at the baseline, on the same public certificate and DNS trust chains, to the same standard. |
| **What they cannot do** | Turn one intercepted ceremony into more than its captured material is worth — everything downstream of capture is [VOTE-2](VOTE-2-captured-credential-replay.md)'s bounded story (single-use TOTP burn, terminal freeze) and one seat of m ([CORE-1](CORE-1-single-approver-account-compromise.md)). Defeat certificate validation itself on a properly configured client — the attack requires a CA or DNS failure, not merely a network position. |
| **Current defenses** | TLS termination with standard library verification on every documented deployment path; nothing in the proxy weakens platform PKI defaults. The proxy holds no mechanism against a mis-issued certificate — no service does; that is the trust model of the public PKI, identical at the baseline. |
| **Operator configuration** | Deploy exclusively over HTTPS with a valid CA-issued certificate and enable HSTS (both already on the [operator checklist](00-overview.md#operator-checklist)). Monitor Certificate Transparency logs for unexpected issuance against the proxy's domain. Pin the proxy's URL in approver onboarding (a bookmark defeats DNS-luring). Keep the origin's DNS registrar account under 2FA — it is part of this trust chain. |

## Rating rationale

`delta: inherited` — the threat exists to make "considered" distinguishable from
"forgotten": the catalog assumes TLS everywhere across IDENT-3/IDENT-4/VOTE-2, and this
entry is where that assumption is examined rather than silently relied on. The baseline
runs the identical mechanism to the identical standard: a mis-issued certificate or
hijacked DNS for `pypi.org` MITMs the maintainer's session, captures the token, and
publishes. **Likelihood low = low** — CA mis-issuance and DNS hijacks against a specific
origin are rare, targeted events in both worlds (the inherited cross-check). Severity
differs within the inherited allowance: **baseline critical** (MITM maintainer↔PyPI →
token → unilateral publish) vs **residual high** (MITM one approver → one ceremony's
credentials → one vote of m) — the containment is
[CORE-1](CORE-1-single-approver-account-compromise.md)'s quorum story, credited once there.

**The caveat that bounds the classification:** inherited holds **under the
operator-checklist assumption** — a valid certificate and HSTS. `pypi.org` is
HSTS-preloaded and CT-monitored as a matter of course; a fresh self-hosted origin is
neither until the operator makes it so. An under-configured deployment (no HSTS, no CT
awareness, a lax internal CA) edges *below* the baseline standard, and below-standard
practice is exactly what breaks net-cancellation. The operator row is therefore not
hygiene garnish — it is what keeps this threat inherited rather than introduced.

## Bucket

`N/A` — inherited threats carry no defense-claim bucket. The proxy can neither strengthen
nor weaken the public PKI; what it owes — and delivers — is not being *worse* than the
baseline's use of it, plus the operator row above.

## ATT&CK mapping

**T1557 (Adversary-in-the-Middle):** the attacker positions between the approver and the
proxy to intercept or modify traffic — the certificate- or DNS-enabled interception rated
here. The DNS facet (hijack, cache poisoning) and passive-listening facet are instances of
the same position and are deliberately not tagged separately: T1557 is the operation
against this system's surface. The *lure*-based path to the same capture (a look-alike
domain the victim is sent to, no PKI failure needed) is
[IDENT-4](IDENT-4-phishable-approver-authentication.md)'s T1566.002, not this file's.
