---
id: CRYPTO-2
title: "Cryptographic Side-Channel Leakage"
stride: ["Information Disclosure"]
attack: [T1040]
capability: [L1]
delta: inherited
likelihood_baseline: low
likelihood_residual: low
severity_baseline: low
severity_residual: low
bucket: N/A
related: [CRYPTO-1, IDENT-5]
---

<!-- Generalized + retitled from "Timing Attack on bcrypt Verification" (grill, 2026-07-02):
     instance → invariant. Old filename repointed in the Phase D reference sweep. -->

# CRYPTO-2 — Cryptographic Side-Channel Leakage

| | |
|---|---|
| **Category** | Information Disclosure |
| **Capability** | L1 — anonymous network access and a stopwatch: the ability to submit requests and measure response times. |
| **What the attacker gains** | Even a *correct* implementation of the documented crypto leaks through physics — chiefly response time. The observable instances in this system (table below) yield, at most, partial information about which secrets exist and where verification stopped — never the secrets themselves, and never without a query volume that authentication throttling denies. |
| **What they cannot do** | Derive a password, TOTP secret, or key from timing at any feasible query volume. Defeat anything with what does leak: knowing a username still leaves password + TOTP + quorum standing. Sustain the oracle once #123's rate limit lands ([IDENT-5](IDENT-5-no-anti-automation-on-authentication-endpoints.md)). |
| **Current defenses** | Constant-time comparison wherever code touches secret equality: the bcrypt library compares its output in constant time, and the TOTP path compares candidate codes via `hmac.compare_digest` (`core/crypto.py`) precisely so the code is not a timing oracle. A code-review check confirms no credential comparison uses ordinary equality. |

**The instances.** The invariant is that side channels survive correct implementation; the
per-surface story is what varies:

| Surface | What timing could reveal | Status |
|---|---|---|
| bcrypt password comparison | If comparison were not constant-time: partial information about the stored hash, over an infeasible volume of timed queries | Closed by library property — `bcrypt.checkpw` is constant-time; a secondary oracle at worst. |
| TOTP code comparison | Which candidate time-step matched, narrowing a brute-force | Closed in our code — `matched_totp_step` compares via `hmac.compare_digest`, explicitly constant-time. |
| Login short-circuit (username enumeration) | Whether an account exists: an unknown username returns in microseconds while a known one burns ~300 ms in bcrypt, because `verify_credentials` short-circuits before hashing. The returned boolean is uniform across failure modes; the response *time* is not. | **Live residual, accepted.** Knowing an approver's username defeats nothing on its own, and the exposure is a wash against baseline — see the rating rationale. |

**Boundaries.** vs. [CRYPTO-1](CRYPTO-1-cryptographic-implementation-failure.md): CRYPTO-1 owns *the code
deviates from the crypto design*; CRYPTO-2 owns *the code matches the design and physics still
leaks a little* — complements, split on whether the implementation is at fault. vs.
[IDENT-5](IDENT-5-no-anti-automation-on-authentication-endpoints.md): every timing oracle here
needs query volume, and the missing-then-planned rate limit (#123) is rated there, not
here — IDENT-5 caps the budget every one of these instances spends.

The ATT&CK mapping is **T1040 (Network Sniffing)**, tagged with a noted weak fit: it is the
closest technique for a passive-observation side channel, but T1040 properly describes
packet capture rather than response-time measurement. This is a taxonomies.md judgment
call, recorded as such.

## Rating rationale — inherited, reported once

`delta: inherited`. Side channels of correctly-used standard primitives are properties of
the primitives, identical in any bcrypt/TOTP-based authenticator; the proxy neither
introduces nor removes them. The username-enumeration instance nets equal-or-better too:
in the baseline, package-maintainer identities are *public* on pypi.org — no oracle is
needed to learn them — while the proxy places approver identities behind authentication
and this timing gap only partially un-hides them. Baseline and residual likelihood are
therefore **equal (low)** — that equality is what "inherited" means — and severity is
**low** on both sides (marginal, non-credential disclosure that fails safe). Bucket is
**N/A**: an inherited threat is reported once as a scope statement, not defended
threat-by-threat, so it carries no owned-mitigation classification. It is retained as the
catalog's inherited-class exemplar — considered, not forgotten.
