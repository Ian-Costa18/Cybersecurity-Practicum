---
id: T23
title: "Timing Attack on bcrypt Verification"
stride: ["Information Disclosure"]
attack: [T1040]
capability: [L1]
delta: inherited
likelihood_baseline: low
likelihood_residual: low
severity_baseline: low
severity_residual: low
bucket: N/A
related: [T25]
---

# T23 — Timing Attack on bcrypt Verification

| | |
|---|---|
| **Category** | Information Disclosure |
| **Capability** | L1 |
| **What the attacker gains** | If the bcrypt comparison were not constant-time, an attacker able to make many authentication attempts and measure response times could extract partial information about the stored hash. This is a secondary oracle: it does not immediately derive the password and requires an infeasible volume of timed queries. |
| **What they cannot do** | Derive the password directly, or extract anything without the query volume a rate limiter (#123) denies. |
| **Current defenses** | Standard bcrypt implementations compare their output in constant time; using a well-maintained library (Python `bcrypt`) is sufficient, and a code-review check confirms no credential comparison is done with a non-constant-time equality. The request volume the oracle needs is also what #123's in-proxy throttle removes ([T25](T25-no-anti-automation-on-authentication-endpoints.md)). |

The ATT&CK mapping is **T1040 (Network Sniffing)**, tagged with a noted weak fit: it is the closest technique for a passive-observation side channel, but T1040 properly describes packet capture rather than response-time measurement. This is a taxonomies.md judgment call, recorded as such.

## Rating rationale — inherited, reported once

`delta: inherited`. Constant-time credential comparison is a property of the bcrypt library the proxy uses, identical to any bcrypt-based authenticator; the proxy neither introduces nor removes the side channel. Baseline and residual likelihood are therefore **equal (low)** — that equality is what "inherited" means — and severity is **low** on both sides (a marginal, non-credential disclosure that fails safe). Bucket is **N/A**: an inherited threat is reported once as a scope statement, not defended threat-by-threat, so it carries no owned-mitigation classification. It is retained in the catalog to show it was considered, not forgotten.
