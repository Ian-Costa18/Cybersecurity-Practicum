---
id: T26
title: "API Token Theft"
stride: ["Elevation of Privilege"]
attack: TODO  # MITRE ATT&CK Enterprise technique IDs — issue #107
capability: [L1, L2]
delta: TODO  # net-delta class: improved | inherited | introduced — #107
likelihood_baseline: TODO  # high|medium|low; N/A iff delta: introduced — #107
likelihood_residual: TODO  # high|medium|low — #107
severity_baseline: TODO  # critical|high|medium|low; N/A iff delta: introduced — #107
severity_residual: TODO  # critical|high|medium|low — #107
bucket: TODO  # four-bucket evaluation classification — owned by issue #107
related: [T1, T5, T11]
---

# T26 — API Token Theft

| | |
|---|---|
| **Category** | Elevation of Privilege (Requester impersonation) |
| **Capability** | Possession of a leaked API token (L1/L2 with token access) |
| **What the attacker gains** | An API Token is a long-lived bearer credential a User issues for non-interactive tooling (Twine), and it lives where automation runs — CI logs, a `.pypirc` on disk, environment variables, or a non-TLS channel. Whoever holds the plaintext can impersonate the **Requester** on the submission endpoints (`POST /pypi/legacy/` and equivalents): upload artifacts and open Approval Requests as that User. This is a distinct theft surface from the password + TOTP pair, which the API Token deliberately bypasses (it carries no TOTP step). |
| **What they cannot do** | Approve or deny, log into the User Portal or Admin Portal, or do anything beyond submission — the token is scoped to upload endpoints only ([web-proxy.md](../web-proxy.md) § API Tokens). Get anything published without quorum — every submitted artifact is still hash-bound and m-of-n-gated (the token opens a *request*, not an *outcome*). Recover the User's other tokens, password, or TOTP. |
| **Current defenses** | Tokens are stored only as a **hash**; the plaintext is shown once and never persisted (a database read yields useless hashes — see T5). Each token is **individually revocable** without touching the User's other credentials. **Token auth is gated on the owning User's `is_active` at request time**, so a single admin deactivation instantly disables *every* one of that User's tokens without enumerating them ([account-management.md](../account-management.md)) — the fastest containment for a leaked CI credential. TLS protects the token in transit. |
| **Planned defenses** | Token expiry / rotation reminders. Usage anomaly detection (a token suddenly used from a new source). Optional per-token IP allowlist for CI runners with stable egress. |
| **Operator configuration** | Store tokens in a secrets manager or the CI platform's secret store, never in a committed `.pypirc`. Rotate (revoke + reissue) on any suspected exposure. To contain a compromised User wholesale, deactivate the account — this kills all their tokens at once. Ensure submission endpoints are reachable only over TLS. |
