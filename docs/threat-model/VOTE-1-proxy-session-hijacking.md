---
id: VOTE-1
title: "Proxy Session Hijacking (Login Session)"
stride: ["Elevation of Privilege", "Spoofing"]
attack: [T1539, T1550.004]
capability: [L1]
delta: introduced
likelihood_baseline: N/A
likelihood_residual: medium
severity_baseline: N/A
severity_residual: critical
bucket: 2
related: [IDENT-1, VOTE-3, CORE-2, CODE-1]
tests:
  - tests/accounts/test_admin_portal.py::test_deactivate_revokes_session_and_blocks_login
  - tests/auth/test_login.py::test_logout_revokes_the_session_immediately
  - tests/auth/test_sessions.py::test_a_tampered_or_wrongly_keyed_cookie_does_not_verify
  - tests/auth/test_sessions.py::test_an_expired_session_is_invalid_and_cleaned_up
---

# VOTE-1 — Proxy Session Hijacking (Login Session)

| | |
|---|---|
| **Category** | Elevation of Privilege, Spoofing |
| **Capability** | L1 (passive network attacker where TLS is absent, XSS, or physical access to the cookie) |
| **What the attacker gains** | A stolen **Proxy Session** cookie impersonates the User on every session-gated surface until the session expires or is revoked. *Every* User receives a Proxy Session at login: it gates the **User Portal** (`/account`), the **waiting room**, and the **Admin Portal** (`/admin`). With a hijacked session the attacker can, acting as that User, mint a new **API Token** (a fresh upload credential — escalating to Requester impersonation on the submission endpoints, [CORE-2](CORE-2-api-token-theft.md)), revoke the User's tokens, cancel the User's `pending` Approval Requests, and enumerate the requests they may approve. **If the victim is an admin**, the same cookie drives the entire Admin Portal — create/deactivate/delete users, reset credentials, regenerate enrollment links — because `/admin/*` is gated on `session + is_admin` alone and admin actions are **not** re-authenticated, reaching [IDENT-1](IDENT-1-admin-account-compromise.md)'s roster-takeover position at L1 without ever touching the admin's credentials. |
| **What they cannot do** | **Cast, change, or withdraw a Vote (approve or deny).** Every vote requires a fresh password + TOTP re-authentication and is signed with the password-derived Ed25519 key; a Proxy Session never unlocks signing key material ([approver-authentication.md](../approver-authentication.md), [web-proxy.md](../web-proxy.md)). A stolen session therefore yields no approval authority. It also cannot recover the plaintext of the User's *existing* API Tokens (stored hashed, shown once at creation). Driving actions inside the victim's live browser *without* stealing the cookie (session-riding via XSS) is the web-application-vulnerability threat, not this one. |
| **Current defenses** | Server-side, revocable sessions: the `session_id` is integrity-signed with `server.secret_key` ([config.md](../config.md)) — the cookie cannot be forged or tampered without the key, demonstrated by `tests/auth/test_sessions.py::test_a_tampered_or_wrongly_keyed_cookie_does_not_verify` (tampered signature, wrong key, and malformed cookie all fail to resolve) — held server-side and bounded by `session_expiry_hours` (default 8 h), with expiry enforced and the row cleaned up (`::test_an_expired_session_is_invalid_and_cleaned_up`). **Explicit logout revokes immediately** (`test_logout_revokes_the_session_immediately`, `tests/auth/test_login.py`), and account deactivation revokes every session for the User (`test_deactivate_revokes_session_and_blocks_login`). Cookie hardening: every Proxy Session cookie is issued `HttpOnly`, `Secure`, and `SameSite=Strict` ([web-proxy.md](../web-proxy.md)), raising the bar for XSS theft and CSRF. Vote re-authentication keeps approval authority unreachable from a stolen session (above). |
| **Operator configuration** | Deploy exclusively over HTTPS; enable HSTS. Keep `session_expiry_hours` short, scaled to the sensitivity of the protected services. Minimize admin accounts and treat admin credentials as Tier-1 (see [IDENT-1](IDENT-1-admin-account-compromise.md)) — an admin's session cookie is the highest-value token in the system. Serve the proxy on its own origin and never embed it in an iframe (reinforces `SameSite`). |

The ATT&CK mapping is two techniques. **T1539 (Steal Web Session Cookie):** taking the cookie itself via malware on the endpoint, physical access, or script access where protections fail. **T1550.004 (Use Alternate Authentication Material: Web Session Cookie):** replaying the stolen cookie to act as the victim without knowing any credential.

## Rating rationale

`delta: introduced` — the Proxy Session is proxy machinery; there is no baseline analog in a direct `twine upload` to PyPI. Both baselines are N/A. Residual likelihood is **medium**, a deliberate deviation *below* the L1 default (high): `HttpOnly` + `Secure` + `SameSite=Strict` cookies, TLS deployment, an 8-hour expiry, and tested logout / deactivation revocation push theft toward endpoint compromise rather than passive capture. Residual severity is **critical**: the admin-victim case reaches [IDENT-1](IDENT-1-admin-account-compromise.md)'s roster takeover — an unauthorized publish — at L1. It drops to **high** once step-up re-authentication (#125) caps a stolen session at its non-admin outcome.

## Bucket

Bucket ② (argued by design). *A stolen session yields no approval authority* is a designed-in property — voting re-authenticates with password + TOTP and signs with the password-derived key, which a session never unlocks — but no single test drives the negative end-to-end, so it is argued rather than executably demonstrated.

## Planned defenses

- **Admin Portal action hardening (step-up re-auth for sensitive admin actions + admin-action notifications)** — #125 — a hijacked admin session alone can no longer mutate the roster; **when it lands, `severity_residual` drops critical → high**, and the admin-victim escalation into [IDENT-1](IDENT-1-admin-account-compromise.md) is closed. No bucket change (② rests on the argued-by-design re-authenticated-voting mechanics; #125 lowers severity, not the bucket).
