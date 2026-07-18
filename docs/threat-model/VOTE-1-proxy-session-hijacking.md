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
severity_residual: high
bucket: 2
related: [IDENT-1, VOTE-3, CORE-2, CODE-1]
tests:
  - tests/accounts/test_admin_step_up.py::test_sensitive_admin_action_requires_fresh_step_up_reauth
  - tests/accounts/test_admin_step_up.py::test_activate_requires_step_up_but_token_revoke_stays_session_only
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
| **What the attacker gains** | A stolen **Proxy Session** cookie impersonates the User on every session-gated surface until the session expires or is revoked. *Every* User receives a Proxy Session at login: it gates the **User Portal** (`/account`), the **waiting room**, and the **Admin Portal** (`/admin`). With a hijacked session the attacker can, acting as that User, mint a new **API Token** (a fresh upload credential — escalating to Requester impersonation on the submission endpoints, [CORE-2](CORE-2-api-token-theft.md)), revoke the User's tokens, cancel the User's `pending` Approval Requests, and enumerate the requests they may approve. **If the victim is an admin**, the same cookie still reaches the Admin Portal, but the sensitive roster mutations there — create/activate/deactivate/delete users, reset credentials, edit contact/groups, regenerate enrollment links — now demand **fresh step-up re-authentication** (a fresh password + single-use TOTP, #135): the stolen *session*, lacking the second factor, can view the portal but can no longer drive the enroll-forward takeover. It is thereby capped at its non-admin outcome; [IDENT-1](IDENT-1-admin-account-compromise.md)'s roster-takeover position is no longer reachable from the cookie alone. |
| **What they cannot do** | **Cast, change, or withdraw a Vote (approve or deny).** Every vote requires a fresh password + TOTP re-authentication and is signed with the password-derived Ed25519 key; a Proxy Session never unlocks signing key material ([approver-authentication.md](../approver-authentication.md), [web-proxy.md](../web-proxy.md)). A stolen session therefore yields no approval authority. It also cannot recover the plaintext of the User's *existing* API Tokens (stored hashed, shown once at creation). Driving actions inside the victim's live browser *without* stealing the cookie (session-riding via XSS) is the web-application-vulnerability threat, not this one. |
| **Current defenses** | Server-side, revocable sessions: the `session_id` is integrity-signed with `server.secret_key` ([config.md](../config.md)) — the cookie cannot be forged or tampered without the key, demonstrated by `tests/auth/test_sessions.py::test_a_tampered_or_wrongly_keyed_cookie_does_not_verify` (tampered signature, wrong key, and malformed cookie all fail to resolve) — held server-side and bounded by `session_expiry_hours` (default 8 h), with expiry enforced and the row cleaned up (`::test_an_expired_session_is_invalid_and_cleaned_up`). **Explicit logout revokes immediately** (`test_logout_revokes_the_session_immediately`, `tests/auth/test_login.py`), and account deactivation revokes every session for the User (`test_deactivate_revokes_session_and_blocks_login`). Cookie hardening: every Proxy Session cookie is issued `HttpOnly`, `Secure`, and `SameSite=Strict` ([web-proxy.md](../web-proxy.md)), raising the bar for XSS theft and CSRF. Vote re-authentication keeps approval authority unreachable from a stolen session (above), and **step-up re-authentication on sensitive Admin Portal actions** (#135) extends the same fresh-password-+-single-use-TOTP check — reusing the vote path's `verify_credentials` — to the enroll-forward roster mutations, so a hijacked admin session cannot enroll, activate, reset, deactivate, delete, or re-point an approver without re-proving the second factor (`tests/accounts/test_admin_step_up.py::test_sensitive_admin_action_requires_fresh_step_up_reauth`). **Activate** is included as the system side of [IDENT-2](IDENT-2-enrollment-link-interception.md)'s out-of-band confirmation gate: a hijacked session that self-activated an intercepted enrollment seat would complete that takeover without a second factor, so it too demands step-up (`test_activate_requires_step_up_but_token_revoke_stays_session_only`). |
| **Operator configuration** | Deploy exclusively over HTTPS; enable HSTS. Keep `session_expiry_hours` short, scaled to the sensitivity of the protected services. Minimize admin accounts and treat admin credentials as Tier-1 (see [IDENT-1](IDENT-1-admin-account-compromise.md)) — an admin's session cookie is the highest-value token in the system. Serve the proxy on its own origin and never embed it in an iframe (reinforces `SameSite`). |

The ATT&CK mapping is two techniques. **T1539 (Steal Web Session Cookie):** taking the cookie itself via malware on the endpoint, physical access, or script access where protections fail. **T1550.004 (Use Alternate Authentication Material: Web Session Cookie):** replaying the stolen cookie to act as the victim without knowing any credential.

## Rating rationale

`delta: introduced` — the Proxy Session is proxy machinery; there is no baseline analog in a direct `twine upload` to PyPI. Both baselines are N/A. Residual likelihood is **medium**, a deliberate deviation *below* the L1 default (high): `HttpOnly` + `Secure` + `SameSite=Strict` cookies, TLS deployment, an 8-hour expiry, and tested logout / deactivation revocation push theft toward endpoint compromise rather than passive capture. Residual severity is **high**: with step-up re-authentication on sensitive Admin Portal actions shipped (#135), a stolen session is capped at its non-admin outcome — it no longer reaches [IDENT-1](IDENT-1-admin-account-compromise.md)'s roster takeover, since the enroll-forward mutations demand a fresh second factor the cookie never carries. It is not **medium** because the non-admin surface a stolen session still commands is itself damaging: minting a fresh API Token escalates to Requester impersonation on the submission endpoints ([CORE-2](CORE-2-api-token-theft.md)), and any User's `pending` requests can be cancelled. (Before #135 this was **critical** — the admin-victim case reached an unauthorized publish at L1.)

## Bucket

Bucket ② (argued by design). *A stolen session yields no approval authority* is a designed-in property — voting re-authenticates with password + TOTP and signs with the password-derived key, which a session never unlocks — but no single test drives the negative end-to-end, so it is argued rather than executably demonstrated. The severity-reducing step-up control (#135) does **not** move the bucket: ② rests on the re-authenticated-voting mechanics, and #135 lowers the admin-victim *severity* (critical → high), not the bucket. The step-up leg does, however, carry its own executable negative — `test_sensitive_admin_action_requires_fresh_step_up_reauth` drives a session-only sensitive action to a `401` and the fresh-credential one to success — but that demonstrates the admin-action cap, not the approval-authority property this bucket is argued on.

## Planned defenses

- **Peer-approved sensitive admin actions** — future work (the third tier from #125's original design grill, 2026-07-04, deferred alongside step-up #135 and the admin-action notification leg #125). Would require a second admin to approve an enroll-forward mutation, so even a *fully credentialed* compromised admin — not just a hijacked session — cannot unilaterally take over the roster. Not scoped to an issue yet.
