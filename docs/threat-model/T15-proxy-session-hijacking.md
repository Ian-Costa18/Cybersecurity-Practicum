---
id: T15
title: "Proxy Session Hijacking (Login Session)"
stride: ["Elevation of Privilege", "Spoofing"]
attack: TODO  # MITRE ATT&CK Enterprise technique IDs — issue #107
capability: [L1]
delta: TODO  # net-delta class: improved | inherited | introduced — #107
bucket: TODO  # four-bucket evaluation classification — owned by issue #107
related: [T13]
---

# T15 — Proxy Session Hijacking (Login Session)

| | |
|---|---|
| **Category** | Elevation of Privilege, Spoofing |
| **Capability** | L1 (passive network attacker, XSS, or physical access to the cookie) |
| **What the attacker gains** | A stolen **Proxy Session** cookie impersonates the User on every session-gated surface until the session expires or is revoked. *Every* User now receives a Proxy Session at login (not just admins): it gates the **User Portal** (`/account`), the **waiting room**, and the **Admin Portal** (`/admin`). With a hijacked session the attacker can, acting as that User, mint a new **API Token** (a fresh upload credential — escalating to Requester impersonation on the submission endpoints), revoke the User's tokens, cancel the User's `pending` Approval Requests, and enumerate the requests they may approve. **If the victim is an admin**, the same cookie drives the entire Admin Portal — create/deactivate/delete users, reset credentials, regenerate enrollment links — because `/admin/*` is gated on `session + is_admin` alone and admin actions are **not** re-authenticated (collapsing into T13). |
| **What they cannot do** | **Cast, change, or withdraw a Vote (approve or deny).** Every vote requires a fresh password + TOTP re-authentication and is signed with the password-derived Ed25519 key; a Proxy Session never unlocks signing key material (see [approver-authentication.md](../approver-authentication.md), [web-proxy.md](../web-proxy.md)). A stolen session therefore yields no approval authority. It also cannot recover the plaintext of the User's *existing* API Tokens (stored hashed, shown once at creation). |
| **Current defenses** | Server-side, revocable sessions: the `session_id` is integrity-signed with `server.secret_key` ([config.md](../config.md)) — the cookie cannot be forged or tampered without the key — held server-side (revocable, e.g. by account deactivation) and bounded by `session_expiry_hours` (default 8 h). Cookie hardening: every Proxy Session cookie is issued `HttpOnly`, `Secure`, and `SameSite=Strict` ([web-proxy.md](../web-proxy.md)), raising the bar for XSS theft and CSRF. Vote re-authentication keeps approval authority unreachable from a stolen session (above). |
| **Planned defenses** | Step-up re-authentication for sensitive Admin Portal actions, so a hijacked admin session alone cannot mutate the roster. Binding sessions to the User's IP or TLS fingerprint. An explicit user-facing logout / session-revocation endpoint. |
| **Operator configuration** | Deploy exclusively over HTTPS; enable HSTS. Keep `session_expiry_hours` short, scaled to the sensitivity of the protected services. Minimize admin accounts and treat admin credentials as Tier-1 (see T13) — an admin's session cookie is the highest-value token in the system. Serve the proxy on its own origin and never embed it in an iframe (reinforces `SameSite`). |
