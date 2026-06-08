# Build the Proxy From Scratch Rather Than Extending an Existing Auth Service

## Status
Accepted

## Context

This decision follows from [ADR 0002](0002-asymmetric-key-approval-signing.md): the signing model requires the proxy to receive the approver's plaintext password at approval time, which no OAuth2/OIDC/forward-auth IdP exposes — making build-vs-buy a live question. Several mature, open-source authentication proxy services exist that provide forward-auth, session management, TOTP, admin UIs, and user management out of the box:

- **Authelia** (Go) — forward-auth proxy with TOTP, LDAP/file backend, session management
- **Authentik** (Python/Django) — full IdP with forward-auth, TOTP, custom flows, admin UI

Building on one of these would avoid re-implementing auth primitives (password hashing, TOTP verification, session cookies, admin UI scaffolding). This is a significant potential reduction in scope.

The question is whether the credential-backed approval signing model ([ADR 0001](0001-credential-backed-approval.md), [ADR 0002](0002-asymmetric-key-approval-signing.md)) is compatible with delegating authentication to an external service.

## The Incompatibility

[ADR 0002](0002-asymmetric-key-approval-signing.md) requires that at approval time the proxy:

1. Receives the approver's **plaintext password** directly
2. Derives `enc_key` via PBKDF2-HMAC-SHA-256 from that plaintext password
3. Decrypts the approver's Ed25519 private key using `enc_key`
4. Signs the approval record with the Ed25519 private key
5. Discards the plaintext password and private key immediately

OAuth2/OIDC and forward-auth protocols — the interfaces exposed by Authelia, Authentik, and every comparable service — are designed so that the relying application **never sees the user's password**. What they expose instead:

| What the IdP passes | Usable as PBKDF2 input? |
|---|---|
| Access token / ID token (JWT signed by IdP key) | No — derived from IdP key, not user password; token theft = private key theft |
| Identity headers (`X-Remote-User`, etc.) | No — plaintext strings, no cryptographic value |
| Session cookie | No — randomly generated, not password-derived |

No standard OAuth2/OIDC mechanism exposes a password-derived value that could substitute for the plaintext password in step 2. SRP (Secure Remote Password) would expose such a value, but neither Authelia nor Authentik implements SRP, and adding it would require writing a custom auth protocol — negating the benefit of using the external service.

## Decision

**Build the proxy from scratch in Python.**

The proxy owns the login form, receives credentials directly, and controls the full authentication event.

## Rationale

1. **The crypto model requires owning the plaintext password at approval time.** There is no protocol-compliant way to extract a password-derived value from Authelia, Authentik, or any OIDC-compliant IdP. Attempting to work around this (e.g., a parallel custom login form alongside Authelia) results in two auth systems with no meaningful benefit over one.

2. **Scope is manageable.** The proxy is not a general-purpose IdP. It manages a small, closed set of users (project team members, not arbitrary end-users). The auth primitives in scope are: password hashing (bcrypt), TOTP, session cookies, PBKDF2 key derivation, AES-256-GCM encryption, Ed25519 signing. These are all well-understood and covered by existing libraries.

3. **Python is required.** The practicum project is implemented in Python. Go-based services (Authelia) are not extensible in Python.

4. **The novel contribution is the approval layer, not the auth primitives.** Building from scratch keeps the approval logic — the actual research contribution — cleanly integrated rather than bolted onto a foreign codebase.

## Implications

- The proxy implements its own password hashing (bcrypt), TOTP verification, session management, and admin UI.
- No external IdP or SSO is used for proxy authentication. Users authenticate directly to the proxy.
- The proxy can still sit behind NGINX/Traefik/Caddy as a forward-auth provider for downstream services — it is the forward-auth service, not a consumer of one.

## Trade-offs Accepted

- **More implementation surface.** Auth primitives must be implemented and maintained rather than inherited. Mitigated by using audited libraries (passlib, pyotp, itsdangerous) and the full test harness required by the MVP spec.

- **No SSO with existing IdPs.** Users cannot log in with Google, GitHub, or corporate SSO. For the MVP use case (a small, closed team), this is acceptable.
