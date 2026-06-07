# MVP Scope Definition

This document formally defines what is and is not in the MVP for the Multi-Signature Authentication Web Proxy. It is the authoritative reference for scoping decisions. If a feature is not listed here, it is out of scope for the MVP.

See [ideas.md](./ideas.md) for deferred features and the rationale for each deferral.

---

## Goal

Demonstrate that m-of-n approval is a practical security primitive beyond cryptocurrency custody — applied to supply-chain security and shared account management. The MVP must be implementable, evaluable, and defensible as a practicum project.

---

## Use Cases in Scope

### 1. Package Publishing (PyPI)

A developer uploads a package to the proxy. The proxy hashes it, notifies approvers, and only publishes to PyPI after quorum is reached. The package is bound to the approval hash — it cannot be modified between upload and publication.

**Service type:** `one-time`, action: `publish-to-pypi`

**Research basis:** Supply-chain attacks (event-stream, ctx, XZ Utils) documented in the literature review; multi-approval would have prevented each.

### 2. Shared Account Management

Multiple account co-owners must all approve before the proxy reveals stored credentials or grants temporary access to a shared account.

**Service type:** `one-time`, action: `reveal-credentials`

**Research basis:** Mentioned in project proposal; structurally simple workflow (request → approve → reveal).

---

## Components in Scope

### Approval Core

- **m-of-n quorum:** Configurable per service; approval proceeds only after the threshold is reached.
- **Deny:** Any single approver can deny a request and halt it immediately.
- **Hash binding:** For `one-time` requests, the proxy hashes the payload (package artifact) immediately on upload. Approvers approve that exact hash. A modified payload will not match and publication is blocked.
- **Stateless per-approval sessions:** Approvers do not have persistent sessions. Each approval link triggers a fresh, independent authentication event scoped to that request.
- **Approval signing:** Each approval is signed with the approver's Ed25519 private key (decrypted transiently from the password at authentication time). The private key is discarded immediately after signing.
- **Replay prevention:** Approval records contain the `approval_request_id`; duplicate decisions from the same approver for the same request are rejected.

### Service Types

| Type | Behavior |
|---|---|
| `one-time` | After quorum is reached, the proxy executes a single action (publish to PyPI, reveal credentials) and does not grant an ongoing session. |
| `forward-auth` | After quorum is reached, the proxy grants a session and forwards the HTTP request to the configured `backend`, injecting identity headers. Used for protecting internal web applications. |

### User Accounts & Authentication

- **Single account type:** No separate admin table; admin is an `is_admin` flag on a regular user account.
- **Local identity only:** All accounts are managed by the proxy. No external identity providers (SSO/OIDC/SAML) in the MVP.
- **Two factors, no fallback:** Every authentication requires password (verified via bcrypt) + TOTP (6-digit code, ±1 time step window). There is no password-only fallback.
- **Enrollment link:** Admin creates the account; the proxy emails a single-use, expiring (default 24 h) enrollment link. The approver sets their own password and TOTP secret. The admin never sees either.
- **Per-user Ed25519 key pair:** Generated at enrollment. The private key is encrypted with AES-256-GCM using a key derived from the user's password via PBKDF2. The plaintext private key is never stored.

### Admin / Authentication Portal

Accessible at `/admin`. Requires `is_admin = true`. Admin sessions are cookie-based (default 8 h). Capabilities:

- Create user (username + email; proxy emails enrollment link)
- View users (list with status, admin flag)
- Deactivate user (`is_active = false`; reversible; invalidates in-flight approval links)
- Delete user (irreversible; removes `encrypted_private_key`; retains `public_key` for audit)
- Reset credentials (invalidates password + TOTP; issues new enrollment link)
- Regenerate enrollment link (for users who have not enrolled or whose link expired)

### Cryptographic Primitives

| Primitive | Role | Key parameters |
|---|---|---|
| Ed25519-IETF (RFC 8032) | Approval record signing | SUF-CMA; deterministic nonce |
| PBKDF2-HMAC-SHA-256 | Derive `enc_key` from password | 600,000 iterations; 128-bit random salt per user |
| AES-256-GCM | Encrypt Ed25519 private key at rest | 96-bit random IV per encryption; 128-bit tag; AAD = `user_id ‖ version` |
| bcrypt | Password verification | cost ≥ 12; output is a login verifier only — never used as key material |

These four invariants must hold in any implementation. Violating any one collapses the security model:

1. bcrypt output is never used as key material
2. PBKDF2 output (`enc_key`) is never stored
3. Ed25519 private key is discarded immediately after signing
4. AES-256-GCM IV is unique per encryption event

### Notifications

- **SMTP email only.** Enrollment links and approval request links are sent via SMTP.
- **Portal fallback.** If email delivery fails, the link is displayed in the admin portal instead of failing hard (`fallback_to_portal: true`).

### Configuration

- **Per-service YAML file.** Each service defines its approvers, quorum, type, and post-approval behavior.
- **Environment variable substitution.** Secrets (SMTP password, PyPI token, `secret_key`) are referenced as `$ENV{VAR_NAME}` and never stored in plaintext in the config file.

### Approve/Deny Page

After authentication, the approver sees:

- Service name and request summary
- For `one-time` (package publishing): a download link to the artifact so the approver can inspect it locally
- For `forward-auth`: HTTP method, URL, and relevant headers
- Current quorum status (e.g., "1 of 3 approvals received")
- Approve and Deny buttons

### Audit Trail

Every approval and denial is stored with: approver identity, `key_id`, `approval_request_id`, timestamp, `action_hash`, decision, and Ed25519 signature. Any modification to a stored record is detectable without a password:

```
Ed25519Verify(public_key, canonical_json(approval_record), approval_signature)
```

Public keys are retained permanently; deleted accounts remain auditable.

---

## Testing

The MVP ships with a full testing harness covering unit and integration tests. Real implementations are used wherever possible. The only mocked boundaries are third-party network endpoints (PyPI publish API, and any other external HTTP APIs) — no credentials needed, and no external network calls during the test suite.

The one exception to mocking is SMTP: tests run a real in-process SMTP server so that email delivery, link formatting, and address routing are all exercised end-to-end without reaching a real mail provider.

The database, crypto primitives, and HTTP stack are never mocked.

---

## Known Limitations Accepted for MVP

These are not bugs — they are documented trade-offs made to keep the MVP tightly scoped:

- **Credentials in memory unencrypted.** The proxy holds publishing credentials (PyPI token) and shared account credentials in memory. A compromised proxy can read them. Mitigated in a future version by per-user credential wrapping.
- **No approval link expiration.** Approval links do not expire (enrollment links do). Slightly increases replay risk, but acceptable given the threat model targets single-approver compromise, not attacker-guessing-old-links.
- **Admin-only credential recovery.** No self-service. If an approver forgets their password, an admin resets it. Keeps the recovery trust boundary clean.
- **Uniform approvers per service.** All approvers for a service are equal; any of them can approve any request. No per-user or per-action variance.
- **Manual distribution fallback.** If SMTP is disabled or fails, links are shown in the portal. Requires the admin to manually distribute them — not ideal UX, acceptable for a practicum.
- **No rate limiting.** There is no limit on how many approval requests a requester can create per time window. A compromised requester account can flood approvers with spurious requests.
