# MVP Scope Definition

This document formally defines what is and is not in the MVP for the Multi-Signature Authentication Web Proxy. It is the authoritative reference for scoping decisions. If a feature is not listed here, it is out of scope for the MVP.

See the GitHub issues labelled [`enhancement` / `future-enhancement` / `practicum`](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues?q=is%3Aissue+label%3Aenhancement%2Cfuture-enhancement%2Cpracticum) for deferred features and the rationale for each deferral.

---

## Goal

Demonstrate that m-of-n approval is a practical security primitive beyond cryptocurrency custody — applied to supply-chain security and shared account management. The MVP must be implementable, evaluable, and defensible as a practicum project.

---

## Build Sequence

The scope defined in this document is the full v1 vision. The **build** is sequenced *thinnest-thesis-first*: nothing here is cut, only ordered, so a working end-to-end proof of the core thesis exists early rather than at the end.

- **Phase 0 — Package Publishing tracer bullet.** The headline thesis, end-to-end: an artifact uploaded and bound by hash, approvers notified, quorum reached over signed votes via an emailed approval link, and publication to a mocked PyPI — plus the minimal signed audit trail that vote signing already implies. Proves *m-of-n approval is a practical primitive* on its own. Approver authentication starts at password + Ed25519 signing; the second factor arrives in Phase 2.
- **Phase 1 — Shared Account Management (forward-auth).** The generality proof: the same approval core driving a `forward-auth` Service Grant (see [ADR 0007](adr/0007-two-aggregate-request-model.md)), plus the `/auth` performance metric.
- **Phase 2 — Hardening and self-service.** The remaining scoped surface — full Admin Portal, User Portal, TOTP second factor, multiple labeled API tokens — layered onto the working spine as time allows.

Phases are an ordering, not a contract: later phases may be re-sequenced as the build teaches us what matters. **Fine-grained vertical slices are generated into the issue tracker (via the build breakdown) when implementation begins**; this section stays coarse so slice-level detail lives in exactly one place.

### Slicing status

Tracks which phases have been broken into vertical-slice issues. A phase is sliced only when its implementation is about to begin; this keeps speculative slice-level detail out of the tracker for work that may still be re-sequenced.

| Phase | Sliced? | Issues |
|---|---|---|
| Phase 0 — Package Publishing tracer bullet | **Sliced** (2026-06-18) | [#1](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/1) skeleton & test harness · [#2](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/2) identity & crypto foundation · [#3](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/3) upload + Hash Binding + request · [#4](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/4) signed votes + quorum · [#5](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/5) execution + hash re-verify |
| Phase 1 — Shared Account Management (forward-auth) | **Sliced** (2026-06-18) | [#8](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/8) prefactor: generalize request + forward-auth config · [#9](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/9) browser login + Proxy Session · [#10](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/10) forward-auth request + waiting room · [#11](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/11) Service Grant handoff · [#12](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/12) `/auth` gate (closed + open) · [#13](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/13) automated email solicitation. Absorbs automated email solicitation (moved out of Phase 0). The forward-auth `/auth` latency metric was deferred to Phase 2. |
| Phase 2 — Hardening & self-service | **Sliced** (2026-06-18) | [#14](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/14) prefactor: generalize User + multi-token · [#15](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/15) admin-created user + enrollment (keypair at enrollment) · [#16](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/16) TOTP enforcement (login + vote) · [#17](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/17) Admin Portal + SMTP fallback link · [#18](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/18) User Portal (own tokens + self-cancel + vote) · [#19](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/19) forward-auth `/auth` latency metric. Covers the Admin/User Portals, TOTP, multiple API tokens, enrollment, SMTP→portal fallback, Requester self-cancel, and the forward-auth `/auth` latency metric (moved from Phase 1). |

---

## Use Cases in Scope

> **Scope posture.** Package Publishing is the **primary, headline** use case — it is the subject of both adversarial security demonstrations and carries the project's supply-chain motivation. Shared Account Management remains in the MVP as the **generality proof** (the same approval core driving a structurally different post-approval outcome — see [ADR 0007](adr/0007-two-aggregate-request-model.md)) and as the home of the forward-auth performance metric, but is evaluated more lightly (happy-path completion + `/auth` latency, no adversarial demo of its own). The problem framing, personas, user stories, and success metrics behind this posture live in the [MVP PRD](mvp-prd.md); this document remains authoritative for *scope*.

### 1. Package Publishing (PyPI)

A developer uploads a package to the proxy. The proxy hashes it, notifies approvers, and only publishes to PyPI after quorum is reached. The package is bound to the approval hash — it cannot be modified between upload and publication.

**Service type:** `one-time`, action: `publish-to-pypi`

**Research basis:** Supply-chain attacks (event-stream, ctx, XZ Utils) documented in the literature review; multi-approval would have prevented each.

### 2. Shared Account Management

Multiple account co-owners must all approve before the proxy grants access to a shared account.

**Service type:** `forward-auth`

Once quorum is reached, the Requester (who waits in a browser session using the same waiting-room interface as other `forward-auth`-protected web apps) is forwarded to the shared account interface. No credentials are revealed to the Requester directly.

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
- **Append-only, supersedable vote model:** While a request is `pending`, an approver can change or withdraw their vote; a later vote supersedes the earlier one rather than overwriting it. The **effective vote** (each approver's most recent vote) drives quorum and the single-denial rule; superseded votes are retained for audit. See [ADR 0009](adr/0009-append-only-vote-model.md).

### Service Types

| Type | Behavior |
|---|---|
| `one-time` | The Requester submits a request and receives an immediate acknowledgment. Approval happens asynchronously in the background; the Requester is notified by email when the action completes (or is denied). They do not wait at a browser. After quorum is reached, the proxy executes a single action (e.g., publish to PyPI) and does not grant the Requester an ongoing session. |
| `forward-auth` | After quorum is reached, the proxy grants a session and forwards the HTTP request to the configured `backend`, injecting identity headers. Used for protecting internal web applications. |

### User Accounts & Authentication

- **Single account type:** No separate admin table; admin is an `is_admin` flag on a regular user account.
- **Local identity only:** All accounts are managed by the proxy. No external identity providers (SSO/OIDC/SAML) in the MVP.
- **Two factors, no fallback:** Every authentication requires password (verified via bcrypt) + TOTP (6-digit code, ±1 time step window). There is no password-only fallback.
- **Enrollment link:** Admin creates the account; the proxy emails a single-use, expiring (default 24 h) enrollment link. The approver sets their own password and TOTP secret. The admin never sees either.
- **Per-user Ed25519 key pair:** Generated at enrollment. The private key is encrypted with AES-256-GCM using a key derived from the user's password via PBKDF2. The plaintext private key is never stored.
- **API tokens:** A User may hold **multiple** labeled API tokens (one per machine/context) for programmatic, non-browser access. Each is stored only as a **hash**; the plaintext is shown **once** at creation and is never retrievable, and each is **individually revocable**.
- **Server-side revocable Proxy Sessions:** Login issues a server-side session record (not a stateless signed cookie); the cookie carries only the signed `session_id`. Deleting the record (logout or deactivation) revokes access immediately. Applies to all Users.

### Admin Portal

Accessible at `/admin`. Requires `is_admin = true`. Uses a Proxy Session (default 8 h). For account administration of *other* Users. Capabilities:

- Create user (username + email; proxy emails enrollment link)
- View users (list with status, admin flag)
- Deactivate user (`is_active = false`; reversible; invalidates in-flight approval links; revokes the user's Proxy Sessions)
- Delete user (irreversible; removes `encrypted_private_key`; retains `public_key` for audit)
- Reset credentials (invalidates password + TOTP; issues new enrollment link)
- Regenerate enrollment link (for users who have not enrolled or whose link expired)
- Revoke a user's API tokens (admins may revoke, but cannot create or view them — keeps the admin out of the credential path)

### User Portal

Accessible at `/account`. The authenticated **self-service** surface for **any enrolled User** (not just admins), distinct from the Admin Portal. Requires only a Proxy Session; organized by capability, since a User is simultaneously a Requester and an Approver. Capabilities:

- Manage own API tokens (create labeled; revoke)
- View own Approval Requests with status, and cancel ones still `pending` (`request.cancelled`)
- View requests the User may approve, and cast / change / withdraw their vote on still-`pending` ones

Viewing the portal needs only a Proxy Session, but any **vote action always requires fresh password + TOTP re-authentication** (a vote is cryptographically signed) — the portal routes vote actions through the existing `POST /approve/{id}` re-auth flow rather than offering a frictionless button.

### Cryptographic Primitives

| Primitive | Role | Key parameters |
|---|---|---|
| Ed25519-IETF (RFC 8032) | Approval record signing | SUF-CMA; deterministic nonce |
| PBKDF2-HMAC-SHA-256 | Derive `enc_key` from password | 600,000 iterations; 128-bit random salt per user |
| AES-256-GCM | Encrypt Ed25519 private key at rest | 96-bit random IV per encryption; 128-bit tag; AAD = `user_keys.id` |
| bcrypt | Password verification | cost ≥ 12; output is a login verifier only — never used as key material |

These four invariants must hold in any implementation. Violating any one collapses the security model:

1. bcrypt output is never used as key material
2. PBKDF2 output (`enc_key`) is never stored
3. Ed25519 private key is discarded immediately after signing
4. AES-256-GCM IV is unique per encryption event

### Notifications

- **SMTP email only.** Enrollment links and approval request links are sent via SMTP.
- **Portal fallback.** If email delivery fails, the link is displayed in the Admin Portal instead of failing hard (`fallback_to_portal: true`).

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
