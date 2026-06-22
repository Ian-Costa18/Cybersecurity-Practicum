# Account Management & Admin Authentication

This document covers the user account model, authentication factors, account provisioning, the Admin Portal, and credential recovery.

For the per-approval authentication flow and cryptographic signing scheme, see [approver-authentication.md](approver-authentication.md).

For the decision to use credential-backed approval over threshold signatures, see [ADR 0001](adr/0001-credential-backed-approval.md).

---

## User Account Model

Every approver and admin is a **User** stored in the proxy's local database. There are no external identity providers in the MVP (SSO integration is a future idea).

### Users table

| Field | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key |
| `username` | string | Unique; used at login |
| `email` | string | Unique. Used to deliver enrollment link |
| `password_hash` | string | bcrypt hash of the user's password |
| `totp_secret` | string | Shared secret for TOTP. **Stored in plaintext in the MVP** — at-rest encryption (AES-256-GCM under a system-level key, since the proxy must verify TOTP without the user present) is a **planned** defense, not yet implemented. See [threat-model.md](threat-model.md) T7 / T5 |
| `groups` | string | Optional. Free-text group membership string injected as the `Remote-Groups` header (or its configured equivalent) on forward-auth success. Comma-separated values are conventional (e.g., `"developers,release-managers"`) but the proxy does not interpret the content — it is passed verbatim to the backend. Null if not set |
| `is_admin` | bool | If true, user can access the Admin Portal |
| `is_active` | bool | False until enrollment is complete; set to false to deactivate |
| `created_at` | timestamp | When the account was created by an admin |
| `enrolled_at` | timestamp | When the user completed enrollment (null until then) |

There is no separate admin account type. Admin is a flag on a regular user account. Admins authenticate with the same mechanism as approvers (password + TOTP).

### User keys table

Key pairs are stored separately, so a user can accumulate multiple key pairs over their lifetime (one generated at enrollment, a new one generated on each password reset). Approval records reference the specific key used to sign them (`votes.key_id` = `user_keys.id`), allowing audit verification regardless of how many resets have occurred.

The **active** key — the one new approvals are signed with — is **derived, not pointed at**: it is the user's row with `revoked_at IS NULL`. A partial unique index (`user_id` where `revoked_at IS NULL`) guarantees at most one active key per user, so there is no `users.current_key_id` pointer to keep in sync. A user may transiently have *no* active key (after a reset retires the old one, before re-enrollment mints a new one).

| Field | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key; referenced by approval records as `key_id` |
| `user_id` | UUID | Foreign key to users table |
| `public_key` | string | Ed25519 public key; retained permanently for audit |
| `encrypted_private_key` | string | `AES-256-GCM(private_key, PBKDF2(password, key_salt))`; deleted on password reset or account deletion |
| `key_salt` | string | Random salt for this key's encryption key derivation |
| `created_at` | timestamp | When this key pair was generated |
| `revoked_at` | timestamp | When this key was superseded or the account was reset; null = currently active key |

**Active-key lifecycle.** A user has no active key until enrollment completes, which inserts the enrollment-generated key (active, `revoked_at` null). A **credentials reset retires the active key** — its `encrypted_private_key` and `key_salt` are dropped and its `revoked_at` is stamped, so it can no longer sign, but its `public_key` is retained so every approval it already signed stays verifiable — leaving the user with no active key until **re-enrollment inserts a fresh one**. On **account deletion**, the active key is retired the same way (private half dropped, public retained) and the account is deactivated; all key rows are kept for audit. Retirement is also *necessary* on reset: the password-derived key wrap ([User keys table](#user-keys-table), `encrypted_private_key`) means the old key cannot be re-wrapped under the new password without the old password, which a reset does not have. The biconditional "a retired key keeps only its public half" is enforced by a CHECK constraint.

### API tokens table

A User may hold **multiple** API Tokens (one-to-many under User), one per machine or context (e.g., `"work laptop"`, `"CI runner"`). Each token is stored only as a **hash** — the plaintext is shown **once** at creation and is never retrievable afterward. Each token is individually revocable without affecting the User's password, TOTP, or other tokens.

The token hash is a plain cryptographic hash (SHA-256), deliberately **not** a password-stretching KDF (bcrypt / PBKDF2). API tokens are high-entropy random values, so there is nothing to brute-force; stretching would add cost with no security benefit. This is the opposite of passwords, which use bcrypt precisely because they are low-entropy and must be made expensive to guess.

**Token authentication is gated on the owning User's `is_active`, checked at request time.** A token presented by a deactivated User is rejected regardless of its own `revoked_at` status. This is what lets deactivation contain a leaked CI/upload token immediately (PRD story 20) without the admin having to enumerate and revoke each token individually — and it also covers any token minted before the deactivation event.

| Field | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key |
| `user_id` | UUID | Foreign key to users table |
| `token_hash` | string | Hash of the API token; the plaintext is shown once at creation and never stored |
| `label` | string | Human-readable label identifying the machine/context (e.g., `"CI runner"`) |
| `created_at` | timestamp | When the token was created |
| `last_used_at` | timestamp | When the token was last presented; null until first use |
| `revoked_at` | timestamp | When the token was revoked; null = currently active |

### Sessions table

Proxy Sessions are **server-side, revocable records** — not stateless signed cookies. A session row is the authoritative record of a logged-in User; the cookie carries only the **signed `session_id`**. Deleting a session row (logout, or user deactivation) revokes access **immediately**, because the next request finds no matching row. This applies to **all** Users, not just admins.

| Field | Type | Notes |
|---|---|---|
| `session_id` | UUID | Primary key; the value carried (signed) in the session cookie |
| `user_id` | UUID | Foreign key to users table |
| `issued_at` | timestamp | When the session was created at login |
| `expires_at` | timestamp | When the session expires (see `session_expiry_hours` in [config.md](config.md)) |

---

## Authentication Factors

Every user authenticates with two factors:

1. **Password** — verified against `password_hash` using bcrypt. Minimum length is configurable (default: 12 characters). Because **bcrypt silently truncates its input at 72 bytes**, passwords are **capped at 72 bytes** at enrollment and reset, so bcrypt verification and the PBKDF2 key-wrap ([approver-authentication.md](approver-authentication.md)) operate on the *same* bytes — avoiding a state where login verifies only the first 72 bytes while key derivation uses the full string. (See [ADR 0003](adr/0003-cryptographic-primitive-selection.md).)
2. **TOTP (Time-based One-Time Password)** — a 6-digit code generated by an authenticator app (Google Authenticator, Authy, etc.) using the user's `totp_secret`. The proxy accepts codes within a configurable clock-skew window — `auth.totp_window` time steps on either side of now (default: 1, i.e. a 90-second window; see [config.md](config.md)).

Both factors must pass before any action is taken. There is no fallback to password-only authentication.

---

## Account Provisioning Flow

An admin creates approver accounts through the Admin Portal. The approver then self-enrolls via a one-time link. The admin never sees the approver's password or TOTP secret.

```mermaid
sequenceDiagram
    actor Admin
    participant Portal as Admin Portal
    actor Approver

    Admin->>Portal: Create user (username, email)
    Portal->>Portal: Store account in DB (inactive, no credentials)
    Portal->>Approver: Email enrollment link via SMTP
    Note over Portal: Link also shown in portal as fallback if email fails
    Approver->>Portal: Click enrollment link
    Portal->>Portal: Validate token (not expired, not already used)
    Approver->>Portal: Set password + scan TOTP QR code
    Portal->>Portal: Generate Ed25519 key pair (public_key, private_key)
    Portal->>Portal: Derive enc_key = PBKDF2(password, key_salt)
    Portal->>Portal: encrypted_private_key = AES-256-GCM-Encrypt(private_key, enc_key)
    Portal->>Portal: Discard private_key from memory
    Portal->>Portal: Store credentials and key material in DB
    Portal->>Portal: Mark account active, invalidate enrollment token
    Portal-->>Approver: Enrollment complete
```

### Enrollment Link Properties

Enrollment tokens are **high-entropy random values stored hashed** — not stateless signed blobs. The proxy persists each token's hash alongside an expiry and a **single-use/consumed flag**; validation hashes the presented token and checks the stored record is unexpired and unconsumed. As with API tokens, the stored hash is a plain cryptographic hash (SHA-256), not a password-stretching KDF: the token is already high-entropy, so stretching would add cost with no security benefit.

#### Enrollment tokens table

| Field | Type | Notes |
|---|---|---|
| `id` | UUID | Primary key |
| `user_id` | UUID | Foreign key to users table |
| `token_hash` | string | SHA-256 of the enrollment token; the plaintext appears once in the emailed link and is never stored |
| `expires_at` | timestamp | When the link expires (default 24h; see `enrollment_link_expiry_hours` in [config.md](config.md)) |
| `consumed_at` | timestamp | Set when enrollment completes; null = unconsumed. The **check-and-set is atomic** — a single transaction verifies `consumed_at IS NULL` and sets it, so concurrent clicks on the same link cannot both enroll |
| `created_at` | timestamp | When the link was issued |

- **Format:** `https://proxy.example.com/enroll/{token}` where `token` is a cryptographically random 256-bit value. Only its hash is stored.
- **Delivery:** The proxy emails the link directly to the approver's registered email address via SMTP on account creation. The Admin Portal also displays the link as a fallback if email delivery fails.
- **Expiry:** Configurable; default 24 hours from creation. The expiry is recorded on the stored token record.
- **Single-use:** A consumed flag is set immediately after the approver completes enrollment, so the token cannot be replayed.
- **If expired:** Admin generates a new enrollment link via the Admin Portal. The account remains inactive.

---

## Admin Portal

The Admin Portal is accessible at `https://proxy.example.com/admin`. Access requires a user account with `is_admin = true`. Authentication uses the same password + TOTP flow as approver authentication, and results in a Proxy Session (server-side, revocable; see the [sessions table](#sessions-table) and `session_expiry_hours` in [config.md](config.md), default 8 hours).

### Admin Portal vs. User Portal

The proxy has two distinct authenticated surfaces:

- **Admin Portal** (`/admin`) — **account administration**, restricted to `is_admin` Users. Manages *other* Users' accounts: provisioning, deactivation, credential reset. An admin is deliberately kept out of the credential path — they may revoke a User's API Tokens but cannot create or view them.
- **User Portal** (`/account`) — **self-service**, available to any enrolled User regardless of `is_admin`. Organized by capability rather than role, because one User is simultaneously a Requester and an Approver: a User manages their own API Tokens, tracks the Approval Requests they created (cancelling ones still `pending`), and reviews/changes their own Votes on requests they may approve. The User Portal is specified in [web-proxy.md](web-proxy.md); casting, changing, or withdrawing a Vote always routes through the re-authentication approval flow.

### Admin Portal Capabilities (MVP)

- **Create user:** Enter username, email, and optionally a `groups` value; system emails an enrollment link.
- **View users:** List all accounts with status (active, inactive, admin flag, groups).
- **Edit user:** Update `groups` (and any other non-credential fields) without resetting credentials.
- **Deactivate user:** Set `is_active = false` immediately; any in-flight approval links for that user are invalidated, and their Proxy Sessions are revoked (session rows deleted). Because **token authentication and vote acceptance both re-check `is_active` at request time** (see [API tokens](#api-tokens-table)), a leaked CI/upload token stops working the instant the account is deactivated, and a vote already past the re-auth gate is rejected at write time if the approver was deactivated in the interim. Reversible — account can be reactivated with all credentials intact.
- **Delete user:** Irreversible. Removes `encrypted_private_key` (signing capability revoked) but retains `public_key` so historical approval records remain verifiable.
- **Reset credentials:** Invalidate the user's current password and TOTP; generate a new enrollment link.
- **Regenerate enrollment link:** Generate a new link for a user who has not yet enrolled or whose link expired.
- **Revoke a user's API tokens:** Revoke any of a User's API Tokens (e.g., on suspected compromise). Admins may revoke but **cannot create or view** a User's tokens — this keeps the admin out of the credential path; token creation and inspection live in the User Portal.

---

## Account Events

Account-management operations emit **events** the same way the [request lifecycle](request-lifecycle.md) does. This document is the source of truth for account events; the [notification system](notification-system.md) **subscribes** to them rather than redefining them. Account events are distinct from request-lifecycle events: they concern a User's account, not an Approval Request.

Each event names the **affected User** as its subject. Notification delivery (SMTP, portal fallback, default subscriptions) is specified in [notification-system.md](notification-system.md).

| Event | Fires when | Subject |
|---|---|---|
| `account.enrollment_issued` | An admin creates a user, or regenerates an enrollment link for a user who has not yet enrolled or whose link expired | The new/pending User — carries the enrollment link |
| `account.credentials_reset` | An admin resets a user's credentials (invalidates password + TOTP, issues a fresh enrollment link) | The affected User — carries the new enrollment link |
| `account.deactivated` | An admin sets `is_active = false` | The affected User |
| `account.deleted` | An admin irreversibly deletes the account | The affected User |

`account.enrollment_issued` and `account.credentials_reset` both deliver an enrollment link (a credentials reset *is* a fresh enrollment). `account.deactivated` and `account.deleted` deliver an informational "contact your admin" message — they carry no link and grant no capability.

> The catalog is open to additional account events later (e.g., `account.groups_changed`); it is intentionally minimal for MVP.

---

## Credential Recovery

There is no self-service credential recovery. If an approver forgets their password or loses access to their authenticator app, they contact an admin. The admin verifies their identity out-of-band (phone call, in person) and then uses the Admin Portal to reset the account and issue a new enrollment link.

This keeps the credential trust boundary clean: account access is always gated by a human decision.

There is also **no self-service password change** in the MVP — the User Portal exposes no change-password flow. A password change happens only via an admin-initiated credentials reset, which issues a fresh enrollment link and, as noted in the [active-key lifecycle](#user-keys-table), **necessarily retires the prior signing key** (re-enrollment generates a new pair; past signatures remain verifiable via the retained `public_key`).

---

## Configuration Reference

All authentication parameters are documented in [docs/config.md](config.md).
