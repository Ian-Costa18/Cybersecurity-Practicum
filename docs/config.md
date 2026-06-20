# Configuration Reference

The proxy is configured via a single YAML file. By default the proxy looks for `config.yaml` in the working directory; this can be overridden with the `--config` flag.

---

## Full Example

```yaml
server:
  host: 0.0.0.0
  port: 8080
  base_url: https://proxy.example.com
  secret_key: "change-me-use-a-long-random-string"

auth:
  enrollment_link_expiry_hours: 24
  password_min_length: 12
  totp_window: 1
  session_expiry_hours: 8

notifications:
  email:
    enabled: true
    smtp_host: smtp.example.com
    smtp_port: 587
    smtp_user: proxy@example.com
    smtp_password: "smtp-password"
    from_address: "Multi-Sig Proxy <proxy@example.com>"
    tls: true
    fallback_to_portal: true

services:
  pypi-publish:
    approvers: [alice, bob, charlie]
    quorum: 3
    type: one-time
    action: publish-to-pypi
    credentials:
      pypi_token: "pypi-token-value"

  internal-app:
    approvers: [alice, bob]
    quorum: 2
    type: forward-auth
    endpoint: http://internal-app:8080
    grant_expiry_hours: 8   # 0 = grant expires with the Proxy Session
```

---

## `server`

| Field | Type | Default | Description |
|---|---|---|---|
| `host` | string | `0.0.0.0` | Interface to bind to |
| `port` | integer | `8080` | Port to listen on |
| `base_url` | string | required | Public-facing base URL; used to construct enrollment and approval links sent in emails |
| `secret_key` | string | required | Long random secret used to integrity-sign the `session_id` carried in session cookies, so a cookie cannot be forged or tampered with. **Minimum 16 characters** — the proxy refuses to start with a shorter key. (Enrollment tokens are **not** signed with this key — they are high-entropy random values stored hashed with a single-use flag and expiry.) Treat as a credential — do not commit to version control |

---

## `auth`

Controls approver account and authentication behavior. See [account-management.md](account-management.md) for full context.

| Field | Type | Default | Description |
|---|---|---|---|
| `enrollment_link_expiry_hours` | integer | `24` | How long an enrollment link is valid. Must be at least `1`; enrollment links always expire |
| `password_min_length` | integer | `12` | Minimum password length enforced at enrollment and password reset. Passwords are also capped at **72 bytes** (the bcrypt input limit) so verification and key-wrap use the same bytes — see [account-management.md](account-management.md) |
| `totp_window` | integer | `1` | Number of 30-second TOTP steps to accept on either side of the current time. `1` means codes from up to 90 seconds ago or 90 seconds in the future are accepted, tolerating clock drift |
| `session_expiry_hours` | integer | `8` | Lifetime of a Proxy Session. Governs **every** Proxy Session — admin and non-admin alike — now that all Users receive a Proxy Session (e.g., for the User Portal), not just admins. (Formerly `admin_session_expiry_hours`, which covered only Admin Portal sessions.) |

---

## `notifications`

### `notifications.email`

Controls SMTP email delivery for enrollment links and approval request notifications.

**Omitting the `email:` block disables email delivery** — the `enabled: true` default below applies only when the block is present. To turn email off, either leave the block out entirely or set `enabled: false`.

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Set to `false` to disable email delivery entirely. Enrollment links and approval links must then be distributed manually via the Admin Portal |
| `smtp_host` | string | required | SMTP server hostname. Required whenever the `email:` block is present, even with `enabled: false` |
| `smtp_port` | integer | `587` | SMTP server port. Common values: `587` (STARTTLS), `465` (TLS), `25` (plain, not recommended) |
| `smtp_user` | string | optional | SMTP authentication username. Omit for an unauthenticated (e.g. local dev) SMTP server |
| `smtp_password` | string | optional | SMTP authentication password. Omit for an unauthenticated SMTP server. Consider loading from an environment variable (see below) |
| `from_address` | string | required | The `From:` address on outgoing emails. Required whenever the `email:` block is present. Can include a display name: `"Name <addr@example.com>"` |
| `tls` | bool | `true` | Use STARTTLS when connecting. Set to `false` only for local development SMTP servers |
| `fallback_to_portal` | bool | `true` | If email delivery fails, log the error and display the link in the Admin Portal instead of failing hard. Recommended for MVP |

### Emails Sent

The full event-to-recipient matrix and the decoupling contract are specified in [notification-system.md](notification-system.md). The MVP defaults:

| Event | Recipient | Content |
|---|---|---|
| `account.enrollment_issued` (admin creates a user / regenerates link) | New user | Enrollment link (expires per `auth.enrollment_link_expiry_hours`) |
| `account.credentials_reset` | Affected user | Fresh enrollment link |
| `account.deactivated` / `account.deleted` | Affected user | Informational "contact your admin"; no link |
| `request.created` (new approval request) | All approvers for the service | Approval link, service name, request summary |
| `request.approved` | Requester | Request outcome |
| `request.denied` | Requester + Endorsing Approvers | Request outcome (a later denial overrode the approval an Endorsing Approver had given) |
| `action.succeeded` / `action.failed` | Requester + Endorsing Approvers | Execution outcome (one-time services) |
| `grant.activated` | Requester + Endorsing Approvers | Access granted (forward-auth) |

---

## `services`

Each key under `services` defines a protected service. The key is the service ID (used in logs and approval requests).

| Field | Type | Required | Description |
|---|---|---|---|
| `approvers` | list of strings | yes | Usernames of users who can approve requests for this service. Must exist as active user accounts |
| `quorum` | integer | yes | Minimum number of approvers who must approve before the request proceeds. Must be ≥ 2 and ≤ `len(approvers)` — see [Startup validation](#startup-validation) |
| `type` | string | yes | `one-time` or `forward-auth` (see below) |
| `action` | string | if `type: one-time` | The action to execute after quorum is reached (e.g., `publish-to-pypi`) |
| `max_attempts` | integer | `one-time` only (default `3`) | Action retry budget: how many times the Executor may attempt the external operation before a transient failure becomes terminal `failed`. Permanent rejections (4xx) skip retries regardless (see [request-lifecycle.md](request-lifecycle.md)) |
| `endpoint` | string | required for `forward-auth`; optional for `one-time` | Outbound destination URL for this service. For `forward-auth` it is the **backend** — the upstream forwarded to after approval. For `one-time` it is where the approved action is published; defaults to PyPI's legacy upload URL (`https://upload.pypi.org/legacy/`) when omitted |
| `grant_expiry_hours` | integer | `forward-auth` only (default `8`) | Lifetime of the Service Grant issued on approval, in hours. `0` = the grant **expires with the Requester's Proxy Session** (ends when their session ends) rather than at a fixed timestamp; there is no permanent grant. Expiry is evaluated **lazily at `/auth`** — no scheduler watches the clock (see [request-lifecycle.md](request-lifecycle.md), [web-proxy.md](web-proxy.md)) |
| `credentials` | map | depends on action | Credentials required to execute the action (e.g., `pypi_token`). Treat as secrets — see environment variable substitution below |

### Service Types

**`one-time`** — After quorum is reached, the proxy executes a single action (e.g., publish a package to PyPI) and does not grant the requester an ongoing session.

**`forward-auth`** — After quorum is reached, the proxy grants a session and forwards the requester's HTTP request to the `endpoint` URL (the backend), injecting identity headers. Used for protecting internal web applications.

### Startup validation

The proxy validates each service at startup and **refuses to boot** on an invalid quorum:

- **`quorum > len(approvers)`** is rejected — the request would be permanently unsatisfiable.
- **`quorum < 2`** is rejected — a single-approver quorum makes one identity a full authority, defeating the multi-signature premise and conflicting with [constraints.md §3](constraints.md). The minimum meaningful quorum is `2`.

Each name in `approvers` must also resolve to an existing, active user account.

### `services.*.headers` (forward-auth only)

Controls which identity headers are injected into upstream requests on forward-auth success, and what they are named. All fields are optional; defaults match Authelia's header names for drop-in compatibility.

```yaml
services:
  internal-app:
    type: forward-auth
    endpoint: http://internal-app:8080
    headers:
      remote_user: Remote-User       # username; default: Remote-User
      remote_name: Remote-Name       # display name (same as username in MVP); default: Remote-Name
      remote_email: Remote-Email     # user email; default: Remote-Email
      remote_groups: Remote-Groups   # user groups field (free text); omitted if user has no groups set; default: Remote-Groups
```

| Field | Default header name | Value injected |
|---|---|---|
| `remote_user` | `Remote-User` | The authenticated user's username |
| `remote_name` | `Remote-Name` | The authenticated user's username (display name not separately stored in MVP) |
| `remote_email` | `Remote-Email` | The authenticated user's email address |
| `remote_groups` | `Remote-Groups` | The user's `groups` field verbatim; header is omitted entirely if the field is null |

Set a field to `false` to suppress that header entirely:

```yaml
headers:
  remote_groups: false   # do not send Remote-Groups to this backend
```

---

## Environment Variable Substitution

Secrets (SMTP password, PyPI tokens, `server.secret_key`) should not be stored in plaintext in the config file. Any string value can reference an environment variable using the `$ENV{VAR_NAME}` syntax:

```yaml
server:
  secret_key: $ENV{PROXY_SECRET_KEY}

notifications:
  email:
    smtp_password: $ENV{SMTP_PASSWORD}

services:
  pypi-publish:
    credentials:
      pypi_token: $ENV{PYPI_TOKEN}
```

The proxy will fail to start if a referenced environment variable is not set.

---

## Sensitive Fields Summary

The following fields should never be committed to version control:

| Field | Recommendation |
|---|---|
| `server.secret_key` | Use `$ENV{PROXY_SECRET_KEY}` |
| `notifications.email.smtp_password` | Use `$ENV{SMTP_PASSWORD}` |
| `services.*.credentials.*` | Use `$ENV{...}` for each credential |
