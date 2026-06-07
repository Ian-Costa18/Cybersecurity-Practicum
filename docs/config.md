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
  pbkdf2_iterations: 600000
  admin_session_expiry_hours: 8

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
    backend: http://internal-app:8080
```

---

## `server`

| Field | Type | Default | Description |
|---|---|---|---|
| `host` | string | `0.0.0.0` | Interface to bind to |
| `port` | integer | `8080` | Port to listen on |
| `base_url` | string | required | Public-facing base URL; used to construct enrollment and approval links sent in emails |
| `secret_key` | string | required | Long random secret used to sign enrollment tokens and admin session cookies. Treat as a credential — do not commit to version control |

---

## `auth`

Controls approver account and authentication behavior. See [account-management.md](account-management.md) for full context.

| Field | Type | Default | Description |
|---|---|---|---|
| `enrollment_link_expiry_hours` | integer | `24` | How long an enrollment link is valid. Set to `0` to disable expiry (not recommended) |
| `password_min_length` | integer | `12` | Minimum password length enforced at enrollment and password reset |
| `totp_window` | integer | `1` | Number of 30-second TOTP steps to accept on either side of the current time. `1` means codes from up to 90 seconds ago or 90 seconds in the future are accepted, tolerating clock drift |
| `pbkdf2_iterations` | integer | `600000` | PBKDF2 iteration count used when deriving the MFKDF signing key at approval time. Higher is more resistant to brute force; lower is faster. 600,000 follows OWASP recommendations for PBKDF2-HMAC-SHA256 |
| `admin_session_expiry_hours` | integer | `8` | Lifetime of an authentication portal session cookie |

---

## `notifications`

### `notifications.email`

Controls SMTP email delivery for enrollment links and approval request notifications.

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Set to `false` to disable email delivery entirely. Enrollment links and approval links must then be distributed manually via the authentication portal |
| `smtp_host` | string | required if enabled | SMTP server hostname |
| `smtp_port` | integer | `587` | SMTP server port. Common values: `587` (STARTTLS), `465` (TLS), `25` (plain, not recommended) |
| `smtp_user` | string | required if enabled | SMTP authentication username |
| `smtp_password` | string | required if enabled | SMTP authentication password. Consider loading from an environment variable (see below) |
| `from_address` | string | required if enabled | The `From:` address on outgoing emails. Can include a display name: `"Name <addr@example.com>"` |
| `tls` | bool | `true` | Use STARTTLS when connecting. Set to `false` only for local development SMTP servers |
| `fallback_to_portal` | bool | `true` | If email delivery fails, log the error and display the link in the authentication portal instead of failing hard. Recommended for MVP |

### Emails Sent

| Event | Recipient | Content |
|---|---|---|
| Admin creates a user account | New approver | Enrollment link (expires per `auth.enrollment_link_expiry_hours`) |
| New approval request created | All approvers for the service | Approval link, service name, and basic request summary |

---

## `services`

Each key under `services` defines a protected service. The key is the service ID (used in logs and approval requests).

| Field | Type | Required | Description |
|---|---|---|---|
| `approvers` | list of strings | yes | Usernames of users who can approve requests for this service. Must exist as active user accounts |
| `quorum` | integer | yes | Minimum number of approvers who must approve before the request proceeds |
| `type` | string | yes | `one-time` or `forward-auth` (see below) |
| `action` | string | if `type: one-time` | The action to execute after quorum is reached (e.g., `publish-to-pypi`) |
| `backend` | string | if `type: forward-auth` | URL of the upstream service to forward requests to after approval |
| `credentials` | map | depends on action | Credentials required to execute the action (e.g., `pypi_token`). Treat as secrets — see environment variable substitution below |

### Service Types

**`one-time`** — After quorum is reached, the proxy executes a single action (e.g., publish a package to PyPI) and does not grant the requester an ongoing session.

**`forward-auth`** — After quorum is reached, the proxy grants a session and forwards the requester's HTTP request to the `backend` URL, injecting identity headers. Used for protecting internal web applications.

### `services.*.headers` (forward-auth only)

Controls which identity headers are injected into upstream requests on forward-auth success, and what they are named. All fields are optional; defaults match Authelia's header names for drop-in compatibility.

```yaml
services:
  internal-app:
    type: forward-auth
    backend: http://internal-app:8080
    headers:
      remote_user: X-Remote-User       # username; default: X-Remote-User
      remote_name: X-Remote-Name       # display name (same as username in MVP); default: X-Remote-Name
      remote_email: X-Remote-Email     # user email; default: X-Remote-Email
      remote_groups: X-Remote-Groups   # user groups field (free text); omitted if user has no groups set; default: X-Remote-Groups
```

| Field | Default header name | Value injected |
|---|---|---|
| `remote_user` | `X-Remote-User` | The authenticated user's username |
| `remote_name` | `X-Remote-Name` | The authenticated user's username (display name not separately stored in MVP) |
| `remote_email` | `X-Remote-Email` | The authenticated user's email address |
| `remote_groups` | `X-Remote-Groups` | The user's `groups` field verbatim; header is omitted entirely if the field is null |

Set a field to `false` to suppress that header entirely:

```yaml
headers:
  remote_groups: false   # do not send X-Remote-Groups to this backend
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
