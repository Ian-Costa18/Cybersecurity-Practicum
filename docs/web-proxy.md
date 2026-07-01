# Web Proxy Application Specification

This document specifies the HTTP behavior, request flows, session model, and endpoint surface of the Multi-Signature Authentication Web Proxy. For cryptographic primitives, see [cryptography.md](cryptography.md). For user account model and enrollment, see [account-management.md](account-management.md). For configuration reference, see [config.md](config.md). For the request/approval **state machine** (the states a request moves through and the events it emits), see [request-lifecycle.md](request-lifecycle.md) — this document describes the HTTP surface over that lifecycle and does not redefine its states.

---

## Overview

The proxy sits in front of protected services and requires m-of-n Approvers to independently authenticate and explicitly approve before a Requester is granted access or an action is executed. All participants — Requesters and Approvers — are Users with proxy accounts. The same person routinely acts as Requester for one service and Approver for another.

Two service types are supported:

| Type | Pattern | Requester experience |
|---|---|---|
| `forward-auth` | Reverse proxy delegates auth decision to the proxy; on approval, request is forwarded to the backend | Browser-based; Requester waits in a real-time waiting room until quorum is reached |
| `one-time` | Requester submits a payload directly to the proxy; proxy executes an action after quorum | Async; Requester gets immediate acknowledgment, then email notifications |

---

## Entry Points

### Forward-Auth Entry Point

The proxy acts as the auth service for a reverse proxy (NGINX `auth_request`, Traefik `ForwardAuth`, Caddy `forward_auth`). The Requester's browser never directly contacts the proxy for the initial request — the reverse proxy makes a subrequest to `GET /auth` on the Requester's behalf.

The reverse proxy must be configured to:
- Forward every request to `GET /auth` before passing it upstream
- **Redirect the browser to the login URL on a `401` response.** This is *not* automatic for every reverse proxy. Traefik `ForwardAuth` and Caddy `forward_auth` follow the auth service's redirect, but stock NGINX `auth_request` denies with `401` and **ignores** any `Location` header — turning that into a login redirect requires an operator-configured `error_page 401 = @login` (or equivalent). Treat the contract as "the reverse proxy must be configured to redirect to the login URL on `401`," not as something the proxy can force. Sources: [nginx auth_request module](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html), [NGINX subrequest authentication guide](https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-subrequest-authentication/).
- Forward the proxy's `200` response headers (identity headers) to the backend

### One-Time Entry Point (PyPI)

The Requester submits directly to `POST /pypi/legacy/` using a tool like Twine. `POST /pypi/legacy/` is a **proxy-local route** that emulates the [PyPI legacy upload API](https://docs.pypi.org/api/upload/) (whose real upload path is `/legacy/`, not `/pypi/legacy/`), so existing tooling requires no changes beyond pointing at the proxy URL.

---

## Forward-Auth Flow

### Step-by-Step

1. **Browser** requests `https://internal-app.example.com/dashboard`
2. **Reverse proxy** calls `GET /auth` (subrequest, no browser redirect yet)
3. **Proxy** checks for a valid Service Grant for this User + service:
   - **Grant found and not expired** → return `200` with identity headers; reverse proxy forwards request to backend. Done.
   - **No grant** → return `401` with `Location: /login?service=internal-app&return_to=...`
4. **Reverse proxy** redirects browser to the login page
5. **Browser** loads `GET /login`; User submits password + TOTP
6. **Proxy** authenticates; issues a Proxy Session cookie (cookie-based, `HttpOnly`, `Secure`, `SameSite=Strict`)
7. **Proxy** redirects to the session-guarded `GET /access?service=…&return_to=…` trigger (the post-login access hop, [ADR 0012](adr/0012-vertical-slice-package-layout.md)), which finds-or-creates the Approval Request for this User + service:
   - **Pending request found** → redirect to `GET /pending/{approval_request_id}` (resume; no re-notification)
   - **No pending request** → create the Approval Request, emit `request.created` (notifying Approvers via SMTP), redirect to `GET /pending/{approval_request_id}`
8. **Waiting room** (`GET /pending/{id}`) opens SSE stream (`GET /pending/{id}/stream`) and displays:
   - Spinner with time elapsed since the request was created
   - Quorum progress counter (e.g., "2 of 3 approvals received")
   - Service name and request summary
9. **Approvers** receive notification emails with Approval Links; they click, re-authenticate, and approve or deny
10. **On quorum reached**: proxy issues a Service Grant; SSE stream pushes a `quorum_reached` event; waiting room redirects browser back to the original URL
11. **Reverse proxy** calls `GET /auth` again; proxy finds the Service Grant → returns `200` with identity headers; request proceeds to backend

### Session Persistence

A Proxy Session persists across requests and services for its configured lifetime (default 8 hours). A User who has already logged in and visits a different `forward-auth` service will skip steps 4–6 and go directly to step 7. Proxy Sessions do not grant access to any service on their own — a Service Grant is always required.

### Resuming After Disconnection

If a Requester's browser crashes or their Proxy Session expires while an Approval Request is in flight:

- **Session still valid**: visiting the original URL again (or navigating directly to `/pending/{id}`) resumes the waiting room seamlessly.
- **Session expired**: the Requester authenticates again (step 5–6); login redirects through `GET /access`, which finds the existing pending Approval Request by User ID + service (no re-notification) and redirects to the waiting room.
- **Quorum was reached while offline**: the proxy has already issued the Service Grant. When the Requester hits the original URL again, `GET /auth` returns `200` immediately and they are forwarded to the backend without going through the waiting room.

The `/pending/{id}` page is scoped to the Requester who created the request. A different authenticated User visiting that URL receives a `403`.

### Service Grant Expiry

The Service Grant state model (`active → expired`, time-windowed, no revocation in MVP) is defined in [request-lifecycle.md](request-lifecycle.md). This section covers only the HTTP-facing configuration and consequence.

A Service Grant has a configurable lifetime (`grant_expiry_hours` per service in [config.md](config.md)). When set to `0`, the grant expires with the Proxy Session — `expires_at` is bound to the session's end rather than a fixed timestamp, so this is still the single `expires_at` trigger defined in [request-lifecycle.md](request-lifecycle.md), not a second one. Permanent grants are not supported. Expiry is evaluated **lazily at `GET /auth`** (no scheduler in MVP): on expiry (`active → expired`), the next request to the service finds no valid grant and triggers a new Approval Request.

---

## One-Time Flow (PyPI Publish)

1. **Developer** configures Twine to point at the proxy:
   ```ini
   [distutils]
   index-servers = proxy

   [proxy]
   repository = https://proxy.example.com/pypi/legacy/
   username = __token__
   password = <proxy-issued API token>
   ```
2. **Twine** POSTs the package to `POST /pypi/legacy/` with HTTP Basic Auth (`__token__` + API token)
3. **Proxy** authenticates the API token, identifies the Requester
4. **Proxy** *(planned pre-upload validation — not yet implemented):* before accepting the artifact the proxy is intended to
   - Parse and validate package metadata and file format locally, and
   - Query `https://pypi.org/pypi/{name}/{version}/json` — if `200`, that version already exists on PyPI and the upload will definitely be rejected; the proxy returns an error to Twine immediately and no Approval Request is created (proceeding best-effort if the JSON API is unreachable).

   **In the current MVP the upload path performs no pre-validation:** a duplicate-version or malformed-metadata upload is accepted and only rejected at publish time, *after* quorum (see [constraints.md §7](constraints.md)). The check above is the target design.
5. **Proxy** computes SHA-256 of the artifact, stores the artifact, creates an Approval Request bound to that hash
6. **Proxy** returns `200` with a PyPI-compatible response body — Twine exits cleanly
7. **Proxy** returns the Approval Request id on the upload response (the `X-Approval-Request-Id` header); the Requester can optionally watch quorum progress in real time at `GET /pending/{id}`. **No upload-acknowledgment email is sent** — the [notification matrix](notification-system.md) routes the Requester to *outcome* events only (the `request.created` email goes to approvers, pulling them to the approve/deny page). The Requester is emailed on the **terminal** outcome (step 9), regardless of whether they visited the waiting room.
8. **Approvers** receive notification emails with Approval Links; they authenticate and approve asynchronously
9. **On quorum reached**: the Approval Request hands off to an **Action** (see [request-lifecycle.md](request-lifecycle.md) for its `queued → running → succeeded/failed` lifecycle). The executor publishes the stored artifact to real PyPI using the configured Service Credential (PyPI upload token). Per the Action's hybrid retry policy, a **transient** failure (network error, timeout, 5xx) is retried automatically up to `max_attempts`; a **permanent** rejection (e.g., PyPI "version already exists", a 4xx) goes straight to terminal `failed`. The Requester is emailed only on a **terminal** outcome:
   - `succeeded`: *"Your package `foo-1.2.3` has been published to PyPI."*
   - `failed`: *"Publication of `foo-1.2.3` failed: [PyPI error message]."*
10. The stored artifact is deleted from proxy storage when the Action reaches a terminal state (`succeeded` or `failed`) or after denial

### Hash Binding

The artifact's SHA-256 hash is computed and recorded in the Approval Request at step 5. Approvers approve that specific hash. If the stored artifact is tampered with between upload and publication, the hash will not match and publication is blocked regardless of quorum status.

---

## Waiting Room

The waiting room page (`GET /pending/{id}`) is available for both service types:

- **`forward-auth`**: the Requester is redirected here automatically after login. When quorum is reached, the page redirects the browser to the original URL.
- **`one-time`**: the Requester arrives via a link in the "pending approval" email. If they have no active Proxy Session, they are redirected to `/login?return_to=/pending/{id}` and land on the waiting room after authenticating — the same flow as a `forward-auth` Requester returning after session expiry. When the action completes, the page shows a result screen (success or failure) instead of redirecting. *(MVP: the waiting-room stream is service-type-agnostic — a one-time request currently emits the generic `quorum_reached` frame on approval; the dedicated `action_*` result-screen events below are post-MVP, see [#83](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/83).)*

The completion email is sent regardless of whether the Requester has the waiting room open.

### Real-Time Updates (SSE)

The page opens a Server-Sent Events connection to `GET /pending/{id}/stream`. These SSE messages are the **waiting-room projection** of the lifecycle events defined in [request-lifecycle.md](request-lifecycle.md) — they are the transport for the quorum-progress-UI consumer, not a separate vocabulary. The server pushes a message when a relevant lifecycle event fires:

| SSE message | Projects lifecycle event | Payload | Who receives it | Action |
|---|---|---|---|---|
| `approval` | `request.vote_recorded` | `{"count": 2, "required": 3, "state": "pending"}` | Both | Update quorum counter |
| `quorum_reached` | `request.approved` | `{"count": 3, "required": 3, "state": "approved"}` | `forward-auth` (MVP: also `one-time`) | Redirect browser to the original URL (`return_to`) |
| `action_retrying` | `action.retrying` | `{"attempt": 2, "max": 3, "message": "..."}` | `one-time` only *(post-MVP, [#83](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/83))* | Show "publishing failed, retrying" status |
| `action_completed` | `action.succeeded` | `{"status": "success", "message": "..."}` | `one-time` only *(post-MVP, [#83](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/83))* | Show success result screen |
| `action_failed` | `action.failed` | `{"status": "failed", "message": "..."}` | `one-time` only *(post-MVP, [#83](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/83))* | Show failure result screen |
| `denied` | `request.denied` | `{"count": 1, "required": 3, "state": "denied", "reason": "..."}` | Both | Show denial message + reason |

Every quorum-progress frame (`approval` / `quorum_reached` / `denied`) carries the same three base fields — `count`, `required`, and `state` (the projected Approval Request lifecycle state) — so the page can update the counter and the status line from any frame with one handler; the `denied` frame adds the optional `reason` (null when the Approver gave none). In the target one-time design a watching Requester sees `action_retrying` updates while transient failures are retried, with `action_completed` or `action_failed` terminal; in the current MVP (no persisted Action, [#83](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/83)) the stream instead closes on the `quorum_reached` frame for a one-time request. The page polls elapsed time locally (no server involvement) to drive the spinner clock.

### Denial State

The `denied` state is terminal and is reached on the **first** denial (the single-denial rule is defined in [request-lifecycle.md](request-lifecycle.md); a denied request cannot be reopened or overridden). This section covers the waiting-room UI for that state.

On the `request.denied` event the SSE stream pushes a `denied` message and the waiting room transitions to a denial screen showing:

- Which service the request was for
- The optional denial reason (free text) provided by the Approver
- A "Request again" button that creates a **new** Approval Request for the same service (the Requester must explicitly initiate it; the denied one is never reused)

> **Security note:** Immediate retry is permitted in the MVP. This creates an MFA-bombing / approval-fatigue risk (T12) and a request-flooding risk (T27 in the threat model) — a Requester can flood Approvers with repeated requests after each denial. Rate limiting is planned; operators should monitor request volume until it is implemented.

---

## Approver Authentication and the Approve/Deny Page

### Re-Authentication Requirement

Clicking an Approval Link always requires the Approver to authenticate (password + TOTP), even if they hold an active Proxy Session. This prevents a stolen or expired session from being used to approve requests.

The authentication form at `GET /approve/{id}` is scoped to that specific approval action. After authentication, the Approver sees the approve/deny page and is not granted a new Proxy Session.

### Approve/Deny Page Content

The approve/deny page is reachable with the Approval Link alone — *viewing* it requires no login (security rests on the per-vote re-authentication, not on hiding the page). It shows:

- Service name and request summary
- Requester identity
- **Live quorum status with named endorsers.** The **Endorsing Approvers** — the Users whose *effective* vote is `approve` — are **named**, and everyone else is shown only as a remaining count: e.g. *"Approved by Alice & Bob — 2 of 3, waiting on 1 more."* Approvers who denied, withdrew, or have not acted are **never named** (a withdrawal drops the User off the list, indistinguishable from one who never acted). This list **updates live** as other Approvers act — see [Live Endorser Updates](#live-endorser-updates-sse).
- For `one-time` (PyPI): SHA-256 hash of the artifact and a download link so the Approver can inspect it locally before deciding
- For `forward-auth`: HTTP method, URL, and relevant request headers
- **Approve** and **Deny** buttons; Deny includes an optional free-text reason field

### Live Endorser Updates (SSE)

The page opens a Server-Sent Events connection to `GET /approve/{id}/stream`. This is the **approver-facing parallel** of the [waiting room's stream](#real-time-updates-sse): the same poll-and-diff projection of the request's votes, reusing the same `approval` / `quorum_reached` / `denied` event vocabulary — not a second live-update mechanism. Two differences from the waiting room stream:

- **Link-scoped, not owner-scoped.** The approve page has no requester-ownership check, so this stream omits the waiting room's `403`-if-not-owner guard. It is reachable with the Approval Link alone and is **not** gated behind a view-time login.
- **Payload carries endorser identities.** Each frame adds an `endorsers` array (the effective-approve usernames) to the base `count` / `required` / `remaining` / `state` fields. The change-detection key is the **set of endorser identities**, not just the count — a withdraw paired with a new approve holds the count constant while the names change, and that frame must still be pushed.

When the request reaches a terminal state (quorum reached or denied) while an Approver is watching, the stream emits the terminal frame and closes, and the page reflects the closed state — consistent with how the page already handles a vote on an already-closed request.

---

## Identity Headers (Forward-Auth)

On a `200` response to the reverse proxy's `auth_request` subrequest, the proxy injects identity headers describing the authenticated Requester. Header names are configurable per service (see [config.md](config.md)); defaults match Authelia's conventions for drop-in compatibility.

| Default header | Value |
|---|---|
| `Remote-User` | Username |
| `Remote-Name` | Username (display name; same as username in MVP) |
| `Remote-Email` | Email address |
| `Remote-Groups` | User's `groups` field verbatim; **omitted entirely** if the field is null |

Any header can be renamed or suppressed per service. The `Remote-Groups` value is free text set by an admin — the proxy does not interpret it.

---

## API Tokens (Programmatic Access)

Users may generate per-user API tokens for tools (like Twine) that cannot perform interactive TOTP. A User may hold **multiple** labeled tokens (one per machine or context, e.g. `"work laptop"`, `"CI runner"`), each created and revoked from the User Portal. An API token:

- Is a long randomly generated string, scoped to submission endpoints only (`POST /pypi/legacy/` and equivalent one-time upload endpoints)
- Is stored only as a **hash**; the plaintext is shown **once** at creation and is never retrievable afterward
- Is **individually revocable** — revoking one token does not affect the User's other tokens, password, or TOTP
- **Cannot** be used to log into the Admin Portal, the User Portal, the waiting room, or to approve requests
- Is presented via HTTP Basic Auth as `__token__:<api_token>`

A User revokes their own tokens from the User Portal; an admin may also revoke (but not create or view) a User's tokens from the Admin Portal, keeping the admin out of the credential path.

---

## User Portal

The **User Portal** (`/account`) is the authenticated self-service surface available to **any enrolled User**, distinct from the Admin Portal (`/admin`, `is_admin` only). It is the **first non-admin authenticated surface** in the proxy: every prior User-facing flow either used a stateless per-approval re-auth (approve/deny) or no session at all. The User Portal requires only a **Proxy Session** (the same server-side, revocable session a User obtains by logging in) — no `is_admin` flag.

It is organized by **capability, not role**, because one User is simultaneously a Requester and an Approver across different services. Capabilities:

- **Manage own API Tokens:** Create a new labeled token (plaintext shown once at creation), and revoke any of the User's existing tokens.
- **View own Approval Requests:** List the requests the User has created with their current status, and **cancel** ones still `pending` (the existing `request.cancelled` transition defined in [request-lifecycle.md](request-lifecycle.md)).
- **View requests the User may approve:** List Approval Requests for which the User is an eligible Approver, showing the User's own current Vote, and cast / change / withdraw that Vote on requests still `pending`.

### Voting Still Requires Re-Authentication

Viewing the portal needs only a Proxy Session, but **casting, changing, or withdrawing a Vote always requires fresh password + TOTP re-authentication**. Approver sessions remain stateless, and a Vote is cryptographically signed — which requires the password to decrypt the signing key. The portal therefore **shows** the User's votes and requests but routes any vote *action* through the existing re-auth approval flow (`POST /approve/{id}`); it is **not** a frictionless one-click button. A withdraw or change is just another signed Vote cast through that same flow (append-only; see [request-lifecycle.md](request-lifecycle.md)).

---

## Admin Authorization

All endpoints under `/admin/*` require both:

1. A valid Proxy Session (authenticated User)
2. `is_admin = true` on the User's account

Any request to an `/admin/*` endpoint that fails either check receives a `403`. The Admin Portal uses the same server-side, revocable Proxy Session as every other authenticated surface, sharing the same configurable lifetime (`session_expiry_hours`, default 8 hours).

---

## HTTP Endpoints

| Method | Path | Auth required | Purpose |
|---|---|---|---|
| `GET` | `/auth` | Proxy Session (or none → 401) | Forward-auth subrequest from reverse proxy |
| `GET` | `/login` | None | Login page |
| `POST` | `/login` | None | Login form submission |
| `GET` | `/access` | Proxy Session | Forward-auth post-login access trigger: find/create the Approval Request, emit `request.created` on a new one, then redirect to the waiting room |
| `GET` | `/pending/{id}` | Proxy Session (Requester only) | Waiting room page |
| `GET` | `/pending/{id}/stream` | Proxy Session (Requester only) | SSE stream for quorum updates |
| `POST` | `/pypi/legacy/` | API token (HTTP Basic Auth) | Twine-compatible package upload |
| `GET` | `/approve/{id}` | None (re-auth prompt shown) | Approval link landing and re-auth form |
| `GET` | `/approve/{id}/stream` | None (link-scoped) | SSE stream of live endorser/quorum status |
| `POST` | `/approve/{id}` | Fresh approval auth (per-request) | Approve or deny form submission |
| `GET` | `/enroll/{token}` | None | Enrollment link landing |
| `POST` | `/enroll/{token}` | None | Set password + TOTP on enrollment |
| `GET` | `/account` | Proxy Session | User Portal home (self-service) |
| `POST` | `/account/tokens` | Proxy Session | Create an API token (plaintext returned once) |
| `DELETE` | `/account/tokens/{id}` | Proxy Session | Revoke one of the User's own API tokens |
| `GET` | `/account/requests` | Proxy Session | List the User's own Approval Requests with status |
| `POST` | `/account/requests/{id}/cancel` | Proxy Session | Cancel one of the User's own `pending` requests (`request.cancelled`) |
| `GET` | `/account/approvals` | Proxy Session | List requests the User may act on, with the User's current Vote |
| `GET` | `/admin` | Proxy Session + is_admin | Admin Portal |
| `POST` | `/admin/users` | Proxy Session + is_admin | Create user |
| `PATCH` | `/admin/users/{id}` | Proxy Session + is_admin | Edit user (groups and non-credential fields) |
| `POST` | `/admin/users/{id}/deactivate` | Proxy Session + is_admin | Deactivate user (`is_active = false`) |
| `DELETE` | `/admin/users/{id}` | Proxy Session + is_admin | Delete user (irreversible) |
| `POST` | `/admin/users/{id}/reset` | Proxy Session + is_admin | Reset user credentials; issue new enrollment link |
| `POST` | `/admin/users/{id}/enrollment-link` | Proxy Session + is_admin | Regenerate enrollment link |
| `DELETE` | `/admin/users/{id}/tokens/{token_id}` | Proxy Session + is_admin | Admin revokes a User's API token (cannot create or view) |

> The User Portal does **not** add an endpoint for casting, changing, or withdrawing a Vote. Those actions reuse the existing `POST /approve/{id}` re-authentication flow (fresh password + TOTP), since a Vote must be cryptographically signed. `/account/approvals` only surfaces the requests and the User's current Vote; acting on one links out to `/approve/{id}`.

---

## Known Limitations

The following are documented trade-offs accepted for the MVP. They are not bugs.

- **No approval request expiration.** Pending requests do not time out. A request can remain open indefinitely until an Approver acts or the Requester's account is deactivated.
- **No rate limiting on request creation.** A Requester can open new Approval Requests immediately after a denial. See T12 (approval fatigue) and T27 (resource flooding) in the threat model.
- **Service credentials held unencrypted in memory.** PyPI tokens and shared account credentials are loaded from config at startup and held in process memory. A compromised proxy host can read them. Mitigated in a future version by per-user credential wrapping.
- **Shared account password reset bypass.** Out-of-band credential recovery on the external service (e.g., password reset emails) is not gated by the proxy. See T24 in the threat model.
- **No self-service credential recovery.** Requesters and Approvers who lose their credentials must contact an admin.
