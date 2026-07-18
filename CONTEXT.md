# Domain Context: Multi-Party Authorization Proxy

## Overview

This is a **general-purpose web authorization proxy** that requires multiple distinct people (approvers) to grant access or approve an action before it is allowed to proceed. The core goal is to **demonstrate that multi-signature (m-of-n) approval is valuable far beyond cryptocurrency custody** — in supply-chain security, sensitive data access, infrastructure management, and other domains where a single actor should not have unilateral control.

Multi-party authorization distributes trust: even if one approver is compromised, an attacker cannot unilaterally approve actions. The system is designed to integrate seamlessly with arbitrary web applications and workflows, protecting both internal systems (forward-auth pattern) and external transactional flows (one-time approvals).

> **Terminology.** *Multi-party authorization (MPA)* is this project's mechanism: a quorum of distinct, authenticated humans authorizing an action. Reserve *multi-signature* / *threshold signature* for the **cryptographic** schemes (BIP-11, MuSig2, FROST) we researched and invoke only by analogy — they are not a name for this system. Earlier drafts branded the project "Multi-Signature Authentication"; that framing conflated our human-quorum authorization with crypto signing and has been retired.

## Where things live

This file is the domain glossary and architectural front door. For a map of all prose docs (specs, ADRs, research, use cases), see [docs/index.md](docs/index.md). Each substantial subdirectory has its own `index.md`. For the package's slice structure and the dependency rule, see [docs/source-layout.md](docs/source-layout.md). For code, use the sverklo index (`sverklo_overview` / `sverklo_search`) over `src/msig_proxy/` rather than reading these docs.

## Core Concepts

### User

A person with a proxy account (password + TOTP + Ed25519 key pair). All proxy participants — whether triggering access or approving it — are Users. There is no separate Requester or Approver account type; the same person routinely acts as Requester for one service and Approver for another (e.g., members of a development team).

### Requester
The role a User plays when they are seeking access to a protected service or submitting an artifact for approval. A Requester is always a User — they authenticate to the proxy before any approval request is created.

### Approver
The role a User plays when they are evaluating and deciding on an Approval Request. Approvers are configured per Service. The same User can be a Requester for one Service and an Approver for another. Approvers are assumed to be trusted — the system design assumes a quorum of them will not collude to bypass security.

### Endorsing Approver

The role an Approver occupies when their Effective Vote on a specific Approval Request is approve at the moment the request reaches its outcome. Distinct from the eligible (snapshot) approver set — who *may* vote — and from an Approver who denied or withdrew. An Endorsing Approver has put their name on that request; the notification system therefore treats them as a recipient for the request's terminal outcome, the same outcomes the Requester receives (see [notification-system.md](docs/notification-system.md)).

### Admin

The role a User plays when administering accounts rather than participating in an approval. An Admin is an ordinary User carrying an `is_admin` flag; they create, activate, reset, edit, and deactivate other Users through the Admin Portal, and they never see or issue another User's credentials. Being an Admin confers no Vote and no power to override a Quorum — administration deliberately sits outside the approval path.

### Operator

The human who deploys and runs the proxy, holding host access, configuration, and secret material — as distinct from an Admin, who holds a proxy account. An Operator acts on the deployment (config file, network topology, scheduled tooling), not through the proxy's web surface, and may hold no proxy account at all: it is an Operator who bootstraps the very first Admin. The distinction is load-bearing for the threat model, where a class of mitigations is enforceable *only* by an Operator (deployment, placement, topology) and is therefore never claimed as a system defense. In practice one human is usually both, exactly as one User is usually both Requester and Approver.

### Approval Request
The aggregate representing the **approval core** of a request: a uniquely-identified object that waits for approvers to grant their consent. Bound to a specific hash (if applicable) or resource, preventing tampering or substitution. Its lifecycle is purely the approval decision — it reaches a terminal state of `approved`, `denied`, or `cancelled` (requester cancellation) and does not itself perform any post-approval work. (A timeout-driven `timed_out` terminal is reserved for the approval-timeout feature and is not yet reachable in the MVP.) On `approved`, it hands off to a **Post-Approval Object** (a [Service Grant](#service-grant) for forward-auth, or an execution object for one-time flows). The Approval Request and the Post-Approval Object it spawns are **bidirectionally linked**: each carries its own unique ID and references the other, so an auditor can walk from an approval to what it caused, and from an executed action back to the vote that authorized it. Reaching a terminal state concludes the *vote*, not the *record* — the forward link to the spawned object is written at handoff.

### Quorum
The minimum number of approvers who must grant approval before a request is allowed to proceed. Configured per service (e.g., "3-of-5 approvers"). The quorum threshold is a security/availability trade-off: higher quorum = harder to compromise but more friction for legitimate requests.

### Vote

An Approver's signed approve, deny, or withdraw decision on a specific Approval Request. Votes are **append-only**: a later vote by the same Approver supersedes their earlier one rather than overwriting it, so the full sequence of an Approver's decisions is preserved for audit. A vote may only be cast or changed while the request is `pending`.

### Effective Vote

An Approver's most recent Vote while an Approval Request is `pending` — the one that counts toward Quorum and the single-denial rule. A *withdraw* leaves that Approver with no effective approve or deny. Quorum and denial are always computed from effective votes, never from the full vote history.

### Superseded Vote

A Vote that a later Vote from the same Approver has replaced. Retained permanently in the audit trail (never deleted) but no longer counted.

### Signing Key

A User's Ed25519 key pair, used to sign their Votes. A User has at most one **active** Signing Key at a time — the one their new Votes are signed with — but accumulates **retired** keys over their lifetime as credentials are reset or rotated. A Signing Key is *born active* at enrollment with both halves (public, and a private half encrypted under the User's password) and is *retired* on reset/rotation: retirement drops the private half permanently and keeps only the public half, so the key can still verify the historical Votes it signed but can never sign again. Retired keys are never deleted — offline verification of an old Vote resolves the exact Signing Key that signed it, not the User's current one. A reset User may temporarily have *no* active key (after retirement, before re-enrollment), mirroring the credential-less enrolled-pending state.

### Service
A protected resource or action (e.g., "PyPI publish," "internal billing app," "database backup"). Each service is configured with its own set of approvers and quorum threshold in the YAML config.

### Access Control List (ACL)
A YAML configuration file that specifies, for each protected service: who the approvers are, what the quorum threshold is, and how the proxy should handle the request after approval (forward it to a backend app, execute an action, etc.).

### Endpoint
The outbound destination URL a Service talks to, configured per Service. One field across both service types: for **forward-auth** it is the **backend** — the protected upstream a granted request is proxied to (required); for **one-time** it is the external API the approved Action is published to (optional, defaulting to PyPI's legacy upload URL). "Backend" is the forward-auth *role* the Endpoint plays, not a separate field — the config key is `endpoint` in both cases.

### Proxy Session
A persistent, cookie-based login session issued to a User after they authenticate to the proxy (password + TOTP). A Proxy Session identifies the User across multiple requests and services and does not require repeated logins. A Proxy Session does not, by itself, grant access to any Service — approval is still required per Service.

### User Portal

The authenticated self-service area where a User, acting in their own roles, manages their API Tokens, tracks the Approval Requests they have created (and cancels ones still `pending`), and reviews and changes their own votes on requests they may approve. Organized by capability, not by role, because one User is simultaneously a Requester and an Approver across different Services. Distinct from the Admin Portal, which is for account administration by an `is_admin` User.

### Service Grant
A **Post-Approval Object** for forward-auth services: a record that a specific User has received quorum approval for a specific Service, issued when an Approval Request reaches `approved`. A Service Grant allows the User to access the Service for the duration of its lifetime without triggering a new Approval Request. Scoped to one User + one Service; does not affect other Services. Has its own lifecycle (active → expired; no revocation in MVP) and its own unique ID, and is bidirectionally linked to the Approval Request that authorized it.

### Post-Approval Object
The umbrella term for whatever an Approval Request hands off to when it reaches `approved`. The Approval Request owns the *approval core*; the Post-Approval Object owns what happens *after* approval, with a lifecycle specific to the service's configured behavior. Two types are modelled — the [Service Grant](#service-grant) (forward-auth: grants interactive access) and the [Action](#action) (one-time: executes an operation against an external service) — and the model is open to more types later. A Post-Approval Object carries its own unique ID and is bidirectionally linked to its Approval Request for audit — realized today for the **Service Grant**; the one-time path currently executes synchronously at handoff and does not yet persist a separate **Action** aggregate (deferred post-MVP, see [Action](#action)).

### Service Handler
The per-service-type behavior, *formerly the Post-Approval Handler*. Each service type's slice owns its behavior across the request's **whole lifetime** — intake, staging, terminal handling, and (for forward-auth) consumption — so the handler is named for the service type it speaks for, not for the post-approval moment alone. The **producer** of a [Post-Approval Object](#post-approval-object) is the part of that behavior reached at a terminal state. Distinct from the Post-Approval Object it produces: the *Object* is the product (a [Service Grant](#service-grant), an [Action](#action)) and is persisted and bidirectionally linked; the *Handler* is stateless behavior derived from the request's `service_type`.

Its **dispatched interface is narrow** — the terminal hooks both types genuinely share: `on_approved` (do the handoff), `on_denied` and `on_cancelled` (type-specific cleanup). It is narrow because terminal handling is the *only* point reached without knowing the service type (the generic vote/cancel path holds a request whose type it must recover at runtime); intake and consumption are reached from type-specific entry points, so they are sibling logic in the slice, not handler methods. One handler exists per service type; the dispatcher resolves it from the request and stays free of any per-type `if`. The dispatcher and the side-effecting primitives are slice logic — never methods on the `ApprovalRequest` model, which depends only on data, so behavior reaching out to the publish boundary, notifications, or the session cannot sit on it. See [source-layout.md](docs/source-layout.md) and [ADR 0012](docs/adr/0012-vertical-slice-package-layout.md).

### Action
A **Post-Approval Object** for one-time services: the operation a Requester is trying to make happen (e.g., "publish this package to PyPI"). In the target design it is tracked through an **execution lifecycle** (queued → running → succeeded/failed, retriable on failure), created when an Approval Request reaches `approved`, carrying its own unique ID and bidirectionally linked to the Approval Request that authorized it. **In the current MVP this persisted aggregate does not yet exist** (deferred post-MVP, see [#83](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/83)): one-time approval executes its action synchronously as a single attempt at handoff, so there is no separate Action row, ID, or back-reference — only the `action.succeeded` / `action.failed` outcome is signalled. The payload an Action will execute is fixed at request time and bound by `action_hash`, so approvers vote on exactly what will run. Note: capital-**A** "Action" is this aggregate; lowercase "action" is the generic verb-sense ("the proxy executes an action") used elsewhere in the docs.

### Approval Link
A unique URL (e.g., `https://proxy.example.com/approve/{approval_id}`) generated for each Approval Request and sent to Approvers via notification. Clicking the link requires the Approver to re-authenticate (password + TOTP) regardless of whether they hold an active Proxy Session — this prevents a stolen session from being used to approve requests. The link itself is not secret; security comes from the re-authentication step. An Approval Link is bound to the Requester who created the request; only the designated Approvers for that Service can act on it.

### Hash Binding
A mechanism to prevent tampering with the payload (e.g., a software package) between upload and publication. When a Requester uploads a package, the system immediately computes its cryptographic hash and records it as part of the approval request. Approvers approve that specific hash. If an attacker modifies the package after approval, the hash will no longer match, and publication is blocked.

### Credential-Backed Approval
An approval model in which approvers do not hold additional cryptographic keys. Instead, they authenticate using their regular credentials (password + 2FA) and their approval is backed by that authentication. The system records the approval in a way that ties it to the approver's identity, preventing a compromised proxy from retroactively forging approvals.

### API Token
A long-lived, randomly generated credential issued by the proxy to a User for programmatic (non-browser) access. Used by tools like Twine that send HTTP Basic Auth and cannot perform interactive TOTP. An API Token identifies the User (Requester) without requiring TOTP, but cannot be used to log into the admin portal or to approve requests — it is scoped to submission endpoints only. Revocable independently of the User's password. Distinct from a Service Credential.

### Service Credential
A credential held by the proxy to authenticate to an external service on behalf of Users after quorum is reached. Distinct from a User's proxy credentials. For PyPI this is an upload token; for shared account management this is a username and password. Service credentials are stored in the proxy's configuration (referenced via environment variable substitution) and never exposed to Requesters or Approvers directly.

### Forward-Auth
An architectural pattern (used by Authelia, Traefik, and NGINX) in which a reverse proxy intercepts an HTTP request and asks a separate auth service "is this user allowed?" The auth service responds with allow/deny + identity headers that the proxy injects into the upstream request. Used for protecting internal web applications.

### One-Time Approval
An async post-approval action pattern. The Requester submits an artifact or trigger (e.g., a package upload via Twine) and receives an immediate acknowledgment. The proxy stores the artifact, notifies Approvers, and waits for quorum asynchronously — the Requester does not wait at a browser. Once quorum is reached, the proxy executes the action (e.g., publishes to PyPI) and notifies the Requester by email. Contrasts with forward-auth, where the Requester waits in a browser for quorum before being granted access. Shared account management uses forward-auth, not one-time, because the Requester is waiting for interactive access to a backend.

### Capability

A word with two distinct senses in this project, told apart by whose property it is:

- **Attacker capability** — the position an attacker must *already* hold for a threat to be reachable, graded on the threat model's L1–L9 ladder (remote network position → single stolen credential → database foothold → host code execution → insider → collusion). A property of the adversary, and the anchor for a threat's likelihood rating.
- **System capability** — a behavior the proxy offers that an actor invokes or receives (submit a package, cast a Vote, activate a seat, receive an alarm). A property of the system, and the unit the evaluation demonstrates with backing tests.

The two are recorded separately and never mixed: attacker capability qualifies a threat; system capability names something the system does. The dividing line is grammatical — **a system capability is a verb an actor performs; a mitigation is a property the system holds so that an attacker cannot act.** Rate limiting and encryption at rest are mitigations, not capabilities: an honest actor never invokes them.

### Evidence Item

A named claim backed by tests. The project keeps two kinds, and they differ in everything but that spine: a **system capability** claims the proxy *does* something, and a **threat** claims the proxy *prevents* something. Each carries the pytest node ids that demonstrate it, and a claim whose cited test no longer exists is a contract violation rather than a stale comment. The **evaluation suite** is defined as the union of every evidence item's tests, and is therefore something you run rather than something you assert.

### Evidence Catalog

One of the two files of record for evidence items: the capabilities catalog (`docs/evaluation-capabilities.yaml`) and the threat catalog (`docs/threat-model/`). Each is the sole home of its own values — nothing restates them, so nothing can drift — and both are validated against the same backing-test contract inside the test suite. A capability additionally names the [MVP PRD](docs/mvp-prd.md) user stories it satisfies, which is why that numbering is append-only.

## Architectural Principles

- **No additional key management burden:** Approvers should not need to manage or store additional cryptographic secrets beyond their regular authentication credentials.
- **Distributed approvers:** The system must support approvers located anywhere (different cities, continents) and operating asynchronously. Quorum can be slow to reach; this is acceptable.
- **Hash-bound integrity:** For transactional requests (e.g., package uploads), the payload is bound to the approval via cryptographic hash. An attacker cannot tamper with it between upload and publication.
- **SMTP-first notification:** For MVP, the proxy delivers notifications (enrollment links, approval request links) via SMTP email. The notification layer is kept separate from the approval logic so that additional backends (Slack, Discord, webhooks via Apprise) can be added without touching the core flow.
- **Per-service configuration:** Different services (PyPI, internal app, backup) can have different approval thresholds and post-approval behaviors. Configuration is declarative (YAML).
- **Known limitations accepted for MVP:** The proxy holds publishing credentials in memory for simplicity. A compromised proxy can read those credentials. This is documented as a limitation; future versions can use per-user credential wrapping or external secret managers.

## Threat Model

**Adversary:** An attacker who can compromise a single approver identity (via credential theft, social engineering, or account takeover) or who can compromise the proxy system itself.

**Goal:** Unilaterally approve an action without authorized quorum (e.g., publish malicious code, access sensitive data, modify infrastructure).

**Defenses:**
- **Quorum requirement (m-of-n):** Even if one approver is compromised, the attacker cannot unilaterally approve. They must compromise at least m-1 additional identities.
- **Hash binding (for transactional requests):** Even if the proxy is compromised, an attacker cannot modify a payload (e.g., a package) between submission and publication. The hash will not match what was approved.
- **Credential-backed approval:** If the proxy is compromised *after* approvals are recorded, the approvals cannot be forged retroactively because they are cryptographically tied to the approver's authentication events.

**Out of scope for MVP:**
- Session hijacking after grant (post-approval sessions are ordinary bearer tokens; mitigated by short lifetimes, re-approval for sensitive actions).
- Proxy bypass for external applications (the organization must ensure the proxy is the sole network path to protected services, or the app must natively delegate to the proxy).
- Insider collusion (if m-of-n approvers collude, they can approve anything; the system assumes approvers are trusted to not collude).
