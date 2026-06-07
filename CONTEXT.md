# Domain Context: Multi-Signature Authentication Web Proxy

## Overview

This is a **general-purpose web authentication proxy** that requires multiple distinct people (approvers) to grant access or approve an action before it is allowed to proceed. The core goal is to **demonstrate that multi-signature (m-of-n) approval is valuable far beyond cryptocurrency custody** — in supply-chain security, sensitive data access, infrastructure management, and other domains where a single actor should not have unilateral control.

Multi-signature authentication distributes trust: even if one approver is compromised, an attacker cannot unilaterally approve actions. The system is designed to integrate seamlessly with arbitrary web applications and workflows, protecting both internal systems (forward-auth pattern) and external transactional flows (one-time approvals).

## Core Concepts

### Requester
The user or system that is requesting access to a protected service or asking for an action to be performed (e.g., uploading a package to PyPI, accessing an internal web application).

### Approver
A trusted user with permission to grant or deny a request. Approvers authenticate with their own credentials (password + 2FA) and explicitly approve requests before they are allowed to proceed. Approvers are assumed to be trusted — the system design assumes a quorum of them will not collude to bypass security.

### Approval Request
A pending request that is waiting for approvers to grant their consent. An approval request is uniquely identified and bound to a specific hash (if applicable) or resource, preventing tampering or substitution.

### Quorum
The minimum number of approvers who must grant approval before a request is allowed to proceed. Configured per service (e.g., "3-of-5 approvers"). The quorum threshold is a security/availability trade-off: higher quorum = harder to compromise but more friction for legitimate requests.

### Service
A protected resource or action (e.g., "PyPI publish," "internal billing app," "database backup"). Each service is configured with its own set of approvers and quorum threshold in the YAML config.

### Access Control List (ACL)
A YAML configuration file that specifies, for each protected service: who the approvers are, what the quorum threshold is, and how the proxy should handle the request after approval (forward it to a backend app, execute an action, etc.).

### Approval Link
A unique URL (e.g., `https://proxy.example.com/approve/{approval_id}`) generated for each approval request and sent to approvers via notification. Clicking the link allows an approver to authenticate and grant consent. The link is not secret — security comes from the authentication step that follows.

### Hash Binding
A mechanism to prevent tampering with the payload (e.g., a software package) between upload and publication. When a requester uploads a package, the system immediately computes its cryptographic hash and records it as part of the approval request. Approvers approve that specific hash. If an attacker modifies the package after approval, the hash will no longer match, and publication is blocked.

### Credential-Backed Approval
An approval model in which approvers do not hold additional cryptographic keys. Instead, they authenticate using their regular credentials (password + 2FA) and their approval is backed by that authentication. The system records the approval in a way that ties it to the approver's identity, preventing a compromised proxy from retroactively forging approvals.

### Forward-Auth
An architectural pattern (used by Authelia, Traefik, and NGINX) in which a reverse proxy intercepts an HTTP request and asks a separate auth service "is this user allowed?" The auth service responds with allow/deny + identity headers that the proxy injects into the upstream request. Used for protecting internal web applications.

### One-Time Approval
A post-approval action pattern in which the approval request, once granted by quorum, triggers a one-time action (e.g., publish to PyPI, run a deployment job) without granting the requester an ongoing session. Contrasts with forward-auth, which grants a session.

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
