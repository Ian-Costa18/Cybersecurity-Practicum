# System Constraints

This document defines what the Multi-Signature Authentication Proxy can and cannot do. It is the authoritative reference for scoping and design decisions. Constraints here are not bugs or omissions — they are deliberate properties of the system.

---

## Constraints

### 1. The underlying service must not need to change

The protected service is not aware of the proxy. It receives requests that have already been approved, optionally with injected identity headers (forward-auth pattern), but is not modified, re-architected, or configured to speak any approval protocol. If a service cannot be placed behind a reverse proxy without modification, it is outside scope.

**Implication:** Operational configuration to enable the proxy is expected and acceptable — routing traffic through the proxy, updating firewall rules, or adjusting network topology are all in scope. What is not acceptable is requiring code changes to the protected service itself (e.g., submitting a pull request to add approval logic, modifying the service's authentication middleware, or changing its API contract). If a service cannot be fronted by a reverse proxy without source-level modification, it is outside scope.

### 2. Non-technical users must be able to use the system without managing cryptographic key material

Approvers cannot be required to generate, store, rotate, or recover cryptographic private keys (in the way a developer manages SSH keys or a GPG keyring). The default path through the system — enrollment, authentication, and approving requests — must work for someone whose only credentials are a password and a TOTP authenticator app. The proxy handles key generation, encryption, and lifecycle internally by default so that the approver never needs to handle a private key, key file, or seed phrase.

This does not preclude adding support for technically sophisticated users to supply or manage their own key material. Such a capability may be added as an optional advanced flow, but it must remain optional — the system can never require it.

**Implication:** The default key-management path (generation, re-encryption on password change, deletion) must be fully owned by the proxy. Any future feature that exposes key material to the user must be opt-in and must not affect users who do not choose it.

### 3. Quorum is mandatory; the action does not proceed without it

The proxy does not issue advisory approvals. If quorum is not reached, the action is not taken, the package is not published, and the session is not granted. There is no bypass, override, or emergency shortcut in the system.

**Implication:** Quorum availability is an operational constraint. If enough approvers are unreachable, on vacation, or unresponsive, legitimate requests can stall indefinitely. Operators must set quorum thresholds with availability in mind, not just security.

### 4. A single approver can block any request

Any approver designated for a service can deny a request immediately, regardless of how many others have already approved. A denial halts the request at once.

**Implication:** A compromised or malicious approver can use the deny button (or simply withhold their approval) as a denial-of-service against legitimate requests. The mitigation is fast account deactivation via the admin portal, not a system-level override.

### 5. The proxy must be the sole network path to protected services

For the forward-auth pattern, the proxy's protection is only as strong as the network topology enforcing it. If the backend service is reachable directly — bypassing the proxy — the approval requirement is bypassed too. The proxy cannot enforce its own network placement.

**Implication:** Operators are responsible for network controls (firewalls, VPC rules, bind addresses) that make the proxy the only entry point. The proxy provides no mechanism to detect or prevent direct access.

### 6. The approved payload cannot be substituted after approval

For transactional requests (package publishing), the proxy hashes the payload (SHA-256) at upload time and binds that hash to the approval request. Approvers approve the specific hash, not the package name or version. If the payload is modified after upload, the hash will not match and publication is blocked.

**Implication:** Approvers cannot approve a "future upload." Each distinct payload requires a new approval request with a new hash. Partial uploads or incremental changes cannot be approved in bulk.

### 7. PyPI post-approval rejection requires full re-approval

The proxy cannot fully pre-validate a package upload against PyPI before creating an Approval Request. In the current MVP the proxy performs **no** pre-upload validation, so **all** rejections — version-already-exists, malformed metadata, maintainer permission errors, server-side content policy violations — are detected only when the proxy attempts to publish after quorum is reached. If PyPI rejects the upload at that point, the Requester must fix the package and re-upload — producing a new artifact with a different SHA-256 hash. Because approvals are hash-bound, all previous approvals are invalidated and the entire approval process must restart from scratch. This multiplies the cost of any post-approval failure by the quorum size.

**Mitigation:** *Planned, not yet implemented* — best-effort pre-validation (a version-conflict check via the PyPI JSON API and local metadata parsing) would catch the most common failure modes before the Approval Request is created (see [web-proxy.md](web-proxy.md) One-Time Flow step 4). Until that lands, these failures are caught only at publish time; the residual (non-pre-validatable) rejections remain a documented constraint of hash binding.

### 8. Insider collusion is out of scope

The system assumes approvers are individually trusted and will not collude to approve malicious requests. If m-of-n approvers coordinate to approve something they should not, the system cannot detect or prevent it. The quorum requirement protects against a single compromised identity — not against coordinated betrayal by a majority.

**Implication:** The system's threat model is compromise of individual accounts, not organizational insider threats. Social and HR controls are the appropriate layer for collusion risk.

### 9. The proxy must be the sole holder of the publish credential

For one-time/transactional services (e.g., PyPI publishing), the trust model depends on the proxy being the **only** holder of the upstream upload credential. The protected upstream account is a **machine/service account whose sole upload token is held by the proxy**. A human owner still exists — PyPI's Terms of Service require a human-accountable owner (see [§7](#7-pypi-post-approval-rejection-requires-full-re-approval) and the [PyPI Terms of Service](https://policies.python.org/pypi.org/Terms-of-Service/)) — but that owner does not retain a usable upload token. If any maintainer also holds a working upload token, they can publish directly and bypass quorum entirely: the credential-axis analogue of the network bypass [§5](#5-the-proxy-must-be-the-sole-network-path-to-protected-services) describes.

This is an **operator-enforced operational precondition**, not something the proxy can verify — the proxy cannot tell whether a second copy of the token exists elsewhere (mirroring §5's honest framing: the proxy cannot enforce its own exclusivity).

**Implication:** Operators must ensure no usable upload token for the protected account exists outside the proxy. Security ② ([mvp-prd.md](mvp-prd.md)) carves out the compromised-proxy case precisely around this sole-custody assumption.

### 10. The config and users files are trusted, privileged operator input

The application config (`config.yaml`, which holds `server.secret_key`) and the declarative-provisioning users file (`users.yaml`) are **trusted input on par with the signing-key trust boundary**: `users.yaml` can **mint admins** (`is_admin: true`) and, in its pre-credentialed mode, carries **offline-guessable** credential material (a bcrypt hash plus the password-wrapped signing key — a weak password is attackable offline against the bundle). Anyone who can write either file already controls the proxy. See [config.md §`users.yaml`](config.md#usersyaml-declarative-provisioning).

**Implication:** Treat both files like `/etc/shadow` — keep the real files out of version control (commit only the dummy `*.example.yaml`), restrict filesystem access to `/config`, and use strong passwords for Mode-B bundles. The proxy does not (and cannot) defend against an attacker who can already modify its config.
