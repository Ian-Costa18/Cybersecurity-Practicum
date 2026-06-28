# Threat Model: Multi-Signature Authentication Web Proxy

This document enumerates the attack surface of the proxy, what an attacker with each capability can achieve, what defenses are currently in place, what planned future defenses exist, and what operators must configure to mitigate or contain each threat. It is a living document and should be updated whenever the architecture, threat surface, or scope changes.

---

## System Summary

The proxy intercepts requests to protected services and requires m-of-n approvers to independently authenticate (password + TOTP) and explicitly approve the request before it proceeds. Two post-approval patterns exist:

- **One-time:** the proxy executes a single action (PyPI publish, credential reveal) on behalf of the requester.
- **Forward-auth:** the proxy grants a session and forwards the request to a backend service.

Approvers hold no additional key material beyond a password and a TOTP app. An Ed25519 key pair is generated per approver at enrollment; the private key is encrypted at rest with AES-256-GCM (key derived via PBKDF2 from the approver's password). Every approval is signed with the approver's private key, producing a tamper-evident audit record verifiable without any password.

---

## Adversary Model

| Capability Level | Description |
|---|---|
| **L1 — Network attacker** | Observes or manipulates network traffic; cannot compromise endpoints. |
| **L2 — Credential attacker** | Has stolen one approver's password (e.g., via phishing, keylogger, breach dump). |
| **L3 — Full account compromise** | Has stolen one approver's password *and* TOTP secret (e.g., full device compromise or DB read). |
| **L4 — Database read** | Has read-only access to the database. |
| **L5 — Database write** | Has read/write access to the database but not the proxy process. |
| **L6 — Proxy compromise** | Has code execution on the proxy host (reads memory, intercepts in-flight data). |
| **L7 — Insider approver** | A legitimate, enrolled approver who acts maliciously or whose account is compromised. |
| **L8 — Admin compromise** | Attacker controls the admin account. |
| **L9 — Colluding quorum** | At least m-of-n approvers coordinate to approve something they should not. |

---

## Threat Catalog

### T1 — Single Approver Account Compromise

| | |
|---|---|
| **Category** | Elevation of Privilege |
| **Capability** | L2 or L3 |
| **What the attacker gains** | The ability to submit one approval on behalf of the compromised approver. |
| **What they cannot do** | Unilaterally complete a request — quorum requires at least m approvals, so a single compromised identity is insufficient. |
| **Current defenses** | m-of-n quorum: any single compromised approver cannot unilaterally approve. Password + TOTP two-factor authentication: both factors must be compromised simultaneously. Ed25519 signing: approvals are cryptographically tied to the authenticated identity and cannot be transferred or reused for a different request. |
| **Planned defenses** | SSO / external identity provider integration (lets organizations layer MFA from existing IdP on top of the proxy's quorum). Per-user credential wrapping (future threshold decryption would require compromising m approvers simultaneously, not just one). |
| **Operator configuration** | Set quorum thresholds with the expected breach rate in mind: 2-of-3 is weaker than 3-of-5. Keep approver rosters small (prefer a tight quorum over a large pool). Use unique, strong passwords and a hardware TOTP device where feasible. Immediately deactivate accounts at the first sign of compromise via the admin portal. |

---

### T2 — Compromised Approver as Denial-of-Service (Deny Button)

| | |
|---|---|
| **Category** | Denial of Service |
| **Capability** | L3 or L7 |
| **What the attacker gains** | The ability to halt any request by clicking Deny, regardless of how many other approvers have already approved. A single approver can block quorum indefinitely. |
| **What they cannot do** | Approve the action unilaterally; the deny only blocks, it does not redirect the action. |
| **Current defenses** | Admin portal account deactivation: setting `is_active = false` immediately invalidates the compromised approver's ability to act on any in-flight or future requests. |
| **Planned defenses** | Approval timeouts with automatic denial of timed-out requests prevent an attacker from simply withholding action rather than clicking Deny. Rate limiting on denials and anomaly detection ("Alice is denying everything") for operator alerting. |
| **Operator configuration** | Maintain a responsive admin contact who can deactivate accounts quickly. Set quorum such that losing one approver to deactivation does not block legitimate requests (e.g., 2-of-4 still works with one account deactivated). Write an incident runbook for "approver account deactivation." Document who holds admin credentials and how to reach them 24/7. |

---

### T3 — Approver Withholding (Liveness Attack)

| | |
|---|---|
| **Category** | Denial of Service |
| **Capability** | L7 (or simply: approver is unresponsive) |
| **What the attacker gains** | By never acting (neither approving nor denying), the attacker prevents quorum from being reached indefinitely. Approval requests have no expiration in the MVP. |
| **What they cannot do** | Approve the action; passive inaction only stalls the request. |
| **Current defenses** | Admin can deactivate the inactive account and enroll a replacement approver. |
| **Planned defenses** | Approval timeouts: requests automatically denied after a configurable deadline. Reminder notifications sent to non-responding approvers at intervals. |
| **Operator configuration** | Set quorum accounting for realistic approver availability (e.g., if 1 of 5 approvers is routinely unreachable, require only 3-of-5). Establish SLAs with approvers (expected response time). Use the admin portal to deactivate accounts of approvers who have left the organization or become unreachable. |

---

### T4 — Proxy Host Compromise

| | |
|---|---|
| **Category** | Elevation of Privilege, Information Disclosure |
| **Capability** | L6 |
| **What the attacker gains** | (a) Publishing credentials (PyPI token, shared account passwords) held in memory unencrypted — this is a documented MVP limitation. (b) Ed25519 private keys during the signing window (the transient window between PBKDF2 derivation and signing is a few milliseconds; the key is then discarded). (c) Plaintext passwords submitted during the current authentication request (transient in memory). (d) TOTP codes at the moment of authentication (transient). (e) Full visibility into in-flight approval requests and their state. |
| **What they cannot do** | Forge retroactive approvals already recorded in the database — Ed25519 signatures over canonical approval records are independently verifiable with the stored public keys; the proxy cannot fabricate a signature without the approver's private key. Modify stored approval records without detection — any change is caught by `Ed25519Verify`. |
| **Current defenses** | Hash binding: for one-time transactional requests, the payload hash is fixed at upload time; a compromised proxy cannot swap the package being published without breaking the approval-hash linkage. Audit trail: all approval records are signed and tamper-evident; post-compromise forensics can establish what was and was not approved before the compromise. |
| **Planned defenses** | Per-user credential wrapping: publishing credentials would be encrypted with each approver's key material, requiring m simultaneous approver decryptions — a compromised proxy alone could not read them. Integration with external secret managers (HashiCorp Vault, AWS Secrets Manager): credentials fetched at publish time, not held in memory. Minimizing the private key window (the key is already designed to be discarded immediately after signing; runtime memory zeroing should be confirmed in implementation). |
| **Operator configuration** | Harden the proxy host: minimal OS footprint, no unnecessary services, regular patching. Run the proxy in a container or VM with no persistent storage other than the database connection. Use network egress filtering to prevent the proxy from making unexpected outbound connections. Monitor for unexpected process execution, outbound connections, or memory dumps. Treat the proxy host as a Tier-1 asset requiring the same controls as a secrets manager. |

---

### T5 — Database Read Compromise

| | |
|---|---|
| **Category** | Information Disclosure, Elevation of Privilege (deferred) |
| **Capability** | L4 |
| **What the attacker gains** | `encrypted_private_key` blobs (encrypted with AES-256-GCM; useless without the user's password). `bcrypt` password hashes (offline cracking target). TOTP secrets in plaintext — once the attacker cracks the bcrypt hash, they have both factors, enabling full account takeover without any network interaction. Public keys and all approval records (read-only; cannot forge without private keys). ACL config (if stored in DB; in MVP it is a YAML file, so not directly accessible via DB read). API tokens and enrollment tokens are stored only as hashes; a database read yields useless hashes, not replayable tokens. |
| **What they cannot do** | Immediately authenticate or approve without cracking passwords (bcrypt cost ≥ 12 ≈ 300 ms/attempt on modern hardware). Forge approval signatures without the private keys (which require cracking the password to decrypt). |
| **Current defenses** | AES-256-GCM encryption of private keys at rest: the plaintext private key is never stored. bcrypt password hashing at cost ≥ 12: makes offline cracking expensive; unique per-user salts prevent precomputed tables. 128-bit random salt per user (PBKDF2): prevents cross-user rainbow tables. Token hashing: API tokens and enrollment tokens are stored only as hashes — the plaintext is shown or delivered once and never persisted, so a database read cannot recover or replay them. |
| **Planned defenses** | Encrypt TOTP secrets at rest (currently stored plaintext; should be encrypted analogously to the private key — this is an unmitigated gap). Formal access controls on the database (IP allowlist to proxy host only; dedicated DB credentials with minimal privileges). |
| **Operator configuration** | Never expose the database port to the internet; bind to localhost or a private network accessible only to the proxy host. Use a dedicated database user with only the necessary table-level permissions (no superuser). Enable database audit logging. Rotate database credentials if a breach is suspected. Establish a credential rotation policy for bcrypt cost escalation as hardware improves. |

---

### T6 — Database Write Compromise

| | |
|---|---|
| **Category** | Tampering, Elevation of Privilege |
| **Capability** | L5 |
| **What the attacker gains** | Ability to modify approval records (e.g., change a "deny" to "approve," or fabricate a record). Ability to alter `is_active`, `is_admin`, or `quorum` fields. Ability to swap `encrypted_private_key` or `public_key` for a controlled value. |
| **What they cannot do** | Forge a valid Ed25519 signature over a modified approval record — `Ed25519Verify(public_key, canonical_json(approval_record), approval_signature)` will fail for any modified record. Retroactively make a fabricated approval look valid without also controlling the public key (and the public key is stored separately). |
| **Current defenses** | Ed25519 audit signatures: every approval record is signed; any modification is detectable offline without any password. Public keys are retained permanently (even after account deletion): historical verifiability cannot be destroyed by deleting the account. |
| **Planned defenses** | Append-only audit log to an external write-once store (e.g., S3 with object lock, or a separate append-only database): even a DB write attacker cannot retroactively alter the log. Database row-level integrity checks (e.g., Postgres triggers that prevent UPDATE on the approval records table). |
| **Operator configuration** | Apply the principle of least privilege: the proxy's database user should have INSERT on the approval records table but not UPDATE or DELETE. Separate the write-enabled connection (used by the proxy) from read-only connections (used by audit tooling). Enable Postgres audit extension (pgaudit) or equivalent. Back up the database regularly; verify backup integrity. |

---

### T7 — TOTP Secret Exposure in Database

| | |
|---|---|
| **Category** | Information Disclosure |
| **Capability** | L4 |
| **What the attacker gains** | TOTP secrets are currently stored as plaintext in the database. An attacker who reads the database gets all TOTP secrets, allowing them to generate valid TOTP codes for any approver at any time. Combined with a cracked bcrypt hash (see T5), this yields complete account takeover of all accounts with a single database read — no network interaction required. |
| **What they cannot do** | This does not directly give them the private key (still needs password crack for PBKDF2 derivation), but the TOTP factor is completely eliminated as a defense. |
| **Current defenses** | None. This is an unaddressed gap in the current design. |
| **Planned defenses** | Encrypt TOTP secrets at rest using AES-256-GCM with a key derived from a system-level secret (not the user's password, since the proxy needs to verify TOTP without the user being present). The encryption key should be stored in environment variables or an external secrets manager, not in the database. |
| **Operator configuration** | Until TOTP encryption is implemented: treat database access controls as the only barrier. Restrict database access aggressively. Alert immediately on any unexpected database reads. Consider storing the database on an encrypted volume to raise the cost of offline extraction. |

---

### T8 — Approval Link Replay

| | |
|---|---|
| **Category** | Elevation of Privilege |
| **Capability** | L1, L2 |
| **What the attacker gains** | If an approval link can be reused, an attacker who obtains a previously used link could attempt to authenticate with a compromised approver account and cast or alter a Vote on a request. |
| **What they cannot do** | Replay a captured Vote as a stand-alone artifact — every Vote is independently signed and scoped to its `approval_request_id`, so it cannot be transplanted onto a different request or re-submitted without re-authenticating. Act on a closed request — Votes freeze at any terminal state (`approved`/`denied`/`cancelled`/`timed_out`), so a replayed link cannot change the outcome of a request that is no longer `pending`. Change a Vote without the approver — casting or superseding a Vote requires a fresh password + TOTP re-authentication every time. Note that under the append-only vote model (see [ADR 0009](adr/0009-append-only-vote-model.md)) a Vote is no longer immutable: while a request is `pending`, the authenticated Approver may legitimately supersede their own prior Vote (flip the decision or withdraw). This is an intentional supersession by the real Approver, not a replay. |
| **Current defenses** | Append-only signed votes ([ADR 0009](adr/0009-append-only-vote-model.md)): each Vote carries its `approval_request_id` and is independently signed, so a captured Vote cannot be replayed against another request. Fresh authentication on every link visit: casting or changing a Vote requires re-authenticating (password + TOTP) each time; obtaining the link alone is insufficient. **Single-use TOTP ([RFC 6238 §5.2](https://www.rfc-editor.org/rfc/rfc6238#section-5.2)):** an accepted TOTP code is recorded and burned per `(user, time-step)`, so a captured `password + TOTP` pair cannot be replayed once that code has been redeemed (see [approver-authentication.md](approver-authentication.md)). Idempotent re-casts: an identical repeated decision is a no-op and does not alter the effective vote. Terminal-state freeze: once a request leaves `pending`, no further Vote (original or replayed) is accepted. |
| **Planned defenses** | Approval link expiration (currently absent; links do not expire): adds a time-based barrier for links that were captured but not used. **Residual exposure:** even with single-use TOTP, a captured-but-not-yet-redeemed code stays replayable within its ±1-step (~90 s) acceptance window (`auth.totp_window`) — this is why T8 is rated **partially**, not fully, mitigated below. Tightening `totp_window` toward `0` shrinks the window at the cost of clock-drift tolerance. |
| **Operator configuration** | Distribute approval links over TLS-protected channels only. If SMTP is used, ensure it is configured with STARTTLS or SMTPS. Treat any unexpected "already approved" or "link not found" responses as potential indicators of link interception. |

---

### T9 — Enrollment Link Interception

| | |
|---|---|
| **Category** | Elevation of Privilege, Spoofing |
| **Capability** | L1 (with email access) |
| **What the attacker gains** | Enrollment links are single-use and expire in 24 hours, but if an attacker intercepts one before the legitimate approver uses it, the attacker can enroll as that approver — setting the password, TOTP secret, and effectively taking over the identity before it is established. |
| **What they cannot do** | Reuse a link that has already been consumed (single-use). Use the link after 24 hours (time-limited). |
| **Current defenses** | Single-use enrollment links: once consumed, the link is invalidated. 24-hour expiration: reduces the interception window. Admin must manually create the account — an out-of-band step that gives the real approver a chance to notice. |
| **Planned defenses** | Out-of-band enrollment confirmation: after enrollment, send a verification email to the approver or require them to confirm their identity to the admin before the account is activated. |
| **Operator configuration** | Distribute enrollment links using secure channels (end-to-end encrypted messaging where possible, not just plain email). Call the approver to confirm enrollment completion. Immediately regenerate enrollment links if an approver reports they never received one. Enable SMTP TLS to protect in-transit email. |

---

### T10 — Approval Link Phishing

| | |
|---|---|
| **Category** | Spoofing, Information Disclosure |
| **Capability** | L1 |
| **What the attacker gains** | An attacker who can send email to approvers can craft a fake approval link pointing to a malicious proxy that captures the approver's password and TOTP code. |
| **What they cannot do** | Use captured credentials to forge Ed25519 approval signatures without also accessing the database (the private key is encrypted at rest with the approver's password; the database is not accessible to the phishing site). |
| **Current defenses** | Authentication happens on the proxy domain; approvers can verify the domain in the browser address bar. |
| **Planned defenses** | DMARC / DKIM / SPF on the notification email domain prevents email spoofing (attacker cannot send email appearing to come from the proxy domain). HTTPS with a known-good certificate for the proxy (approvers can verify). |
| **Operator configuration** | Configure DMARC, DKIM, and SPF on the proxy's email-sending domain. Use a consistent, recognizable sender address and proxy domain. Train approvers to verify the URL before entering credentials. Consider pinning the proxy domain in approver onboarding documentation. |

---

### T11 — Package Swap Between Upload and Publication (Payload Substitution)

| | |
|---|---|
| **Category** | Tampering |
| **Capability** | L6 (proxy compromise) or attacker with write access to the artifact store |
| **What the attacker gains** | If an attacker can substitute a different artifact after approvers have reviewed and approved the original, the malicious artifact gets published under the approved provenance. |
| **What they cannot do** | Succeed in the **upload→publish substitution** — hash binding blocks it. The payload is hashed at upload time; approvers approve that specific hash; the Executor **re-verifies `SHA-256(held artifact) == action_hash` immediately before publishing**, so if the artifact changes the hash will not match and publication is blocked. **Out of scope:** a *fully compromised proxy that holds the live upload token* could ignore its own hash check and publish a different artifact straight to PyPI — hash binding does not defend that case (an accepted MVP limitation; see [mvp-prd.md](mvp-prd.md) Security ②). |
| **Current defenses** | Hash binding: payload SHA-256 is computed immediately on upload, recorded in the approval request, and re-verified by the Executor before publishing. Any substitution **in the upload→publish window** causes a hash mismatch and publication is blocked — this holds even against an attacker with write access to the artifact store. It does **not** defend a fully compromised proxy that holds the live token and bypasses its own executor. |
| **Planned defenses** | The hash binding mechanism is a fundamental design principle and effective against payload substitution within the upload→publish window (not against a token-holding compromised proxy — see above). Future enhancements: surface the hash prominently in the approve/deny UI so approvers can cross-check against their local copy. |
| **Operator configuration** | No additional configuration required. Operators should verify the proxy implementation computes and checks the hash as specified in the design. |

---

### T12 — MFA Bombing / Request Flooding / Approval Fatigue

| | |
|---|---|
| **Category** | Denial of Service, Social Engineering |
| **Capability** | L2 (compromised requester account) or any authenticated requester |
| **What the attacker gains** | (a) **MFA bombing (approval fatigue):** An attacker floods approvers with repeated approval requests, exploiting the fact that the MVP allows immediate retry after denial. Approvers, overwhelmed by notifications, eventually click "Approve" without careful review — the same attack pattern as MFA push-bombing in passwordless authentication systems. (b) **DoS via noise:** Legitimate requests are buried. (c) **Retry amplification:** Because any single denial immediately closes a request and the Requester can immediately open a new one, an attacker can create a denial → retry loop that generates sustained notification traffic to approvers. There is currently no rate limit on approval requests. |
| **What they cannot do** | Force approvers to approve; approvers must still authenticate (password + TOTP) and explicitly click Approve on each request. |
| **Current defenses** | None. This is a documented MVP limitation. |
| **Planned defenses** | Rate limiting per requester per service per time window on the request creation endpoint. Cooldown period after denial before the same requester can reopen a request for the same service. Anomaly detection: alert admins when a single requester opens significantly more requests than their historical baseline. Approval fatigue detection: alert approvers or admins when a burst of requests arrives from a single source. |
| **Operator configuration** | Until rate limiting is implemented: monitor approval request volume; investigate bursts immediately. Deactivate requester accounts showing anomalous behavior. Ensure approvers understand they should never approve a request they did not initiate themselves — include this in approver onboarding. |

---

### T13 — Admin Account Compromise

| | |
|---|---|
| **Category** | Elevation of Privilege |
| **Capability** | L3 |
| **What the attacker gains** | Full control over the approver roster: create new accounts, deactivate existing ones, reset credentials, regenerate enrollment links. An attacker with admin access can install themselves or a colluding party as a new approver, meet quorum, and approve arbitrary requests. |
| **What they cannot do** | Retroactively modify approval records (tamper-evident via Ed25519). Approve requests without going through the authentication flow — admin panel actions are scoped to account management, not approval decisions. |
| **Related — privileged config input** | The declarative-provisioning `users.yaml` ([config.md §`users.yaml`](config.md#usersyaml-declarative-provisioning)) and `config.yaml` are **trusted operator input** equivalent to admin authority: `users.yaml` can mint admins (`is_admin: true`) and, in pre-credentialed mode, holds offline-guessable credential material. Write access to these files *is* a compromise — this is the config-file analogue of admin-account compromise, accepted as out of scope the same way ([constraints.md §10](constraints.md)). |
| **Current defenses** | Admin authentication requires the same password + TOTP two-factor flow as approvers. Admin is a flag on a regular user account, not a separate privileged system. All admin actions are logged (implicitly via the audit trail of approvals that result). |
| **Planned defenses** | Dedicated audit log of admin actions (user creation, deactivation, credential reset) with timestamps and admin identity. Admin action notifications: alert all admins when a new approver is enrolled or when credentials are reset. Peer-approved admin actions (future): require a second admin to confirm sensitive operations. |
| **Operator configuration** | Limit the number of admin accounts to the minimum necessary. Treat admin credentials as Tier-1 secrets (hardware MFA, unique password, stored in a password manager). Immediately deactivate admin accounts when an administrator leaves the organization. Review admin action logs regularly. Do not reuse admin passwords across systems. |

---

### T14 — Network Path Bypass (Forward-Auth Pattern)

| | |
|---|---|
| **Category** | Elevation of Privilege |
| **Capability** | L1 (network-level access to the backend) |
| **What the attacker gains** | If the backend service is reachable without going through the proxy, the entire approval requirement is bypassed. The proxy cannot detect or block direct access to the backend. |
| **What they cannot do** | Access the proxy-enforced approval state — but if they can reach the backend directly, they do not need to. |
| **Current defenses** | None — this is explicitly a documented constraint. The system trusts operators to enforce network topology. |
| **Planned defenses** | Future Traefik plugin integration makes deployment easier and reduces misconfiguration risk. The constraint is architectural; full mitigation requires network-layer enforcement. |
| **Operator configuration** | Bind backend services to private network interfaces only (e.g., `127.0.0.1` or a private VPC CIDR). Add firewall rules that allow inbound connections to the backend only from the proxy host IP. Regularly audit firewall rules. Test that direct access from outside the proxy is blocked. Do not expose backend services on public-facing interfaces even temporarily. |

---

### T15 — Session Hijacking (Forward-Auth Sessions)

| | |
|---|---|
| **Category** | Elevation of Privilege, Spoofing |
| **Capability** | L1 (passive network attacker or XSS attacker) |
| **What the attacker gains** | If an attacker can steal a post-approval session cookie (via network sniffing, XSS, or physical access), they can impersonate the requester until the session expires or is revoked. |
| **What they cannot do** | Approve requests as an approver (approver sessions are stateless; each approval requires a fresh authentication event). Bypass the approval requirement for future requests — only the already-granted session is hijacked. |
| **Current defenses** | Stateless approver sessions: approvers have no persistent sessions to hijack. Forward-auth sessions should use short lifetimes. |
| **Planned defenses** | Binding sessions to the requester's IP or TLS fingerprint. Re-approval requirements for sensitive actions within an active session. Explicit session revocation endpoint. |
| **Operator configuration** | Deploy the proxy exclusively over HTTPS. Set `Secure` and `HttpOnly` flags on all session cookies. Configure short session lifetimes (the lower the sensitivity of the protected resource, the shorter the session). Enable HTTP Strict Transport Security (HSTS). |

---

### T16 — SMTP Channel Attack

| | |
|---|---|
| **Category** | Information Disclosure, Spoofing |
| **Capability** | L1 |
| **What the attacker gains** | Enrollment links and approval links are delivered via SMTP. An attacker who can intercept or inject into the SMTP channel can steal enrollment links (leading to account takeover — see T9) or approval links (which are not secret — security comes from authentication — but interception enables social engineering). |
| **What they cannot do** | Obtain credentials or approval authority from intercepting approval links alone (authentication is still required). |
| **Current defenses** | Approval links are not sensitive secrets (security comes from the authentication step). Enrollment links are single-use and time-limited. |
| **Planned defenses** | DMARC, DKIM, SPF enforcement on outbound email. Future multi-backend notification (Apprise) would allow supplementing email with more secure channels (e.g., push notifications to a trusted device). |
| **Operator configuration** | Configure SMTP with STARTTLS or SMTPS. Use a reputable email provider with SPF/DKIM/DMARC records. Never use unencrypted SMTP. Use `fallback_to_portal: true` as a hardening measure in high-security deployments — links are shown in the admin portal rather than emailed, requiring out-of-band distribution to approvers. |

---

### T17 — Cryptographic Implementation Failure

| | |
|---|---|
| **Category** | Elevation of Privilege, Information Disclosure |
| **Capability** | L4 to L6 (depends on the specific failure) |
| **What the attacker gains** | Depends on which invariant is violated: |
| | **bcrypt output used as key material:** Collapse of enc_key derivation security. |
| | **PBKDF2 output stored:** Stored enc_key gives direct AES-256-GCM key; bypasses all password hashing. |
| | **Ed25519 private key not discarded after signing:** Persistent plaintext private key in memory or DB makes encryption pointless. |
| | **AES-256-GCM IV reuse:** Authentication is destroyed and XOR of ciphertexts gives full plaintext recovery. |
| | **AES-256-GCM plaintext released before tag verification:** Enables ciphertext manipulation without detection. |
| **Current defenses** | These invariants are documented explicitly in [cryptography.md](cryptography.md) and must be upheld in implementation. The design is sound if implemented correctly. |
| **Planned defenses** | Unit tests asserting that the private key is not in memory after signing (using memory inspection or explicit zeroing). CI checks for any code path that stores `enc_key` in a persistent data structure. Code review checklist for cryptographic invariants. |
| **Operator configuration** | No runtime configuration can fix a broken implementation. Operators should: require a security code review of the cryptographic subsystem before deployment; review the cryptography.md document and confirm implementation matches specification; use cryptographic linting tools (e.g., `bandit` for Python). |

---

### T18 — Supply Chain Attack on the Proxy Itself

| | |
|---|---|
| **Category** | Tampering, Elevation of Privilege |
| **Capability** | External — attacker compromises a dependency of the proxy |
| **What the attacker gains** | A malicious dependency (e.g., a compromised Python package used by the proxy) could exfiltrate credentials, approval data, or private keys; silently approve requests; or provide a backdoor into the proxy host. This is the same class of attack the proxy is designed to prevent in downstream packages. |
| **What they cannot do** | Forge historical Ed25519 approval signatures already stored in the database (prior records remain tamper-evident). |
| **Current defenses** | None specifically documented. |
| **Planned defenses** | Dependency pinning (lock file with hashes for all transitive dependencies). Reproducible builds. Automated dependency vulnerability scanning (Dependabot, pip-audit, etc.). Code signing of proxy releases. |
| **Operator configuration** | Only install the proxy from a trusted source; verify release signatures if provided. Use a private package index mirror where possible rather than pulling directly from PyPI at deploy time. Audit third-party dependencies in the proxy's lock file. Run the proxy in a container with a minimal base image to limit the blast radius of a compromised dependency. |

---

### T19 — Insider Collusion

| | |
|---|---|
| **Category** | Elevation of Privilege |
| **Capability** | L9 — at least m-of-n approvers coordinate maliciously |
| **What the attacker gains** | A quorum of colluding approvers can approve any request — the proxy cannot distinguish legitimate approval from coordinated malicious approval. |
| **What they cannot do** | Deny having approved — the Ed25519 audit trail proves each approver's participation and the proxy records non-repudiable signatures. |
| **Current defenses** | Audit trail: every approval is signed; post-incident forensics can prove who approved what and when. This does not prevent collusion but enables accountability after the fact. |
| **Planned defenses** | Approval content preview (in-browser package file browser) makes it harder to approve malicious content unknowingly. Screen-share auditing would record approvers' behavior during sensitive operations. Fine-grained authorization (per-user thresholds) can require approvals from disjoint groups, making full collusion harder. Formal verification (Tamarin/ProVerif) can verify the approval protocol's non-repudiation properties. |
| **Operator configuration** | Treat this as an HR and organizational security problem, not a technical one. Select approvers from independent organizational units where possible. Set quorum thresholds high enough that collusion requires meaningful organizational coordination (e.g., 4-of-7 across multiple teams). Conduct periodic audits of the approval log for anomalies. Review all approvals for high-value actions (major releases, infrastructure changes) after the fact. |

---

### T20 — AES-256-GCM Nonce (IV) Exhaustion

| | |
|---|---|
| **Category** | Information Disclosure |
| **Capability** | L4 |
| **What the attacker gains** | AES-256-GCM provides confidentiality and authentication guarantees with probability ≤ 2^{−18} for adversary advantage given random 96-bit IVs, up to 2^48 invocations per key. Exceeding this bound (or reusing an IV) destroys authentication and enables plaintext recovery. |
| **What they cannot do** | Exploit this without also having L4 access to the ciphertext blobs. |
| **Current defenses** | Each encryption event generates a fresh 96-bit random IV. For the MVP use case (per-user key encrypted at enrollment and re-encrypted on password change only), the per-key invocation count will be orders of magnitude below the 2^48 limit. |
| **Planned defenses** | If key rotation or re-encryption is ever performed at high frequency, add an invocation counter per key and rotate the AES key before reaching the 2^32 limit (as recommended by NIST SP 800-38D §8.3). |
| **Operator configuration** | No action required for typical use. If the system is extended to encrypt large numbers of objects under a single key, enforce key rotation before the invocation limit is reached. |

---

### T21 — CSRF on the Approve/Deny Form

| | |
|---|---|
| **Category** | Elevation of Privilege |
| **Capability** | L1 (web attacker who can get approver to visit a malicious page) |
| **What the attacker gains** | If the approve/deny form does not include a CSRF token, an attacker who can trick an authenticated approver (during their active approval window) into visiting a malicious page could submit a forged approval or denial. |
| **What they cannot do** | Trigger this attack outside the narrow window between the approver authenticating and the form being submitted. Stateless approver sessions limit the exposure to a single per-request authentication event. |
| **Current defenses** | Stateless per-approval sessions significantly reduce CSRF risk: the approver has no persistent session cookie that a CSRF attack could leverage across requests. |
| **Planned defenses** | CSRF tokens on the approve/deny form submission (standard practice; should be included in the web UI implementation). SameSite cookie attribute on any session cookies issued during the approval flow. |
| **Operator configuration** | Ensure the proxy is deployed on its own domain and not embedded in an iframe. Review the web framework's CSRF protection documentation and verify it is enabled. |

---

### T22 — Information Disclosure via Quorum Status & Approver Visibility

| | |
|---|---|
| **Category** | Information Disclosure |
| **Capability** | L1 |
| **What the attacker gains** | The approve/deny page shows live quorum status and, per #22, the **identities of the Endorsing Approvers** (Users whose effective vote is approve — e.g. "Approved by Alice & Bob — 2 of 3, waiting on 1 more"). A holder of the approval link learns *who* has approved and how many approvals remain. Approvers who denied, withdrew, or have not yet acted are **not** named. Residual leak: the endorser set could assist social engineering ("Alice and Bob are in; I'll lean on whoever's left"). |
| **What they cannot do** | Forge approvals, or learn the identities of approvers who have not endorsed — deniers, withdrawals, and non-actors are never named, so the silent roster is not exposed. |
| **Current defenses** | The approve/deny page (and its live endorser list) is reachable only with the request's **approval link, an unguessable random UUIDv4**, delivered solely to the eligible approvers via the `request.created` notification. Casting a vote additionally requires fresh password + TOTP re-authentication; *viewing* the page requires only possession of the link. Disclosure is limited to effective-approvers, which is an opt-in act (approving); non-endorser identities are withheld by design. |
| **Planned defenses** | None required. Endorser-identity disclosure to link-holders is an accepted design decision (#22): the link is unguessable and approver-only, only opt-in endorsers are named, and the information cannot forge a vote — judged a low residual risk. |
| **Operator configuration** | No action required. If endorser-identity disclosure among approvers is itself a concern, document the expectation with approvers; the silent roster (non-actors) is never revealed. |

---

### T23 — Timing Attack on bcrypt Verification

| | |
|---|---|
| **Category** | Information Disclosure |
| **Capability** | L1 |
| **What the attacker gains** | If the bcrypt comparison is not performed in constant time, an attacker who can make many authentication attempts and measure response times could gain partial information about the password hash. |
| **What they cannot do** | Immediately derive the password; this is a secondary oracle attack requiring many queries. |
| **Current defenses** | Standard bcrypt library implementations perform constant-time comparison of the output. Using a well-maintained library (e.g., `bcrypt` in Python) is sufficient. |
| **Planned defenses** | Explicitly use constant-time comparison (`hmac.compare_digest` in Python) when comparing any credentials. Confirm during code review. |
| **Operator configuration** | Add rate limiting on the login endpoint to prevent the volume of requests needed for a timing attack. |

---

### T24 — Shared Account Password Reset Bypass

| | |
|---|---|
| **Category** | Elevation of Privilege, Information Disclosure |
| **Capability** | L7 (insider approver or co-owner of the shared account) |
| **What the attacker gains** | External services (email providers, GitHub, etc.) send password reset emails to the shared account's registered email address. If one party controls or monitors that email address, they can initiate a password reset unilaterally — gaining sole control of the shared account without the knowledge or consent of the other co-owners. The proxy's quorum enforcement covers access to the shared account; it does not cover out-of-band credential recovery mechanisms on the external service. |
| **What they cannot do** | Use the proxy to approve their own unilateral action — the attack bypasses the proxy entirely by going through the external service's own recovery flow. |
| **Current defenses** | None. This is an out-of-scope architectural gap for the MVP. The proxy cannot intercept or gate external service recovery flows. |
| **Planned defenses** | Intermediary email account: route the shared account's recovery email to a dedicated inbox that is itself gated by a multi-sig approval before forwarding. This would require an additional service layer outside the proxy. Deferred to future work. |
| **Operator configuration** | Until a formal mitigation is available: use a shared email account (e.g., a group inbox) for the external service's registration address, ensuring no single party has unilateral access. Document which party controls the recovery email and treat that as a trust boundary. Conduct periodic audits of the shared account's registered email and recovery methods. |

---

## Summary Table

| ID | Threat | Capability | Fully Mitigated (MVP)? | Action Required |
|---|---|---|---|---|
| T1 | Single approver account compromise | L2/L3 | Partially — quorum prevents unilateral action | Set quorum thresholds appropriately; fast deactivation runbook |
| T2 | Compromised approver as DoS (deny) | L3/L7 | Partially — admin deactivation is the only mitigation | Admin deactivation runbook; quorum allows for one lost approver |
| T3 | Approver withholding (liveness) | L7 | No — no timeout | Admin deactivation; availability-aware quorum |
| T4 | Proxy host compromise | L6 | No — credentials in memory unencrypted | Harden proxy host; plan for per-user credential wrapping |
| T5 | Database read | L4 | Partially — private keys encrypted; TOTP exposed | Restrict DB access; encrypt TOTP secrets |
| T6 | Database write | L5 | Partially — approval signatures tamper-evident; ACL writeable | Least-privilege DB user; append-only log |
| T7 | TOTP secret exposure | L4 | No — TOTP secrets in plaintext | Encrypt TOTP secrets at rest (planned) |
| T8 | Approval link replay | L1/L2 | **Partial** — signed votes, single-use TOTP (RFC 6238 §5.2) + re-auth, terminal freeze; residual ±1-step (~90 s) window for an unredeemed captured code | Use TLS for link distribution; tighten `totp_window` |
| T9 | Enrollment link interception | L1 | Partially — single-use, 24h expiry | Secure distribution channel; confirm enrollment out-of-band |
| T10 | Approval link phishing | L1 | Partially — auth required; domain verification up to approver | DMARC/DKIM/SPF; approver training |
| T11 | Package swap (payload substitution) | L6 | Yes — hash binding | No additional config required |
| T12 | Request flooding / approval fatigue | L2 | No — no rate limiting | Monitor request volume; deactivate abusing accounts |
| T13 | Admin account compromise | L3 | Partially — same auth requirements as approvers | Minimal admin accounts; Tier-1 credential management |
| T14 | Network path bypass (forward-auth) | L1 | No — operator responsibility | Firewall rules; bind backend to private interface |
| T15 | Session hijacking (forward-auth) | L1 | Partially — short session lifetimes | HTTPS; Secure+HttpOnly cookies; short lifetimes |
| T16 | SMTP channel attack | L1 | Partially — approval links not secret; enrollment links time-limited | SMTP TLS; DMARC/DKIM/SPF |
| T17 | Cryptographic implementation failure | L4-L6 | By design only — depends on correct implementation | Security code review; CI cryptographic invariant checks |
| T18 | Supply chain attack on proxy | External | No | Dependency pinning; vulnerability scanning; verified installs |
| T19 | Insider collusion | L9 | No — out of scope by design | HR/org controls; audit log review; high quorum thresholds |
| T20 | AES-GCM IV exhaustion | L4 | Yes for MVP use patterns | No action for typical use |
| T21 | CSRF on approve/deny form | L1 | Partially — stateless sessions limit window | CSRF tokens in form; SameSite cookies |
| T22 | Quorum status & endorser-identity leak | L1 | Accepted — link-scoped; only opt-in endorsers named, non-actors never | No action required |
| T23 | Timing attack on bcrypt | L1 | Partially — library handles; rate limiting absent | Rate limit login endpoint; verify constant-time comparison |
| T24 | Shared account password reset bypass | L7 | No — out of scope | Use group inbox for recovery email; plan intermediary service |

---

## Operator Checklist

The following configuration steps are required to achieve the security posture described above. They are the operator's responsibility and cannot be enforced by the proxy itself.

### Network & Deployment

- [ ] Deploy the proxy exclusively over HTTPS with a valid certificate.
- [ ] Enable HTTP Strict Transport Security (HSTS).
- [ ] Bind backend services (for forward-auth) to private network interfaces only.
- [ ] Add firewall rules so the backend is reachable only from the proxy host.
- [ ] Bind the proxy database to localhost or a private interface; never expose it to the internet.
- [ ] Test that direct access to the backend (bypassing the proxy) is blocked.

### SMTP / Email

- [ ] Configure SMTP with STARTTLS or SMTPS.
- [ ] Configure DMARC, DKIM, and SPF records for the proxy's sending domain.
- [ ] Consider enabling `fallback_to_portal: true` and distributing links out-of-band for high-security environments.

### Database

- [ ] Create a dedicated database user for the proxy with only the required table-level permissions (no superuser).
- [ ] Grant INSERT, not UPDATE or DELETE, on the approval records table.
- [ ] Enable database audit logging (pgaudit or equivalent).
- [ ] Back up the database regularly and verify backup integrity.
- [ ] Encrypt database storage at rest.

### Session & Cookie Security

- [ ] Set `Secure` and `HttpOnly` flags on all session cookies.
- [ ] Set `SameSite=Strict` or `SameSite=Lax` on session cookies.
- [ ] Configure short session lifetimes appropriate to the sensitivity of the protected resource.

### Account & Approver Management

- [ ] Limit admin accounts to the minimum necessary.
- [ ] Store admin credentials in a password manager with a unique, strong password.
- [ ] Use a hardware TOTP token for admin accounts where possible.
- [ ] Write an incident runbook for "compromised approver account deactivation."
- [ ] Set quorum thresholds accounting for approver availability (losing one approver must not block operations).
- [ ] Confirm enrollment with approvers out-of-band before trusting their account.
- [ ] Distribute enrollment links via encrypted channels, not plain email.
- [ ] Deactivate accounts immediately when an approver leaves the organization.

### Monitoring & Auditing

- [ ] Monitor approval request volume; alert on anomalous bursts.
- [ ] Review the Ed25519 audit log periodically for unexpected approvals.
- [ ] Review admin action logs (user creation, deactivation, credential reset).
- [ ] Establish a process to re-evaluate bcrypt cost as hardware improves.

### Host Hardening

- [ ] Run the proxy on a minimal OS footprint with no unnecessary services.
- [ ] Run the proxy in a container with a minimal base image.
- [ ] Apply OS-level patches regularly.
- [ ] Configure egress filtering to prevent unexpected outbound connections from the proxy host.
- [ ] Verify that the proxy's dependency lock file is pinned with hashes.
- [ ] Run automated dependency vulnerability scanning (pip-audit or equivalent).
