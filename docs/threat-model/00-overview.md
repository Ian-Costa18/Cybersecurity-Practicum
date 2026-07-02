# Threat Model: Multi-Party Authorization Proxy

This directory is the threat catalog for the proxy: one file per threat under a stable
`T<id>` identifier, plus this overview. It enumerates the attack surface, what an attacker
with each capability can achieve, what defenses are in place, and what operators must
configure. It is a living document — update it whenever the architecture, threat surface,
or scope changes.

**How this is organized.** Each threat lives in its own `T<nn>-<slug>.md` file carrying
machine-readable frontmatter (`id`, `title`, `stride`, `capability`, `bucket`, `delta`,
`related`).
The `id` (`T1`…`T27`) is the stable, citable handle used across the other docs; filenames
are zero-padded only for sort order. The `bucket` field is the four-bucket evaluation
classification (executably demonstrated / argued by design / operator-enforced / accepted
limitation) and is owned by **issue #107** — it is `TODO` here until that audit lands.

The `delta` field is the **net-delta classification** — how a threat relates to the
direct-publish baseline (publishing to PyPI with an API token + account 2FA, no proxy):
**improved** (a pre-existing threat the proxy measurably reduces), **inherited** (a
pre-existing authentication-layer threat the proxy leaves unchanged, out of scope by
design), or **introduced** (attack surface that exists only because the proxy exists).
The evaluation reports the four-bucket distribution over the threats the proxy *owns*
(improved + introduced); **inherited** threats carry `bucket: N/A` and are reported as a
scope statement, not defended threat-by-threat. The method is defined in
[evaluation-plan.md](../evaluation-plan.md); the per-threat `delta` values, `bucket`
values, and MITRE ATT&CK technique mappings are owned by **issue #107** and are `TODO`
here until that audit lands.

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

- [T1](T01-single-approver-account-compromise.md) — Single Approver Account Compromise · _Partial_
- [T2](T02-compromised-approver-as-denial-of-service.md) — Compromised Approver as Denial-of-Service (Deny Button) · _Partial_
- [T3](T03-approver-withholding.md) — Approver Withholding (Liveness Attack) · _Gap_
- [T4](T04-proxy-host-compromise.md) — Proxy Host Compromise · _Gap_
- [T5](T05-database-read-compromise.md) — Database Read Compromise · _Partial_
- [T6](T06-database-write-compromise.md) — Database Write Compromise · _Partial_
- [T7](T07-totp-secret-exposure-in-database.md) — TOTP Secret Exposure in Database · _Gap_
- [T8](T08-approval-link-replay.md) — Approval Link Replay · _Partial_
- [T9](T09-enrollment-link-interception.md) — Enrollment Link Interception · _Partial_
- [T10](T10-approval-link-phishing.md) — Approval Link Phishing · _Partial_
- [T11](T11-package-swap-between-upload-and-publication.md) — Package Swap Between Upload and Publication (Payload Substitution) · _Mitigated_
- [T12](T12-approval-fatigue-mfa-bombing.md) — Approval Fatigue / MFA Bombing · _Gap_
- [T13](T13-admin-account-compromise.md) — Admin Account Compromise · _Partial_
- [T14](T14-network-path-bypass.md) — Network Path Bypass (Forward-Auth Pattern) · _Gap_
- [T15](T15-proxy-session-hijacking.md) — Proxy Session Hijacking (Login Session) · _Partial_
- [T16](T16-smtp-channel-attack.md) — SMTP Channel Attack · _Partial_
- [T17](T17-cryptographic-implementation-failure.md) — Cryptographic Implementation Failure · _By design_
- [T18](T18-supply-chain-attack-on-the-proxy-itself.md) — Supply Chain Attack on the Proxy Itself · _Gap_
- [T19](T19-insider-collusion.md) — Insider Collusion · _By design_
- [T20](T20-aes-256-gcm-nonce-exhaustion.md) — AES-256-GCM Nonce (IV) Exhaustion · _Mitigated_
- [T21](T21-csrf-on-the-approve-deny-form.md) — CSRF on the Approve/Deny Form · _Partial_
- [T22](T22-information-disclosure-via-quorum-status-approver-visibility.md) — Information Disclosure via Quorum Status & Approver Visibility · _Accepted_
- [T23](T23-timing-attack-on-bcrypt-verification.md) — Timing Attack on bcrypt Verification · _Partial_
- [T24](T24-shared-account-password-reset-bypass.md) — Shared Account Password Reset Bypass · _Gap_
- [T25](T25-no-anti-automation-on-authentication-endpoints.md) — No Anti-Automation on Authentication Endpoints · _Gap_
- [T26](T26-api-token-theft.md) — API Token Theft · _Partial_
- [T27](T27-request-resource-flooding.md) — Request & Resource Flooding (Denial of Service) · _Gap_

---

## Visual Navigator

Two at-a-glance cuts of the catalog. Status is the current MVP mitigation posture (from the
Summary Table below); it will be superseded by the audited four-bucket `bucket:` field once
issue #107 classifies each threat.

Legend: 🟢 Mitigated · 🟡 Partial · 🔴 Gap · 🔵 By design · 🔵 Accepted

### STRIDE × mitigation status

| STRIDE ↓ / Status → | 🟢 Mitigated | 🟡 Partial | 🔴 Gap | 🔵 By design | 🔵 Accepted |
|---|---|---|---|---|---|
| **S — Spoofing** | — | [T9](T09-enrollment-link-interception.md) [T10](T10-approval-link-phishing.md) [T15](T15-proxy-session-hijacking.md) [T16](T16-smtp-channel-attack.md) | — | — | — |
| **T — Tampering** | [T11](T11-package-swap-between-upload-and-publication.md) | [T6](T06-database-write-compromise.md) | [T18](T18-supply-chain-attack-on-the-proxy-itself.md) | — | — |
| **R — Repudiation** | — | — | — | — | — |
| **I — Information Disclosure** | [T20](T20-aes-256-gcm-nonce-exhaustion.md) | [T5](T05-database-read-compromise.md) [T10](T10-approval-link-phishing.md) [T16](T16-smtp-channel-attack.md) [T23](T23-timing-attack-on-bcrypt-verification.md) | [T4](T04-proxy-host-compromise.md) [T7](T07-totp-secret-exposure-in-database.md) [T24](T24-shared-account-password-reset-bypass.md) | [T17](T17-cryptographic-implementation-failure.md) | [T22](T22-information-disclosure-via-quorum-status-approver-visibility.md) |
| **D — Denial of Service** | — | [T2](T02-compromised-approver-as-denial-of-service.md) | [T3](T03-approver-withholding.md) [T25](T25-no-anti-automation-on-authentication-endpoints.md) [T27](T27-request-resource-flooding.md) | — | — |
| **E — Elevation of Privilege** | — | [T1](T01-single-approver-account-compromise.md) [T5](T05-database-read-compromise.md) [T6](T06-database-write-compromise.md) [T8](T08-approval-link-replay.md) [T9](T09-enrollment-link-interception.md) [T13](T13-admin-account-compromise.md) [T15](T15-proxy-session-hijacking.md) [T21](T21-csrf-on-the-approve-deny-form.md) [T26](T26-api-token-theft.md) | [T4](T04-proxy-host-compromise.md) [T12](T12-approval-fatigue-mfa-bombing.md) [T14](T14-network-path-bypass.md) [T18](T18-supply-chain-attack-on-the-proxy-itself.md) [T24](T24-shared-account-password-reset-bypass.md) [T25](T25-no-anti-automation-on-authentication-endpoints.md) | [T17](T17-cryptographic-implementation-failure.md) [T19](T19-insider-collusion.md) | — |

### Adversary capability × mitigation status

| Capability ↓ / Status → | 🟢 Mitigated | 🟡 Partial | 🔴 Gap | 🔵 By design | 🔵 Accepted |
|---|---|---|---|---|---|
| **L1** | — | [T8](T08-approval-link-replay.md) [T9](T09-enrollment-link-interception.md) [T10](T10-approval-link-phishing.md) [T15](T15-proxy-session-hijacking.md) [T16](T16-smtp-channel-attack.md) [T21](T21-csrf-on-the-approve-deny-form.md) [T23](T23-timing-attack-on-bcrypt-verification.md) [T26](T26-api-token-theft.md) | [T14](T14-network-path-bypass.md) [T25](T25-no-anti-automation-on-authentication-endpoints.md) | — | [T22](T22-information-disclosure-via-quorum-status-approver-visibility.md) |
| **L2** | — | [T1](T01-single-approver-account-compromise.md) [T8](T08-approval-link-replay.md) [T26](T26-api-token-theft.md) | [T12](T12-approval-fatigue-mfa-bombing.md) [T25](T25-no-anti-automation-on-authentication-endpoints.md) [T27](T27-request-resource-flooding.md) | — | — |
| **L3** | — | [T1](T01-single-approver-account-compromise.md) [T2](T02-compromised-approver-as-denial-of-service.md) [T13](T13-admin-account-compromise.md) | — | — | — |
| **L4** | [T20](T20-aes-256-gcm-nonce-exhaustion.md) | [T5](T05-database-read-compromise.md) | [T7](T07-totp-secret-exposure-in-database.md) | [T17](T17-cryptographic-implementation-failure.md) | — |
| **L5** | — | [T6](T06-database-write-compromise.md) | — | — | — |
| **L6** | [T11](T11-package-swap-between-upload-and-publication.md) | — | [T4](T04-proxy-host-compromise.md) | [T17](T17-cryptographic-implementation-failure.md) | — |
| **L7** | — | [T2](T02-compromised-approver-as-denial-of-service.md) | [T3](T03-approver-withholding.md) [T24](T24-shared-account-password-reset-bypass.md) | — | — |
| **L8** | — | — | — | — | — |
| **L9** | — | — | — | [T19](T19-insider-collusion.md) | — |
| **External (no L-level)** | — | — | [T18](T18-supply-chain-attack-on-the-proxy-itself.md) | — | — |

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
| T12 | Approval fatigue / MFA bombing | L2 | No — no rate limiting | Cooldown after denial; approver training ("never approve what you didn't initiate"); see T25 |
| T13 | Admin account compromise | L3 | Partially — same auth requirements as approvers | Minimal admin accounts; Tier-1 credential management |
| T14 | Network path bypass (forward-auth) | L1 | No — operator responsibility | Firewall rules; bind backend to private interface |
| T15 | Proxy Session hijacking (login session) | L1 | Partially — server-side, revocable, signed cookie (`HttpOnly`+`Secure`+`SameSite=Strict`); voting stays re-auth-gated, but admin actions are not | HTTPS + HSTS; short `session_expiry_hours`; minimize admins; step-up re-auth for admin actions |
| T16 | SMTP channel attack | L1 | Partially — approval links not secret; enrollment links time-limited | SMTP TLS; DMARC/DKIM/SPF |
| T17 | Cryptographic implementation failure | L4-L6 | By design only — depends on correct implementation | Security code review; CI cryptographic invariant checks |
| T18 | Supply chain attack on proxy | External | No | Dependency pinning; vulnerability scanning; verified installs |
| T19 | Insider collusion | L9 | No — out of scope by design | HR/org controls; audit log review; high quorum thresholds |
| T20 | AES-GCM IV exhaustion | L4 | Yes for MVP use patterns | No action for typical use |
| T21 | CSRF on approve/deny form | L1 | Partially — stateless sessions limit window | CSRF tokens in form; SameSite cookies |
| T22 | Quorum status & endorser-identity leak | L1 | Accepted — link-scoped; only opt-in endorsers named, non-actors never | No action required |
| T23 | Timing attack on bcrypt | L1 | Partially — library handles; rate limiting absent | Rate limit login endpoint; verify constant-time comparison |
| T24 | Shared account password reset bypass | L7 | No — out of scope | Use group inbox for recovery email; plan intermediary service |
| T25 | No anti-automation on auth endpoints (online TOTP brute / CPU DoS) | L1/L2 | No — no rate limiting or lockout | In-proxy per-IP throttle (planned); reverse-proxy/WAF rate limit today; TLS |
| T26 | API token theft | Token possession | Partially — hashed at rest, per-token + deactivation revocation, quorum/hash-bound | Secrets manager for tokens; rotate on exposure; deactivate to kill all tokens |
| T27 | Request & resource flooding (DoS) | L2 | No — no rate limit or upload cap | Rate limit + quotas + max upload size (planned); monitor volume |

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
- [ ] Enable rate limiting on the authentication and upload endpoints (`/login`, `/approve`, `/pypi/legacy/`) at the reverse proxy or WAF until in-proxy limiting is available (T25/T27).

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
- [ ] Train approvers to never approve a request they did not themselves initiate (T12 approval-fatigue defense).
- [ ] Store API tokens in a secrets manager and rotate them on suspected exposure (T26).

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
