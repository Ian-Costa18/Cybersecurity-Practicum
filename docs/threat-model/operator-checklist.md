# Operator Checklist

The following configuration steps are required to achieve the security posture described in
the [threat-model overview](00-overview.md). They are the operator's responsibility and
cannot be enforced by the proxy itself — they are the concrete work behind every ③
operator-enforced threat. Each item names the threat(s) it addresses; see the
[overview](00-overview.md) for the full catalog and the per-threat files for rationale.

## Network & Deployment

- [ ] Deploy the proxy exclusively over HTTPS with a valid certificate.
- [ ] Enable HTTP Strict Transport Security (HSTS).
- [ ] Monitor Certificate Transparency logs for unexpected issuance against the proxy's domain, and keep the origin's DNS registrar account under 2FA (CRYPTO-3).
- [ ] Bind the proxy database to localhost or a private interface; never expose it to the internet.
- [ ] *(Future vision, forward-auth #109 — not part of the package-publishing MVP)* Bind backend services to private network interfaces only, firewall them to the proxy host, and test that direct backend access is blocked.
- [ ] The proxy now rate-limits the authentication endpoints in-process (per-IP, #123, IDENT-5 ①) and request creation per requester (#32, DOS-1 flooding legs ①); echo reverse-proxy/WAF rate limits on `/login`, `/approve`, `/pypi/legacy/` as defense-in-depth, and cap per-client concurrent connections + idle-timeout long-lived SSE streams to bound the single-worker connection-starvation leg (DOS-1 leg d, ③).
- [ ] Serve the proxy on its own dedicated origin (VOTE-1). The anti-framing headers (`X-Frame-Options: DENY` / `Content-Security-Policy: frame-ancestors 'none'`) are now set in-app (#127, VOTE-3); a reverse proxy may echo them as defense-in-depth.

## SMTP / Email

- [ ] Configure SMTP with STARTTLS or SMTPS.
- [ ] Configure DMARC, DKIM, and SPF records for the proxy's sending domain (starves IDENT-4's lure).
- [ ] Keep `fallback_to_portal: true` (the default) and distribute links out-of-band for high-security environments.

## Database

- [ ] Create a dedicated database user for the proxy with only the required table-level permissions (no superuser).
- [ ] Grant INSERT, not UPDATE or DELETE, on the approval records table (HOST-2, HOST-4).
- [ ] Enable database audit logging (pgaudit or equivalent); alert on unexpected bulk reads and on any DELETE against records tables.
- [ ] Mirror the audit trail to an external append-only / WORM store out of reach of the database role (HOST-4, DOS-2).
- [ ] Back up the database regularly, keep an offsite copy, and verify backup/restore integrity.
- [ ] Encrypt database storage at rest (defense-in-depth over the already hashed/password-wrapped credentials, HOST-3).
- [ ] Keep an independent record of enrollment-time public keys outside the database (HOST-2).

## Session & Cookie Security

- [ ] Verify the proxy issues session cookies with `Secure` and `HttpOnly` set (the proxy sets these; VOTE-1).
- [ ] Verify `SameSite=Strict` (or `Lax`) on session cookies (proxy-set; VOTE-1).
- [ ] Configure short session lifetimes appropriate to the sensitivity of the protected resource.

## Account & Approver Management

- [ ] Limit admin accounts to the minimum necessary.
- [ ] Store admin credentials in a password manager with a unique, strong password; use a hardware TOTP token where possible.
- [ ] Review the admin action log regularly — on the quiet enroll-forward path it is the detection (IDENT-1).
- [ ] Write an incident runbook for "compromised approver account deactivation."
- [ ] Set quorum thresholds accounting for approver availability (losing one approver must not block operations) (DOS-3, DOS-4).
- [ ] Confirm enrollment with approvers out-of-band before trusting their account.
- [ ] Distribute enrollment links via encrypted channels, not plain email (IDENT-2).
- [ ] Deactivate accounts immediately when an approver leaves the organization.
- [ ] Train approvers to never approve a request they did not themselves initiate (VOTE-4 approval-fatigue defense).
- [ ] Inspect any *unapproved* artifact only in a disposable, credential-free, network-isolated sandbox (a throwaway VM or container) — never on a primary dev machine, and never `pip install` or build it into a real environment (VOTE-5).
- [ ] Store API tokens in a secrets manager and rotate them on suspected exposure (CORE-2).
- [ ] Restrict filesystem access to `/config`; keep the real `users.yaml` out of version control (commit only `users.example.yaml`); use strong Mode-B passwords — the Mode-B bundle's TOTP secret is encrypted at rest since #122, so no plaintext field needs env-referencing (IDENT-6).

## Publish-Boundary Integrity

- [ ] Revoke all pre-existing project API tokens and demote maintainer accounts so the sole upload credential lives in the proxy (PUB-2).
- [ ] `$ENV{}`-reference (or secrets-manager-inject) the PyPI token, `secret_key`, and SMTP password rather than inlining them in `config.yaml`/`.env`; git-ignore the real config; encrypt config backups; rotate the PyPI token on any suspected config leak (HOST-5).
- [ ] Enforce 2FA on the PyPI publisher account (prefer an organization account with a 2FA policy) (PUB-3).
- [ ] Register a recovery inbox that no single party controls (a group inbox), and audit registered email/recovery methods periodically (PUB-3).

## Monitoring & Auditing

- [ ] Monitor approval request and upload volume; alert on anomalous bursts (DOS-1, VOTE-4).
- [ ] Review the Ed25519 audit log periodically for unexpected approvals.
- [ ] Review admin action logs (user creation, deactivation, credential reset).
- [ ] Establish a process to re-evaluate bcrypt cost as hardware improves.

## Host Hardening

- [ ] Run the proxy on a minimal OS footprint with no unnecessary services.
- [ ] Run the proxy in a container with a minimal base image (limits CODE-2 blast radius).
- [ ] Apply OS-level patches regularly.
- [ ] Configure egress filtering to prevent unexpected outbound connections from the proxy host.
- [ ] Verify that the proxy's dependency lock file is pinned with hashes (CODE-2).
- [ ] Run automated dependency vulnerability scanning (pip-audit or equivalent).
