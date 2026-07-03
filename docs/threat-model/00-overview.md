# Threat Model: Multi-Party Authorization Proxy

This directory is the threat catalog for the proxy: one file per threat under a stable
group-prefixed identifier, plus this overview. It enumerates the attack surface, what an
attacker with each capability can achieve, what defenses are in place, and what operators
must configure. It is a living document — update it whenever the architecture, threat
surface, or scope changes.

**How this is organized.** Each threat lives in its own `<PREFIX>-<n>-<slug>.md` file
carrying machine-readable frontmatter (`id`, `title`, `stride`, `attack`, `capability`,
`delta`, the four residual/baseline risk anchors, `bucket`, `related`). The `id` is the
stable, citable handle used across the other docs. IDs are grouped into **nine thematic
prefixes**, each numbered independently so the catalog reads top-to-bottom as a narrative —
value proposition first, introduced surfaces next, accepted residuals last — and so adding
or retiring a threat touches only its own group, never the whole catalog:

| Prefix | Theme | IDs |
|---|---|---|
| **CORE** | Value proposition — what the proxy is *for* | CORE-1 … CORE-3 |
| **IDENT** | Approver identity & the authentication surface | IDENT-1 … IDENT-5 |
| **VOTE** | The approval session & the vote itself | VOTE-1 … VOTE-4 |
| **HOST** | Host, database & records | HOST-1 … HOST-4 |
| **CRYPTO** | Cryptography | CRYPTO-1 … CRYPTO-2 |
| **PUB** | The publish boundary / mediation completeness | PUB-1 … PUB-3 |
| **DOS** | Availability & abuse | DOS-1 … DOS-4 |
| **CODE** | Proxy code & supply chain | CODE-1 … CODE-2 |
| **INFO** | Residual information disclosure | INFO-1 |

The frontmatter contract, the controlled vocabularies (STRIDE, capability rungs, buckets,
delta), and the authoring rules are defined in [CONTRIBUTING.md](CONTRIBUTING.md) and
[taxonomies.md](taxonomies.md).

### The net-delta cut

The `delta` field classifies every threat against the **direct-publish baseline** —
publishing to PyPI with an API token plus account 2FA, *no proxy*:

- **improved** — a pre-existing threat the proxy measurably reduces (3 threats: all of CORE).
- **introduced** — attack surface that exists *only because the proxy exists* (24 threats).
- **inherited** — a pre-existing authentication-layer threat the proxy leaves unchanged,
  out of scope by design (1 threat: CRYPTO-2).

The proxy **owns** the improved + introduced threats (27 of 28); the evaluation reports its
four-bucket classification over exactly those. The lone **inherited** threat carries
`bucket: N/A` and is reported as a scope statement, not defended threat-by-threat (see
below). The method is defined in [evaluation-plan.md](../evaluation-plan.md).

### The four-bucket distribution (owned threats)

Every owned threat is assigned one evaluation `bucket` — the honesty axis of the model,
answering *how do we know the defense holds?*:

| Bucket | Meaning | Count | Threats |
|---|---|---|---|
| **①** | **Executably demonstrated** — an adversarial test drives the claim at the edge | 5 | CORE-1, CORE-2, VOTE-2, VOTE-3, PUB-1 |
| **②** | **Argued by design** — the guarantee follows from the architecture, not a bespoke test | 8 | IDENT-1, IDENT-4, VOTE-1, VOTE-4, HOST-2, CRYPTO-1, CODE-1, INFO-1 |
| **③** | **Operator-enforced** — the defense lives in deployment configuration the proxy cannot compel | 9 | IDENT-2, IDENT-3, IDENT-5, HOST-3, HOST-4, PUB-2, PUB-3, DOS-1, DOS-2 |
| **④** | **Accepted limitation** — explicitly out of scope for the MVP; documented, not defended | 5 | CORE-3, HOST-1, DOS-3, DOS-4, CODE-2 |

The bucket-① threats are the ones the test suite must demonstrate directly; their
test-to-threat mapping — each claim, its named test(s), and the pass/fail oracle — is enumerated in
[test-mapping.md](test-mapping.md) (the [#111](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/111)
deliverable), which also carries the full owned-threat results table backing this distribution.

### Inherited scope statement (CRYPTO-2)

[CRYPTO-2 — Cryptographic Side-Channel Leakage](CRYPTO-2-cryptographic-side-channel-leakage.md)
is the model's single **inherited** threat: timing / side-channel leakage in primitive
verification (e.g., `bcrypt` comparison) is the same exposure carried by *any* service that
authenticates a secret. The proxy neither worsens nor specifically defends it beyond using
vetted constant-time library primitives; it is baseline residual risk (likelihood **low** ×
severity **low**), reported here as scope rather than classified into a bucket.

---

## System Summary

The proxy intercepts requests to protected services and requires m-of-n approvers to
independently authenticate (password + TOTP) and explicitly approve the request before it
proceeds. Two post-approval patterns exist:

- **One-time:** the proxy executes a single action (PyPI publish, credential reveal) on
  behalf of the requester.
- **Forward-auth:** the proxy grants a session and forwards the request to a backend service.

Approvers hold no additional key material beyond a password and a TOTP app. An Ed25519 key
pair is generated per approver at enrollment; the private key is encrypted at rest with
AES-256-GCM (key derived via PBKDF2 from the approver's password). Every approval is signed
with the approver's private key, producing a tamper-evident audit record verifiable without
any password.

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
| **External** | No system foothold — acts through the software supply chain (dependencies, build). |

---

## Threat Catalog

The catalog runs as a narrative: **CORE** states the value proposition, the middle groups
enumerate the surfaces the proxy *introduces*, and the tail settles the accepted residuals.
Within each group threats run most-severe-first, except CORE, which runs thesis → residual.

### CORE — Value proposition (improved)

The three threats the proxy exists to reduce. Each is *improved*, not eliminated: the proxy
does not make credential theft less likely, it makes it matter less.

- [CORE-1](CORE-1-single-approver-account-compromise.md) — **Single Approver Account Compromise** · ① · residual high×high
  One stolen approver credential buys one vote, not a publish; m-of-n keeps ≥1 independent barrier standing.
- [CORE-2](CORE-2-api-token-theft.md) — **API Token Theft** · ① · residual high×medium
  A stolen proxy API token still lands behind the quorum gate; the real PyPI token never leaves the proxy.
- [CORE-3](CORE-3-insider-collusion.md) — **Insider Collusion** · ④ · residual low×critical
  m-of-n colluders can approve improperly — out of scope by design — but every vote is non-repudiably Ed25519-signed.

### IDENT — Approver identity & authentication surface (introduced)

- [IDENT-1](IDENT-1-admin-account-compromise.md) — **Admin Account Compromise** · ② · residual medium×critical
  The admin enrolls and deactivates approvers; a compromised admin can manufacture or remove quorum members.
- [IDENT-2](IDENT-2-enrollment-link-interception.md) — **Enrollment Link Interception** · ③ · residual medium×high
  A single-use, expiring enrollment link, intercepted before the approver uses it, lets an attacker enroll in their place.
- [IDENT-3](IDENT-3-notification-channel-interception.md) — **Notification-Channel Interception** · ③ · residual medium×high
  Email/SMTP carrying approval and enrollment links can be observed or manipulated in transit.
- [IDENT-4](IDENT-4-phishable-approver-authentication.md) — **Phishable Approver Authentication** · ② · residual high×high
  Password + TOTP is inherently phishable; a real-time relay can proxy an approver's login and vote.
- [IDENT-5](IDENT-5-no-anti-automation-on-authentication-endpoints.md) — **No Anti-Automation on Authentication Endpoints** · ③ · residual high×high
  Absent rate limiting, the TOTP factor can be brute-forced online and auth endpoints driven to CPU exhaustion.

### VOTE — The approval session & the vote (introduced)

- [VOTE-1](VOTE-1-proxy-session-hijacking.md) — **Proxy Session Hijacking (Login Session)** · ② · residual medium×critical
  A stolen login-session cookie rides the session; voting stays re-auth-gated, but admin actions do not.
- [VOTE-2](VOTE-2-captured-credential-replay.md) — **Captured-Credential Replay** · ① · residual low×high
  A captured password + TOTP replayed inside the ±1-step window; single-use TOTP + terminal freeze bound it.
- [VOTE-3](VOTE-3-browser-borne-approval-coercion.md) — **Browser-Borne Approval Coercion** · ① · residual low×high
  CSRF / clickjacking against the approve form; `SameSite` + per-vote re-auth limit the window.
- [VOTE-4](VOTE-4-approval-request-fatigue.md) — **Approval-Request Fatigue** · ② · residual high×high
  Flooding an approver with lookalike requests to harvest a reflexive approval (the MFA-bombing analogue).

### HOST — Host, database & records (introduced)

- [HOST-1](HOST-1-proxy-host-compromise.md) — **Proxy Host Compromise** · ④ · residual low×critical
  Code execution on the proxy host reads in-memory secrets and in-flight data; the accepted apex of the DB rungs.
- [HOST-2](HOST-2-database-write-compromise.md) — **Database Write Compromise** · ② · residual medium×critical
  DB write access can tamper with records; Ed25519 signatures + least-privilege grants make tampering evident.
- [HOST-3](HOST-3-database-read-compromise.md) — **Database Read Compromise** · ③ · residual medium×high
  DB read exposes hashed credentials and the plaintext TOTP secret; private keys stay encrypted at rest.
- [HOST-4](HOST-4-database-repudiation-attack.md) — **Database Repudiation Attack** · ③ · residual medium×medium
  DB write access can delete or alter the audit trail; append-only grants + an external mirror defend it.

### CRYPTO — Cryptography

- [CRYPTO-1](CRYPTO-1-cryptographic-implementation-failure.md) — **Cryptographic Implementation Failure** · ② · residual low×high
  A bug in the crypto subsystem (KDF, AEAD, signing) would undermine the at-rest and audit guarantees. *(introduced)*
- [CRYPTO-2](CRYPTO-2-cryptographic-side-channel-leakage.md) — **Cryptographic Side-Channel Leakage** · N/A · residual low×low
  Timing / side-channel leakage in primitive verification — *inherited*, the same exposure as any authenticating service.

### PUB — Publish boundary / mediation completeness (introduced)

- [PUB-1](PUB-1-package-swap-between-upload-and-publication.md) — **Package Swap Between Upload and Publication** · ① · residual low×critical
  Swapping the artifact bytes between approval and publish; the hash binding forecloses it.
- [PUB-2](PUB-2-proxy-bypass.md) — **Proxy Bypass** · ③ · residual medium×critical
  Any residual credential able to publish *without* the proxy walks around the entire quorum gate.
- [PUB-3](PUB-3-external-account-recovery-bypass.md) — **External Account Recovery Bypass** · ③ · residual low×critical
  PyPI's own account-recovery (email reset) is an out-of-band path around the proxy.

### DOS — Availability & abuse (introduced)

- [DOS-1](DOS-1-request-resource-flooding.md) — **Request & Resource Flooding** · ③ · residual high×low
  Unmetered requests and uploads exhaust proxy resources; no in-proxy rate limit yet.
- [DOS-2](DOS-2-destructive-availability-attack.md) — **Destructive Availability Attack** · ③ · residual medium×low
  Data/host destruction or approver lockout by the high-capability rungs; backups + WORM storage mitigate.
- [DOS-3](DOS-3-compromised-approver-as-denial-of-service.md) — **Compromised Approver as Denial-of-Service** · ④ · residual medium×low
  A malicious approver denies or withholds to block quorum; admin deactivation + availability-aware quorum.
- [DOS-4](DOS-4-approver-withholding.md) — **Approver Withholding (Liveness Attack)** · ④ · residual medium×low
  A passive approver simply never votes; no timeout, so quorum sizing must absorb the loss.

### CODE — Proxy code & supply chain (introduced)

- [CODE-1](CODE-1-application-layer-vulnerability.md) — **Application-Layer Vulnerability in the Proxy** · ② · residual low×critical
  A bug in the proxy's own code (injection, an authorization flaw) could bypass the controls.
- [CODE-2](CODE-2-supply-chain-attack-on-the-proxy-itself.md) — **Supply Chain Attack on the Proxy Itself** · ④ · residual low×critical
  A poisoned dependency or build ships malicious code inside the proxy; accepted core, likelihood-reduced.

### INFO — Residual information disclosure

- [INFO-1](INFO-1-information-disclosure-via-quorum-status-approver-visibility.md) — **Information Disclosure via Quorum Status & Approver Visibility** · ② · residual high×medium
  The approve page leaks quorum progress and opt-in endorser identities; link-scoped and accepted.

---

## Visual Navigator

Two at-a-glance cuts of the catalog against the audited four-bucket `bucket:` field.
① Executably demonstrated · ② Argued by design · ③ Operator-enforced · ④ Accepted limitation ·
N/A Inherited (out of scope).

### STRIDE × bucket

A threat with multiple STRIDE tags appears in each of its rows.

| STRIDE ↓ / Bucket → | ① Demonstrated | ② Argued | ③ Operator | ④ Accepted | N/A Inherited |
|---|---|---|---|---|---|
| **S — Spoofing** | CORE-2 | IDENT-4, VOTE-1, VOTE-4 | IDENT-2, IDENT-3 | — | — |
| **T — Tampering** | PUB-1 | HOST-2 | — | CODE-2 | — |
| **R — Repudiation** | — | — | HOST-4 | — | — |
| **I — Information Disclosure** | — | CRYPTO-1, INFO-1 | IDENT-3, HOST-3 | HOST-1 | CRYPTO-2 |
| **D — Denial of Service** | — | — | IDENT-5, DOS-1, DOS-2 | DOS-3, DOS-4 | — |
| **E — Elevation of Privilege** | CORE-1, CORE-2, VOTE-2, VOTE-3 | IDENT-1, IDENT-4, VOTE-1, VOTE-4, HOST-2, CRYPTO-1, CODE-1 | IDENT-2, IDENT-5, HOST-3, PUB-2, PUB-3 | CORE-3, HOST-1, CODE-2 | — |

### Adversary capability × bucket

| Capability ↓ / Bucket → | ① Demonstrated | ② Argued | ③ Operator | ④ Accepted | N/A Inherited |
|---|---|---|---|---|---|
| **L1** | CORE-2, VOTE-2, VOTE-3 | IDENT-4, VOTE-1, CODE-1, INFO-1 | IDENT-2, IDENT-3, IDENT-5 | — | CRYPTO-2 |
| **L2** | CORE-1, CORE-2, VOTE-2 | VOTE-4 | IDENT-5, PUB-2, PUB-3, DOS-1 | — | — |
| **L3** | CORE-1 | IDENT-1 | — | DOS-3 | — |
| **L4** | — | CRYPTO-1 | HOST-3 | — | — |
| **L5** | PUB-1 | HOST-2 | HOST-4, DOS-2 | — | — |
| **L6** | — | — | DOS-2 | HOST-1 | — |
| **L7** | — | — | PUB-3 | DOS-3, DOS-4 | — |
| **L8** | — | — | DOS-2 | — | — |
| **L9** | — | — | — | CORE-3 | — |
| **External** | — | — | — | CODE-2 | — |

---

## Residual Risk Matrix

Every threat plotted by its **residual** posture — likelihood × severity *after* the proxy's
in-place defenses, the leftover risk an operator carries. (Improved threats use their
post-proxy residual; the inherited threat uses its unchanged baseline.)

| Likelihood ↓ / Severity → | Critical | High | Medium | Low |
|---|---|---|---|---|
| **High** | — | CORE-1, IDENT-4, IDENT-5, VOTE-4 | CORE-2, INFO-1 | DOS-1 |
| **Medium** | IDENT-1, VOTE-1, HOST-2, PUB-2 | IDENT-2, IDENT-3, HOST-3 | HOST-4 | DOS-2, DOS-3, DOS-4 |
| **Low** | CORE-3, HOST-1, PUB-1, PUB-3, CODE-1, CODE-2 | VOTE-2, VOTE-3, CRYPTO-1 | — | CRYPTO-2 |

The upper-left concentration (medium-likelihood × critical-severity: IDENT-1, VOTE-1,
HOST-2, PUB-2) is where residual risk is highest — three of the four are ② argued or ③
operator-enforced, so their standing depends on deployment discipline, not a demonstrated
test. The high×high band (CORE-1, IDENT-4, IDENT-5, VOTE-4) is dominated by the missing
anti-automation control (IDENT-5) and the phishing/fatigue surface it amplifies.

## Improved threats: baseline → residual

The proxy's value proposition, quantified. Each CORE threat exists at the direct-publish
baseline; the columns show what the proxy changes. The improvement lives on the **severity**
axis (or, for collusion, likelihood) — the proxy does not make credential theft less likely,
it caps what a theft achieves.

| Threat | Likelihood (base → residual) | Severity (base → residual) | What the proxy changes |
|---|---|---|---|
| [CORE-1](CORE-1-single-approver-account-compromise.md) Single Approver Account Compromise | high → high | **critical → high** | Unilateral publish collapses to one vote; ≥1 independent barrier still stands. |
| [CORE-2](CORE-2-api-token-theft.md) API Token Theft | high → high | **critical → medium** | A stolen token reaches the quorum gate, not PyPI; the real token never leaves the proxy. |
| [CORE-3](CORE-3-insider-collusion.md) Insider Collusion | **medium → low** | critical → critical | Requires m coordinated colluders instead of one credential; every vote is non-repudiable. |

---

## Summary Table

All 28 threats, one row each. **Δ** is the net-delta; **Bucket** is the evaluation
classification (N/A = inherited); **Residual** is residual likelihood × severity.

| ID | Threat | Capability | Δ | Bucket | Residual | Primary operator action |
|---|---|---|---|---|---|---|
| CORE-1 | Single approver account compromise | L2/L3 | improved | ① | high×high | Size quorum to expected breach rate; fast-deactivation runbook |
| CORE-2 | API token theft | L1/L2 | improved | ① | high×medium | Store tokens in a secrets manager; rotate on exposure; deactivate to kill all tokens |
| CORE-3 | Insider collusion | L9 | improved | ④ | low×critical | Independent approver units; high thresholds; audit log review; separate DBA role |
| IDENT-1 | Admin account compromise | L3 | introduced | ② | medium×critical | Minimize admins; Tier-1 admin credentials; review the admin action log |
| IDENT-2 | Enrollment link interception | L1 | introduced | ③ | medium×high | Distribute enrollment links E2E-secure; confirm enrollment out-of-band; SMTP TLS |
| IDENT-3 | Notification-channel interception | L1 | introduced | ③ | medium×high | STARTTLS/SMTPS; SPF/DKIM/DMARC on the sender domain |
| IDENT-4 | Phishable approver authentication | L1 | introduced | ② | high×high | SPF/DKIM/DMARC; one pinned proxy domain; train on decision-mismatch indicators |
| IDENT-5 | No anti-automation on auth endpoints | L1/L2 | introduced | ③ | high×high | Reverse-proxy/WAF rate limits on `/login`, `/approve`, `/pypi/legacy/`; TLS; alert on failures |
| VOTE-1 | Proxy session hijacking | L1 | introduced | ② | medium×critical | HTTPS + HSTS; short `session_expiry_hours`; minimize admins; own-origin, no iframe |
| VOTE-2 | Captured-credential replay | L1/L2 | introduced | ① | low×high | Tighten `auth.totp_window`; TLS everywhere; treat frozen-page reports as replay signals |
| VOTE-3 | Browser-borne approval coercion | L1 | introduced | ① | low×high | Reverse-proxy `X-Frame-Options`/`frame-ancestors 'none'`; dedicated domain |
| VOTE-4 | Approval-request fatigue | L2 | introduced | ② | high×high | Onboard "never approve what you cannot account for"; monitor per-requester volume |
| HOST-1 | Proxy host compromise | L6 | introduced | ④ | low×critical | Harden/patch the host; no persistent storage; egress filtering; Tier-1 asset treatment |
| HOST-2 | Database write compromise | L5 | introduced | ② | medium×critical | Least-privilege DB role (INSERT-only on records); pgaudit; independent public-key record |
| HOST-3 | Database read compromise | L4 | introduced | ③ | medium×high | Never expose the DB port; least-privilege user; encrypted volume; audit bulk reads |
| HOST-4 | Database repudiation attack | L5 | introduced | ③ | medium×medium | INSERT-not-DELETE grants; mirror the audit trail to a WORM store; alert on DELETE |
| CRYPTO-1 | Cryptographic implementation failure | L4 | introduced | ② | low×high | Security review of the crypto subsystem against `cryptography.md`; static crypto lint |
| CRYPTO-2 | Cryptographic side-channel leakage | L1 | inherited | N/A | low×low | Rely on vetted constant-time library primitives (baseline residual) |
| PUB-1 | Package swap (payload substitution) | L5 | introduced | ① | low×critical | None required; verify the deployed proxy re-verifies the hash as specified |
| PUB-2 | Proxy bypass | L2 | introduced | ③ | medium×critical | Revoke all pre-existing tokens; demote maintainers; sole upload credential in the proxy |
| PUB-3 | External account recovery bypass | L2/L7 | introduced | ③ | low×critical | Enforce PyPI 2FA/org policy; group-controlled recovery inbox; audit recovery methods |
| DOS-1 | Request & resource flooding | L2 | introduced | ③ | high×low | Monitor request/upload volume; deactivate anomalous requesters; watch DB growth |
| DOS-2 | Destructive availability attack | L5/L6/L8 | introduced | ③ | medium×low | Offsite/WORM backups; tested restore runbook; write-restricting ACLs; re-enroll path |
| DOS-3 | Compromised approver as DoS | L3/L7 | introduced | ④ | medium×low | Responsive admin deactivation; availability-aware quorum; alert-only denial monitoring |
| DOS-4 | Approver withholding | L7 | introduced | ④ | medium×low | Quorum sized for real availability; response-time expectations; replace absent approvers |
| CODE-1 | Application-layer vulnerability | L1 | introduced | ② | low×critical | WAF if available; patch image/runtime; restrict network exposure (likelihood reducers) |
| CODE-2 | Supply chain attack on the proxy | External | introduced | ④ | low×critical | Install from trusted source; private mirror; audit the lock file; minimal container |
| INFO-1 | Quorum status & endorser-identity leak | L1 | introduced | ② | high×medium | No action; set endorser-visibility expectations at onboarding if it concerns a deployment |

---

## Operator Checklist

The following configuration steps are required to achieve the security posture described
above. They are the operator's responsibility and cannot be enforced by the proxy itself —
they are the concrete work behind every ③ operator-enforced threat.

### Network & Deployment

- [ ] Deploy the proxy exclusively over HTTPS with a valid certificate.
- [ ] Enable HTTP Strict Transport Security (HSTS).
- [ ] Bind backend services (for forward-auth) to private network interfaces only.
- [ ] Add firewall rules so the backend is reachable only from the proxy host.
- [ ] Bind the proxy database to localhost or a private interface; never expose it to the internet.
- [ ] Test that direct access to the backend (bypassing the proxy) is blocked.
- [ ] Enable rate limiting on the authentication and upload endpoints (`/login`, `/approve`, `/pypi/legacy/`) at the reverse proxy or WAF until in-proxy limiting is available (IDENT-5 / DOS-1).
- [ ] Add `X-Frame-Options: DENY` / `Content-Security-Policy: frame-ancestors 'none'` at the reverse proxy and serve the proxy on its own dedicated origin (VOTE-1 / VOTE-3).

### SMTP / Email

- [ ] Configure SMTP with STARTTLS or SMTPS.
- [ ] Configure DMARC, DKIM, and SPF records for the proxy's sending domain (starves IDENT-4's lure).
- [ ] Consider enabling `fallback_to_portal: true` and distributing links out-of-band for high-security environments.

### Database

- [ ] Create a dedicated database user for the proxy with only the required table-level permissions (no superuser).
- [ ] Grant INSERT, not UPDATE or DELETE, on the approval records table (HOST-2, HOST-4).
- [ ] Enable database audit logging (pgaudit or equivalent); alert on unexpected bulk reads and on any DELETE against records tables.
- [ ] Mirror the audit trail to an external append-only / WORM store out of reach of the database role (HOST-4, DOS-2).
- [ ] Back up the database regularly, keep an offsite copy, and verify backup/restore integrity.
- [ ] Encrypt database storage at rest (raises the cost of extracting the plaintext TOTP secret, HOST-3).
- [ ] Keep an independent record of enrollment-time public keys outside the database (HOST-2).

### Session & Cookie Security

- [ ] Set `Secure` and `HttpOnly` flags on all session cookies.
- [ ] Set `SameSite=Strict` or `SameSite=Lax` on session cookies.
- [ ] Configure short session lifetimes appropriate to the sensitivity of the protected resource.

### Account & Approver Management

- [ ] Limit admin accounts to the minimum necessary.
- [ ] Store admin credentials in a password manager with a unique, strong password; use a hardware TOTP token where possible.
- [ ] Review the admin action log regularly — on the quiet enroll-forward path it is the detection (IDENT-1).
- [ ] Write an incident runbook for "compromised approver account deactivation."
- [ ] Set quorum thresholds accounting for approver availability (losing one approver must not block operations) (DOS-3, DOS-4).
- [ ] Confirm enrollment with approvers out-of-band before trusting their account.
- [ ] Distribute enrollment links via encrypted channels, not plain email (IDENT-2).
- [ ] Deactivate accounts immediately when an approver leaves the organization.
- [ ] Train approvers to never approve a request they did not themselves initiate (VOTE-4 approval-fatigue defense).
- [ ] Store API tokens in a secrets manager and rotate them on suspected exposure (CORE-2).

### Publish-Boundary Integrity

- [ ] Revoke all pre-existing project API tokens and demote maintainer accounts so the sole upload credential lives in the proxy (PUB-2).
- [ ] Enforce 2FA on the PyPI publisher account (prefer an organization account with a 2FA policy) (PUB-3).
- [ ] Register a recovery inbox that no single party controls (a group inbox), and audit registered email/recovery methods periodically (PUB-3).

### Monitoring & Auditing

- [ ] Monitor approval request and upload volume; alert on anomalous bursts (DOS-1, VOTE-4).
- [ ] Review the Ed25519 audit log periodically for unexpected approvals.
- [ ] Review admin action logs (user creation, deactivation, credential reset).
- [ ] Establish a process to re-evaluate bcrypt cost as hardware improves.

### Host Hardening

- [ ] Run the proxy on a minimal OS footprint with no unnecessary services.
- [ ] Run the proxy in a container with a minimal base image (limits CODE-2 blast radius).
- [ ] Apply OS-level patches regularly.
- [ ] Configure egress filtering to prevent unexpected outbound connections from the proxy host.
- [ ] Verify that the proxy's dependency lock file is pinned with hashes (CODE-2).
- [ ] Run automated dependency vulnerability scanning (pip-audit or equivalent).
