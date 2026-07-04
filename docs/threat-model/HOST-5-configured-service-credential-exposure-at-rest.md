---
id: HOST-5
title: "Configured Service-Credential Exposure at Rest"
stride: ["Information Disclosure", "Elevation of Privilege"]
attack: [T1552.001]
capability: [L6, external]
delta: improved
likelihood_baseline: medium
likelihood_residual: low
severity_baseline: critical
severity_residual: critical
bucket: 3
related: [HOST-1, PUB-2, CORE-2, CODE-2, IDENT-6]
---

# HOST-5 — Configured Service-Credential Exposure at Rest

| | |
|---|---|
| **Category** | Information Disclosure (read the file), Elevation of Privilege (spend the token) |
| **Capability** | L6 for an on-host read of `/config`; `external` for the reads short of any foothold — a committed `.env`, a leaked config backup, a world-readable mount. The point of this entry is that the *cheap* leg is the external one: no RCE is required to read a file that escaped. |
| **What the attacker gains** | [config.md](../config.md) and [deployment.md](../deployment.md) put the **real PyPI upload token** — plus the SMTP password and `server.secret_key` — in `config.yaml`/`.env` on disk. A read of that file hands over the live token: direct publish at PyPI, the entire quorum bypassed, which is [PUB-2](PUB-2-proxy-bypass.md)'s position reached through a file instead of an onboarding miss. [taxonomies.md](taxonomies.md) names this exact cell — *T1552.001 Credentials in Files = the PyPI token* — and this entry owns it: [HOST-1](HOST-1-proxy-host-compromise.md) covers the in-*memory* read (L6 RCE), [CORE-2](CORE-2-api-token-theft.md) the *proxy-issued* tokens, [HOST-3](HOST-3-database-read-compromise.md) the database. The co-located secrets are second-order: the SMTP password feeds [IDENT-4](IDENT-4-phishable-approver-authentication.md)'s lure at most, and `server.secret_key` alone forges nothing (the cookie HMAC protects a random id that must still resolve to a server-side session row). |
| **What they cannot do** | Reach any approver credential — those live in the database as bcrypt hashes and password-wrapped keys ([HOST-3](HOST-3-database-read-compromise.md)'s protection classes), not in config. Forge a session from `secret_key` alone (above). Publish *through* the proxy's records — the direct publish leaves no request, no votes, no `AuditLog` row, which is also why the proxy cannot detect it ([PUB-2](PUB-2-proxy-bypass.md)'s honest row). |
| **Current defenses** | `$ENV{}` substitution exists for every sensitive field ([config.md](../config.md) §Environment Variable Substitution) and the config docs mandate keeping real files out of version control — but substitution is **opt-in** and the default posture is plaintext-on-disk, so today the defense is the operator actually doing it. Container deployment scopes the file to the container filesystem ([deployment.md](../deployment.md)), which narrows casual exposure but is not an access control. |
| **Operator configuration** | Use `$ENV{}` (or a secrets manager injecting environment variables) for `services.*.credentials.*`, `server.secret_key`, and `notifications.email.smtp_password` — never inline them. Git-ignore the real `config.yaml`/`.env` (commit only the `*.example` files). Restrict `/config` to the proxy and deploy roles; keep it out of world-readable mounts. Encrypt backups that include config, and treat a leaked config file as a live token compromise: rotate the PyPI token immediately. |

## Delta story

`delta: improved` — and the gate is passed on the likelihood axis, so the argument must be
explicit. **Baseline:** *n* maintainers each hold a publish-capable PyPI token at rest —
`~/.pypirc` files, CI secret blocks, laptop keychains — and any single copy leaking is a
unilateral publish. Likelihood **medium**: n independent copies under independently varied
hygiene, against commodity infostealer and repo-scraping pressure, is a realistic event.
Severity **critical**. **Residual:** exactly one host holds the one publish-capable token.
Likelihood **low**: one file, on one hardened server, under one operator's hygiene.
Severity **critical** unchanged — when the leak happens the outcome is identical. Baseline
strictly worse on likelihood → the improved gate passes.

**The division line with [CORE-2](CORE-2-api-token-theft.md)**, stated so the improvement
is counted once per axis: CORE-2's improvement is that the tokens *maintainers still hold*
are demoted to request-only; HOST-5's is that the *publish-capable* token now rests in one
place instead of n. Two halves of the same centralization move — CORE-2 owns the demotion,
HOST-5 owns the concentration.

**The improvement is conditional on hygiene.** The proxy's default storage is plaintext
YAML with `$ENV{}` opt-in — one operator's discipline replaces n maintainers' discipline,
which is only a win if exercised. A committed `.env` forfeits the entire improvement in one
commit: the external leg exists precisely because concentration makes the single copy a
single catastrophic leak. That tension is why the residual mitigation posture is ③ and the
operator row carries the weight.

## Bucket

Bucket ③ (operator-enforced). The improvement itself is architectural (delivered by the
funnel design), but everything defending the remaining copy is deployment hygiene the proxy
cannot compel: `$ENV{}` substitution, secrets management, git-ignoring, file ACLs,
encrypted backups, rotation on suspected leak. No in-app mechanism guards the file the app
is configured *from*.

## ATT&CK mapping

**T1552.001 (Unsecured Credentials: Credentials in Files):** the canonical fit — a live
service credential sitting in a configuration file, harvestable by anyone who can read it.
This is the technique [taxonomies.md](taxonomies.md) shortlisted for the PyPI token from
the start; the database instance of the same technique (the plaintext `totp_secret`) is
tagged on [HOST-3](HOST-3-database-read-compromise.md).
