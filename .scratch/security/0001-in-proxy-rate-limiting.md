---
title: "Add in-proxy rate limiting / anti-automation on authentication & request endpoints"
labels: [enhancement, practicum]
body: |
  ## Motivation

  The proxy has **no rate limiting or account lockout** on any security path. Failed
  auth attempts burn nothing (`auth/credentials.py::verify_credentials` records the
  TOTP step only *after* both factors pass), so an attacker gets unlimited guesses.
  This underpins several threat-model entries:

  - **IDENT-5 — No anti-automation on authentication endpoints.** An L2 attacker who
    already knows a password can brute-force the 6-digit TOTP online
    (`totp_window:1` → ~3/10^6 per try, unlimited tries), defeating the second
    factor and collapsing the L2→L3 gap CORE-1 relies on. Separately, each attempt
    forces a full bcrypt verify (~300 ms) → CPU-exhaustion DoS.
  - **DOS-1 — Request & resource flooding (DoS).** No rate limit / quota on request
    creation; denial→immediate-retry amplification; no max upload size (artifact
    bytes stored in-DB via `StagedArtifact`).
  - **VOTE-4 — Approval fatigue / MFA bombing.** Cooldown-after-denial + creation rate
    limiting are the planned mitigations.
  - **CRYPTO-2 — Timing attack on bcrypt.** Already names "rate limit the login
    endpoint" as its operator mitigation.

  **This is the executable-test enabler.** Implementing in-proxy rate limiting moves
  IDENT-5, CRYPTO-2, and part of VOTE-4/DOS-1 out of the *operator-configured* bucket and into the
  *demonstrated-by-a-test* bucket of `docs/evaluation-plan.md` §2.

  ## Scope

  Per-IP throttle (`429 + Retry-After`, **not** a hard per-account lock) on the
  credential-guessing choke points:

  - `POST /login` and `POST /approve/{id}` — both funnel through
    `auth/credentials.py::verify_credentials`.
  - `POST /pypi/legacy/` — `auth/credentials.py::resolve_api_token`.
  - Request-creation quota + max upload size for the flooding/DOS-1 angle.

  ## Recommended design (from feasibility scoping)

  - **Hand-rolled DB-backed counter, no new library.** Mirror the existing atomic
    check-and-record idiom in `auth/credentials.py::_burn_totp_step` + the
    `ConsumedTotp` model (unique index + `begin_nested()` SAVEPOINT). No
    slowapi/Redis — fights the single-worker (ADR 0013) + DB-only-state model.
  - **`Depends(...)` 429 guard in `auth/guards.py`**, calling a framework-free
    limiter primitive in `core/` (honors the slice dependency rule). Not middleware
    (can't cleanly see the parsed form username; sits above all slices).
  - **Trusted-proxy-aware client IP.** No client-IP handling exists today. Read the
    IP from `X-Forwarded-For` only when the connection arrives from a declared
    trusted reverse proxy (config: trusted-proxy IPs / hop count); otherwise use the
    socket IP and ignore client XFF. Otherwise a direct attacker forges a fresh XFF
    per request and evades the limit.
  - New `auth.rate_limit_*` config fields (window, threshold, backoff duration).

  ## Risks / edge cases (must address)

  1. **Lockout-as-DoS** — never hard-lock an account (an attacker could lock out an
     honest approver and block the "2 a.m. deny"). Per-IP throttle/backoff only, and
     **never throttle the `Deny` path**.
  2. **Account-existence oracle** — preserve the deliberate *indistinguishable-
     failure* property of `verify_credentials`; key on IP (or hashed username),
     return the same generic 401, surface 429 only on the rate dimension.
  3. **Atomicity across SQLite↔Postgres** — atomic `UPDATE … count+1` /
     insert-on-conflict, not read-modify-write. The increment for a *failed* attempt
     must persist via its own SAVEPOINT-commit even though the request transaction
     rolls back (the subtlety `_burn_totp_step` already solves).

  ## Testability

  - Pure unit test of the `core/` counter with arbitrary string keys + injected
    clock (`tests/core/test_rate_limit.py`).
  - Integration test via `TestClient` setting `X-Forwarded-For` per request to
    simulate distinct source IPs: N failures from one IP → 429; a different IP →
    still 401; clock advance → reset. Sits beside `tests/auth/test_login.py`,
    `tests/test_token_auth.py`, `tests/approvals/test_approve.py`.

  ## Effort

  Moderate (~1–2 days, ~300–450 LOC + one Alembic migration). New:
  `core/rate_limit.py`, a migration, tests. Changed: `core/models.py`,
  `auth/guards.py`, the three handlers, `core/config.py`, and the IDENT-5/DOS-1/VOTE-4/CRYPTO-2
  rows in `docs/threat-model.md` (per the same-branch doc-edit rule).

  ## Doc updates on implementation

  `docs/threat-model.md` (IDENT-5/DOS-1/VOTE-4/CRYPTO-2 → current defense), `docs/web-proxy.md`
  §Known Limitations, `docs/config.md` (new `auth.rate_limit_*` fields).

  _Long-lived: keep open until implemented; it's the spine for converting several
  operator-delegated threats into executable tests._
---

> Local stand-in for a GitHub issue (`gh` was unavailable). Promote with
> `gh issue create` when the CLI is configured, then delete this file.
