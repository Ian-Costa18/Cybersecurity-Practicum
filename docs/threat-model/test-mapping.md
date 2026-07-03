# Test-to-Threat Mapping (Executable Demonstration)

This document is the [#111](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/111)
deliverable: it maps the passing adversarial tests to their threat-model IDs and reports the
four-bucket classification over the threats the proxy **owns**. The method — the `delta` cut and
the four evaluation buckets — is defined in [evaluation-plan.md](../evaluation-plan.md) §3; the
per-threat values it maps against are settled in the catalog ([00-overview.md](00-overview.md) and
the per-threat files). This is curation and reporting over the existing suite, not new tests.

Every test name below has been verified to exist in `tests/`. Run the suite with `uv run pytest`.

---

## Scope: what "demonstrated" means here

Only **owned** threats (`delta: improved` or `introduced` — 27 of 28) carry a `bucket`. The single
**inherited** threat, [CRYPTO-2](CRYPTO-2-cryptographic-side-channel-leakage.md), is excluded from
the distribution and reported once as a scope statement (see [evaluation-plan.md](../evaluation-plan.md)
§3); it is baseline residual risk, not a proxy weakness, and has no test to map.

The four buckets answer *how do we know the defense holds?*

| Bucket | Meaning | Count | Test-backed? |
|---|---|---|---|
| **①** | Executably demonstrated — an adversarial test drives the claim and asserts it fails | 5 | **yes** (this document) |
| **②** | Argued by design — the guarantee follows from the architecture, not a bespoke test | 8 | no (rationale) |
| **③** | Operator-enforced — the defense lives in deployment config the proxy cannot compel | 9 | no (operator) |
| **④** | Accepted limitation — explicitly out of scope for the MVP | 5 | no (accepted) |

Bucket ① was specified with two labelled tiers — **black-box** (driven at the HTTP edge; oracle =
the PyPI mock is never invoked) and **integrity/detection** (asserted at the crypto/DB layer;
oracle = `Ed25519Verify` fails). In the final classification **all five bucket-① threats sit in the
black-box tier.** No owned threat lands at the integrity/detection tier — see
[the note on Ed25519 tamper-evidence](#note-the-integritydetection-tier-collapsed-into-host-2-) below.

---

## Bucket-① executable demonstration map

The five owned threats whose defense is demonstrated by a driving adversarial test. Each row states
the claim, the named test(s) with their exact path, and the pass/fail oracle the test asserts.

### CORE-1 — Single Approver Account Compromise · improved · residual high×high

- **Claim demonstrated:** one compromised approver cannot cause a publish; m-of-n flips to
  authorized only at the m-th approval from **distinct** identities.
- **Tests:**
  - `tests/approvals/test_votes.py::test_quorum_reached_only_at_the_threshold` (domain layer)
  - `tests/approvals/test_approve.py::test_two_approvals_over_http_reach_quorum` (HTTP edge)
  - `tests/approvals/test_votes.py::test_a_non_eligible_user_cannot_vote`
- **Oracle (black-box):** below m distinct-identity approvals the request stays `pending` and the
  PyPI publish path is never reached; the state flips to authorized **exactly** at the threshold, not
  before. A non-eligible identity's vote is rejected and never counts toward quorum.
- **Flagship showcase:** the end-to-end "compromised quorum-minus-one cannot publish" narrative is
  the **Act 2 demo** ([#114](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/114)) —
  referenced here, not rebuilt.

### CORE-2 — API Token Theft · improved · residual high×medium

- **Claim demonstrated:** a stolen API token can *open* a hash-bound request but cannot *publish*
  without quorum; revocation and `is_active` gating instantly disable a leaked token.
- **Tests:**
  - `tests/test_execution.py::test_a_denied_request_never_reaches_pypi`
  - `tests/approvals/test_votes.py::test_quorum_reached_only_at_the_threshold`
  - `tests/test_token_auth.py::test_a_revoked_token_is_rejected`
  - `tests/test_token_auth.py::test_a_token_of_an_inactive_user_is_rejected`
- **Oracle (black-box):** a token-authenticated submission opens a `pending` request; the PyPI mock
  is never invoked without m signed Votes over the bound hash (submission ≠ publication). A revoked
  token, or a token whose owning User is `is_active = false`, is rejected at request time.

### VOTE-2 — Captured-Credential Replay · introduced · residual low×high

- **Claim demonstrated:** a captured `password + TOTP` pair is one-shot — the TOTP burns per
  `(user, time-step)` and cannot be reused to vote again, on a different request, or at login; voting
  freezes at any terminal state; an identical re-cast is an idempotent no-op.
- **Tests:**
  - `tests/approvals/test_votes.py::test_a_reused_totp_code_is_burned_and_rejected`
  - `tests/approvals/test_votes.py::test_a_burned_code_cannot_vote_a_different_request`
  - `tests/auth/test_login.py::test_a_reused_totp_code_cannot_log_in_twice`
  - `tests/approvals/test_votes.py::test_voting_is_frozen_after_a_terminal_state`
  - `tests/approvals/test_approve.py::test_voting_on_a_closed_request_shows_the_frozen_page`
  - `tests/approvals/test_votes.py::test_identical_repeat_is_an_idempotent_noop`
- **Oracle (black-box):** a redeemed `(user, time-step)` TOTP is rejected on every second use
  (re-vote, cross-request, login); a vote on a terminal request records nothing and returns the
  frozen page; an identical re-cast leaves the tally unchanged.
- **Residual (noted, not a gap):** a captured-but-unredeemed code inside its ±1-step (~90 s) window
  is the accepted residual, operator-tunable via `auth.totp_window`. Bounding the window further is
  [#30](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/30) (request timeouts); no
  bucket change — the threat is already ①.

### VOTE-3 — Browser-Borne Approval Coercion · introduced · residual low×high

- **Claim demonstrated:** a forged **cross-site** vote is impossible because the approval flow
  carries no ambient credential — every `POST /approve/{id}` requires a fresh `password + TOTP` in
  the form body.
- **Tests:**
  - `tests/approvals/test_approve.py::test_a_vote_requires_fresh_reauthentication`
- **Oracle (black-box):** a vote posted with wrong/absent credentials returns **401**, records
  **zero** votes, and leaves the request `pending`.
- **Per-leg gap (noted):** this covers the **CSRF** leg (①, today). The **UI-redress / clickjacking**
  leg is ③ operator-enforced today (reverse-proxy `X-Frame-Options` / `frame-ancestors 'none'`);
  [#127](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/127) (in-app anti-framing
  headers) promotes that leg ③ → ① via a header-presence assertion. Headline bucket is the primary
  (CSRF) leg's — ①.

### PUB-1 — Package Swap Between Upload and Publication · introduced · residual low×critical

- **Claim demonstrated:** artifact bytes swapped after approval are refused at publish — approvers
  sign a specific SHA-256, and the Executor re-verifies `SHA-256(held artifact) == action_hash`
  immediately before publishing.
- **Tests:**
  - `tests/service_types/one_time/test_publish.py::test_matching_hash_publishes`
  - `tests/service_types/one_time/test_publish.py::test_a_mutated_artifact_refuses_and_never_calls_pypi`
  - `tests/test_execution.py::test_a_mutated_payload_is_refused_at_publish`
  - `tests/test_execution.py::test_a_denied_request_never_reaches_pypi`
  - `tests/approvals/test_approve.py::test_artifact_download_returns_the_staged_bytes` (approver-side
    cross-check: the exact staged bytes are downloadable for inspection before signing)
- **Oracle (black-box):** a mutated artifact fails the hash re-verification and the PyPI mock is
  **never** invoked; a matching hash publishes. A denied request never reaches PyPI.
- **Out of scope (noted):** a fully compromised proxy (L6) holding the live upload token can ignore
  its own check — an accepted MVP limitation owned by [HOST-1](HOST-1-proxy-host-compromise.md) (④).

---

## Gaps & notes

**Note — the integrity/detection tier collapsed into HOST-2 (②).** #111 originally anticipated an
integrity/detection-tier ① threat backed by Ed25519 tamper-evidence
(`tests/approvals/test_votes.py::test_vote_is_ed25519_signed_and_verifies_offline`, which exists and
passes). In final classification that evidence underwrites [HOST-2](HOST-2-database-write-compromise.md),
which is **② , not ①**: a database-write attacker who *also* substitutes an approver's public key
produces a *validly-signed* forgery no offline verify catches, so tamper-evidence is **argued by
design** (content-tamper leg tested; key-substitution leg argued), not a clean single oracle. Hence
all five ① threats are black-box tier and the integrity/detection tier has no owned occupant.

**No unfilled bucket-① gaps.** Every current ① claim rests on named tests that exist **today**, with
no pending issue as a precondition — which is exactly the checkable statement the bucket-① roll-up
issue guarantees. The roll-up (#121, #123, #32+#126, #124, #125, #127) tracks the *promotion* of
threats currently ②/③ into ① (e.g. VOTE-3's UI-redress leg via #127, IDENT-5/DOS-1 via in-proxy rate
limiting), **not** the five that are demonstrated now.

**INFO-1's disclosure boundary is tested, but the threat is ②.** The endpoint boundary around
[INFO-1](INFO-1-information-disclosure-via-quorum-status-approver-visibility.md) is ①-grade in the
suite — no/invalid link → 404, and deniers/withdrawers/non-actors are never named in any response
(`tests/approvals/test_approve.py`). The **headline** classification is still ②, because the
disclosure INFO-1 describes (quorum progress + opt-in endorser identities to a legitimate viewer of
their own request) is *intended* #22 transparency — an accepted design decision, not a defended
failure. The tests demonstrate the boundary is honored; they do not turn an accepted disclosure into
a demonstrated denial.

---

## Full owned-threat results table

All 27 owned threats: `delta`, residual (likelihood, severity), `bucket`, and either the backing
test + oracle (bucket ①) or the one-line rationale for why the claim is argued/operator/accepted
rather than demonstrated. This doubles as the backing data for the overview
[Residual Risk Matrix](00-overview.md#residual-risk-matrix). The lone inherited threat is listed
below the rule as a scope statement, not a bucket.

| ID | Δ | Residual (lik × sev) | Bucket | Backing test + oracle, or rationale |
|---|---|---|---|---|
| [CORE-1](CORE-1-single-approver-account-compromise.md) | improved | high × high | ① | Quorum threshold + non-eligible rejection (`test_quorum_reached_only_at_the_threshold`, `test_two_approvals_over_http_reach_quorum`, `test_a_non_eligible_user_cannot_vote`); oracle = below m, PyPI never invoked. Flagship = Act 2 demo (#114). |
| [CORE-2](CORE-2-api-token-theft.md) | improved | high × medium | ① | Submission ≠ publication + token containment (`test_a_denied_request_never_reaches_pypi`, `test_quorum_reached_only_at_the_threshold`, `test_a_revoked_token_is_rejected`, `test_a_token_of_an_inactive_user_is_rejected`); oracle = stolen token opens a request but PyPI never invoked without m Votes. |
| [CORE-3](CORE-3-insider-collusion.md) | improved | low × critical | ④ | Accepted: m-of-n cannot defend against ≥ m parties colluding — a deliberate design boundary. Every vote is non-repudiably Ed25519-signed (argued deterrent), but collusion is out of scope. |
| [IDENT-1](IDENT-1-admin-account-compromise.md) | introduced | medium × critical | ② | Argued: admin takeover casts *genuine* signed votes, so signatures detect nothing; the property is "takeover cannot be silent" — victim notifications + atomic audit journaling. Enroll-forward path → ① once #125 lands. |
| [IDENT-2](IDENT-2-enrollment-link-interception.md) | introduced | medium × high | ③ | Operator: secure enrollment-link distribution + out-of-band confirmation are topology, not proxy-enforceable. Detection leg → ① once #128 lands. |
| [IDENT-3](IDENT-3-notification-channel-interception.md) | introduced | medium × high | ③ | Operator: end-to-end channel security (STARTTLS/SMTPS, SPF/DKIM/DMARC) is deployment config; the proxy cannot authenticate the transport it hands links to. |
| [IDENT-4](IDENT-4-phishable-approver-authentication.md) | introduced | high × high | ② | Argued: password + TOTP is inherently phishable/relayable; containment (one relayed session = one vote) is the design guarantee. Phishing-resistant WebAuthn (#129) is the capture-prevention closer → ①. |
| [IDENT-5](IDENT-5-no-anti-automation-on-authentication-endpoints.md) | introduced | high × high | ③ | Operator: rate limiting lives at the reverse proxy/WAF today. In-proxy limiter (#123) promotes ③ → ①. |
| [VOTE-1](VOTE-1-proxy-session-hijacking.md) | introduced | medium × critical | ② | Argued: the login-session cookie is `HttpOnly + Secure + SameSite=Strict` and voting is re-auth-gated (no session to steal on the vote path); the residual is that admin actions ride the session, argued not tested. |
| [VOTE-2](VOTE-2-captured-credential-replay.md) | introduced | low × high | ① | TOTP burn + terminal freeze + idempotent re-cast (`test_a_reused_totp_code_is_burned_and_rejected`, `test_a_burned_code_cannot_vote_a_different_request`, `test_a_reused_totp_code_cannot_log_in_twice`, `test_voting_is_frozen_after_a_terminal_state`, `test_voting_on_a_closed_request_shows_the_frozen_page`, `test_identical_repeat_is_an_idempotent_noop`); oracle = a redeemed code is rejected on every second use. |
| [VOTE-3](VOTE-3-browser-borne-approval-coercion.md) | introduced | low × high | ① | No-ambient-credential CSRF foreclosure (`test_a_vote_requires_fresh_reauthentication`); oracle = forged vote → 401, zero recorded, still pending. UI-redress leg ③ → ① via #127. |
| [VOTE-4](VOTE-4-approval-request-fatigue.md) | introduced | high × high | ② | Argued: a human-vigilance residual with no script-drivable oracle; approval context + hash display + m-of-n backstop bound the marginal wrongful vote. |
| [HOST-1](HOST-1-proxy-host-compromise.md) | introduced | low × critical | ④ | Accepted: code execution on the host defeats any in-process defense — the accepted apex of the DB-capability ladder. |
| [HOST-2](HOST-2-database-write-compromise.md) | introduced | medium × critical | ② | Argued: content-tamper is caught by Ed25519 offline verify (`test_vote_is_ed25519_signed_and_verifies_offline`), but a writer who also substitutes the public key forges a validly-signed vote no oracle catches → argued, not ①. #121 (signed quorum snapshot) hardens it. |
| [HOST-3](HOST-3-database-read-compromise.md) | introduced | medium × high | ③ | Operator: DB confidentiality is deployment (least-privilege role, encrypted volume, no exposed port). Credentials become uniformly ② once #122 wraps the TOTP secret. |
| [HOST-4](HOST-4-database-repudiation-attack.md) | introduced | medium × medium | ③ | Operator: append-only INSERT grants + an external WORM mirror defend the audit trail; the MVP has no in-proxy hash chain to demonstrate. |
| [CRYPTO-1](CRYPTO-1-cryptographic-implementation-failure.md) | introduced | low × high | ② | Argued (②-ceiling): "no implementation bug exists" has no adversarial oracle; the shipped crypto invariant tests (`test_invariant_1..4`) support the argument but cannot prove absence of bugs. |
| [PUB-1](PUB-1-package-swap-between-upload-and-publication.md) | introduced | low × critical | ① | Hash-binding re-verification (`test_matching_hash_publishes`, `test_a_mutated_artifact_refuses_and_never_calls_pypi`, `test_a_mutated_payload_is_refused_at_publish`, `test_a_denied_request_never_reaches_pypi`, `test_artifact_download_returns_the_staged_bytes`); oracle = mutated bytes refuse and PyPI is never invoked. |
| [PUB-2](PUB-2-proxy-bypass.md) | introduced | medium × critical | ③ | Operator: complete mediation is a credential-topology property (revoke pre-existing tokens, demote maintainers) the proxy cannot enforce for an external service. Out-of-band publish reconciliation (#124) → ① detection tier. |
| [PUB-3](PUB-3-external-account-recovery-bypass.md) | introduced | low × critical | ③ | Operator: an external service's own recovery flow is outside the proxy's reach; 2FA + a group-controlled recovery inbox are the mitigations. |
| [DOS-1](DOS-1-request-resource-flooding.md) | introduced | high × low | ③ | Operator: request/upload caps live at the reverse proxy/WAF today. In-proxy limits (#32, #126) promote ③ → ①. |
| [DOS-2](DOS-2-destructive-availability-attack.md) | introduced | medium × low | ③ | Operator: recovery (offsite/WORM backups, tested restore, re-enrollment) is deployment territory by nature; fails safe — pure availability, never an unauthorized publish. |
| [DOS-3](DOS-3-compromised-approver-as-denial-of-service.md) | introduced | medium × low | ④ | Accepted: a single approver's unilateral veto/withhold over quorum availability; admin deactivation + availability-aware quorum sizing are the response, not a demonstrated defense. |
| [DOS-4](DOS-4-approver-withholding.md) | introduced | medium × low | ④ | Accepted: passive non-voting with no timeout in the MVP; quorum sizing must absorb the loss. |
| [CODE-1](CODE-1-application-layer-vulnerability.md) | introduced | low × critical | ② | Argued: SQLAlchemy parameterization, Pydantic edge validation, a small framework-free route surface. Pentest/fuzz assurance is out of scope; authz regression tests are a ① promotion candidate. |
| [CODE-2](CODE-2-supply-chain-attack-on-the-proxy-itself.md) | introduced | low × critical | ④ | Accepted: an in-process poisoned dependency *is* the proxy — no config survives it. Likelihood-reduced by uv.lock hash pinning + CI dependency scanning + Dependabot. |
| [INFO-1](INFO-1-information-disclosure-via-quorum-status-approver-visibility.md) | introduced | high × medium | ② | Argued: the disclosure is intended #22 transparency to a legitimate viewer; the disclosure *boundary* (404 on bad link; non-endorsers never named) is ①-grade tested, but the accepted-leak headline is ②. |

**Inherited (excluded from the distribution — scope statement, not a bucket):**

| ID | Δ | Residual (lik × sev) | Bucket | Scope statement |
|---|---|---|---|---|
| [CRYPTO-2](CRYPTO-2-cryptographic-side-channel-leakage.md) | inherited | low × low | N/A | Timing/side-channel leakage in primitive verification is the same exposure carried by any service that authenticates a secret; the proxy neither worsens nor specifically defends it beyond vetted constant-time library primitives. Baseline residual risk, reported once per [evaluation-plan.md](../evaluation-plan.md) §3. |
