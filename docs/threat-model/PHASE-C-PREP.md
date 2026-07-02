<!--
TEMPORARY WORKING DOC — Phase C grill prep for the threat-model deep-dive (#107).
Per-threat review notes gathered before the Phase C per-threat deep pass. Companion to
REVIEW-PLAN.md; delete alongside it when the deep-dive closes. Not part of the published catalog.

Every claim below marked "verified" was checked against the specs / code / tests on
2026-07-01 (branch 107-threat-model-hardening). Everything else is a question for the grill.
-->

# Phase C Prep — Per-Threat Review Findings

Pre-grill review of all 27 threat files against the settled Phase B decisions
([REVIEW-PLAN.md](REVIEW-PLAN.md)), the governing specs, the open issue list, and the
existing test suite. Organized by Phase C batch. Each threat gets: what Phase B already
settled (don't re-litigate), what the body gets wrong or stale (fix), what was verified
true (keep), and what's genuinely open (grill).

---

## Cross-cutting findings (apply to many batches)

### X1 — Invalid and mismatched `stride` tags despite the "✓" status grid

The tracker's status grid marks `stride` finalized for all 27 threats, but:

- **T12 carries `"Social Engineering"` — not a STRIDE category.** Settled value is
  `Spoofing, Elevation of Privilege`. Must fix in Batch 6.
- **T5** current `[Information Disclosure, Elevation of Privilege]` vs. settled
  `Information Disclosure` only (the "EoP (deferred)" category line goes too).
- **T10** current `[Spoofing, Information Disclosure]` vs. settled `Spoofing` only.
- **T26** current `[Elevation of Privilege]` vs. settled `Spoofing, Elevation of Privilege`.

Grill: treat the settled strawman values as authoritative over the grid's ✓, or re-confirm
each of these four in their batch.

### X2 — Only-issues rule audit (planned defenses → issue or MISSING)

Verified against the open issue list. **Covered:** timeouts #30 (T2/T3), reminders #31/#99
(T3), credential wrapping #25 (T1/T4), SSO #35 (T1), secret managers #29 (T4), key erasure
#38 (T4), TOTP encryption #122 (T5/T7), quorum binding #121 (T6), auth throttle #123
(T25/T23), request abuse/cooldown #32 (T12/T27), Apprise #20 (T16), content preview #33 +
screen-share #23 + fine-grained authz #27 + formal verification #26 (T19), Traefik #24 (T14),
peer-approved recovery #34.

**MISSING an issue (file one in-batch or drop/demote the defense):**

| Threat | Planned defense with no issue |
|---|---|
| T6 | external append-only/WORM log; Postgres UPDATE-blocking triggers (may migrate to the new audit-suppression threat as *operator* config — then no issue needed) |
| T8 | approval-link expiration (grill: subsumed by #30 timeouts? A timed-out request freezes votes, which is effectively link expiry) |
| T9 | out-of-band enrollment confirmation |
| T13 | admin-action notifications; peer-approved **admin actions** (#34 is credential *recovery*, not the same); signed/append-only admin log (shares T6's story) |
| T15 | step-up re-auth for admin actions; IP/TLS-fingerprint session binding (logout is NOT missing — see X4) |
| T17 | CI crypto-invariant checks as a ① promotion claim (see X3 — four invariant tests already exist, so the issue may be "expand", not "create") |
| T21 | CSRF tokens on state-changing forms |
| T26 | token expiry/rotation reminders; usage anomaly detection; per-token IP allowlist |
| T27 | max upload size / artifact-count cap (grill: is this inside #32's scope or a separate issue?) |

### X3 — Existing tests already cover many bucket-① claims (name them, don't hand-wave)

Verified by reading test names. This is the raw material for the #111 mapping table and for
keeping Phase C's ① claims honest *today* (several "① once issue lands" phrasings can cite
these as the already-landed half):

| Threat | Existing executable evidence |
|---|---|
| T1 | `test_quorum_reached_only_at_the_threshold`, `test_two_approvals_over_http_reach_quorum`, `test_a_non_eligible_user_cannot_vote` (tests/approvals/test_votes.py, test_approve.py) + Act 2 demo #114 |
| T6 | `test_vote_is_ed25519_signed_and_verifies_offline`, `test_verify_detects_a_tampered_record`, `test_vote_record_canonical_bytes_is_stable_and_field_sensitive`, `test_a_reenrolled_users_old_votes_still_verify` |
| T8 | `test_a_reused_totp_code_is_burned_and_rejected`, `test_a_burned_code_cannot_vote_a_different_request`, `test_voting_is_frozen_after_a_terminal_state`, `test_a_vote_requires_fresh_reauthentication`, `test_a_reused_totp_code_cannot_log_in_twice` |
| T11 | `test_matching_hash_publishes`, `test_a_mutated_artifact_refuses_and_never_calls_pypi` (test_publish.py); `test_a_mutated_payload_is_refused_at_publish`, `test_a_denied_request_never_reaches_pypi` (test_execution.py) |
| T15 | `test_a_tampered_or_wrongly_keyed_cookie_does_not_verify`, `test_deleting_the_record_revokes_resolution`, `test_an_expired_session_is_invalid_and_cleaned_up` (tests/auth/test_sessions.py) |
| T17/T20 | `test_invariant_1_bcrypt_output_is_not_aes_key_material`, `test_invariant_2_enc_key_is_never_persisted_on_the_record`, `test_invariant_3_sign_returns_only_a_signature_not_the_key`, `test_invariant_4_each_encryption_uses_a_unique_iv` (tests/core/test_crypto.py) — the strawman calls these "candidate" ① tests; **they already exist** |
| T22 | `test_unknown_request_returns_404`, `test_page_names_endorsers_and_counts_the_rest`, `test_withdrawn_approver_is_not_named`, `test_stream_is_link_scoped_and_names_endorsers` — both #111 boundary negatives exist |
| T26 | `test_a_valid_token_authenticates_via_api_tokens`, `test_a_revoked_token_is_rejected`, `test_a_token_of_an_inactive_user_is_rejected` (tests/test_token_auth.py) |

Grill: T17's bucket (settled ②) deserves a second look given invariants 1–4 are already
executable — at minimum the body should name them instead of listing tests as "planned."

### X4 — Stale "planned" items that are actually shipped (or vice versa)

- **T15 lists "an explicit user-facing logout / session-revocation endpoint" as planned —
  it exists** (`test_logout_revokes_the_session_immediately`, tests/auth/test_login.py).
- **T11 lists "surface the hash prominently in the approve/deny UI" as a future
  enhancement — the spec already requires it**: [web-proxy.md:169](../web-proxy.md) — the
  approve page shows the artifact SHA-256 *and a download link*; the download half is
  tested (`test_artifact_download_returns_the_staged_bytes`). This also **removes the
  tension** with T12's settled ② rationale, which leans on "hash display" as a current
  defense.
- **T18's "Current defenses: None specifically documented" is doubly stale**: `uv.lock`
  carries **557 sha256 pins** (verified) and a CI dependency-audit leg exists — **but only
  on `progress-report-4`** (commits `be71e97` pip-audit → `767f337` native `uv audit`),
  which post-date this branch's cut. **Merge progress-report-4 into this branch before
  Batch 8**, or T18's rewrite will cite CI that isn't visible from its own branch.
  Dependabot "on by default" still needs a one-time check of the repo settings.
- **T3's "no expiration in the MVP" is verified accurate** (request-lifecycle.md marks
  `timed_out` future, #30) — keep, and cite #30 explicitly.

### X5 — Capability-axis misfits

- **T18 has `capability: []`** — the L1–L9 model has no slot for "external dependency
  compromise" (overview summary table says "External"). Decide a representation once
  (empty list + prose? an explicit `External` label?) — the overview regen (Phase D)
  needs whatever convention Phase C picks.
- **T26's** capability is "possession of a leaked token" — also not an L-level (body says
  L1/L2 *with token access*, overview says "Token possession"). Same decision.
- **T12** capability `[L2]` = *compromised requester*, but body says "or any authenticated
  requester" — an insider requester is L7-flavored. Minor; settle in Batch 6.

### X6 — Three NEW threat files need provisional IDs at write time

Batches 3, 6, 7 each create a file (audit-trail suppression, app-layer vulnerability,
destructive availability). Final IDs are Phase D's call, but filenames/`id:` are needed at
write time. Recommendation: take **T28/T29/T30** provisionally (no existing references to
collide with; T7's slot stays empty until Phase D renumbering is decided) and let Phase D
renumber if it wants density.

### X7 — Scope question: forward-auth threats vs. the #109 narrowing

Issue #109 (scope practicum to package-publishing; general-purpose as future vision) is
**still open**. T14 is entirely forward-auth; T15/T27 mention forward-auth surfaces;
`grant_expiry` machinery exists in code. Grill once, apply everywhere: does the finished
catalog (a) keep forward-auth threats first-class, (b) annotate them as
out-of-practicum-scope, or (c) defer to #109's resolution? Affects T14 most (its whole
existence), and the §evaluation story (an out-of-scope threat probably shouldn't count in
the owned-threat bucket distribution the report defends).

### X8 — `related:` graph is sparse and asymmetric

Examples: T7→T5 but T5→[]; T25 lists six neighbors, none list T25 back except T1/T12/T23;
T13→T6 but T6→[]; T19→[] despite being T1's boundary. The batch structure hands you the
natural clusters — populate `related:` per batch (including the three NEW threats) rather
than as a Phase D afterthought, then let Phase D only *verify* symmetry.

### X9 — Leave the overview alone during Phase C

00-overview.md's navigator/status labels (Mitigated/Partial/Gap), its missing `attack`
field in the frontmatter list, the empty Repudiation row, and the "`TODO` until #107 lands"
notes are all Phase D regen material. Don't burn batch time syncing them.

---

## Batch 1 — Multi-party authorization core (T1, T19, T11)

### T1 — Single approver account compromise · settled: improved ①, flagship

- **Body is in good shape**; the T25 caveat on the TOTP factor is honest and should survive.
- **Missing the delta story**: nothing in the body compares against the baseline (one
  stolen PyPI token = unilateral publish). The improved-① flagship needs that prose — it
  feeds the §1 value proposition and the Act 2 demo (#114).
- "What the attacker gains: submit **one approval**" — under append-only votes they also
  gain deny/flap (T2's territory) and *withdraw*; one cross-ref line suffices.
- Planned defenses → cite #35 (SSO) and #25 (wrapping) inline (only-issues rule).
- `attack`: coverage map says T1078 Valid Accounts. Downstream supply-chain consequence
  (T1195.002) is **prose only** per the T1657 cross-cutting decision.
- ① evidence exists today (X3). Name the tests + #114.
- `related: [T25]` → add T19 (boundary), T26 (machine analog), T2 (same capability,
  deny direction).

### T19 — Insider collusion · settled: improved ④, attack T1078, drop T1657

- **Body needs the settled reframing**: collusion as the *residual of the core
  improvement* (baseline: 1 insider publishes alone; proxy: m colluders, each leaving a
  signed non-repudiable vote). Currently reads as a pure limitation — that framing put it
  at risk of the introduced ledger, which Phase B explicitly rejected.
- Planned defenses all have issues (#33, #23, #27, #26) — cite them.
- **Grill**: cross-ref the NEW audit-suppression threat? T19's accountability story
  ("cannot deny having approved") assumes the audit trail survives; a colluding quorum
  with DB access could try to delete evidence afterward — one sentence pointing at the
  new threat keeps the non-repudiation claim honest.
- `related: []` → at least T1, T13 (admin can *install* a quorum — adjacent path to L9).

### T11 — Package swap (upload→publish) · settled: introduced ①

- **Body is the most honest in the catalog** (compromised-proxy limitation already
  disclaimed with the mvp-prd cite). Keep.
- **Stale**: "surface the hash in the UI" as future — already spec'd + partially tested
  (X4). Rewrite as current defense.
- **Capability line is off**: "attacker with write access to the artifact store" — the
  artifact store *is* the DB (`StagedArtifact.content`, verified in models.py), i.e.
  **L5**, not just L6. Frontmatter says `[L6]` only; grill whether to add L5.
- ① evidence: four named tests exist (X3) — both black-box (never calls PyPI) and
  executor-level. Strongest test story after T26.
- `attack`: grill call — T1565.001 (stored-data manipulation) fits the swap-in-DB variant;
  the T1657 rule says downstream consequence stays prose.
- `related: []` → T6 (DB-write sibling), T4 (the disclaimed case), T26 (token opens the
  request the hash binds).

---

## Batch 2 — Approver authentication & session (T13, T25, T15, T23, T24)

*This batch writes the net-cancellation framing once (T23/T24) — budget grill time for
that prose, it's reused verbatim in the overview regen.*

### T13 — Admin account compromise · settled: introduced ①

- **Biggest bucket question in the catalog.** Strawman rationale: "admin forgery
  detectable via Ed25519." But the body's own attack path — enroll new approvers, meet
  quorum with *genuine* signatures — is **not** detected by Ed25519 at all; every vote
  verifies. What exactly is the ① test asserting? Candidates: (a) admin actions emit
  `AuditLog` rows atomically (subscriber tests exist in tests/audit/), (b) admin panel
  cannot cast votes. Neither *defeats* the roster-takeover attack; they only evidence it.
  **Grill: is T13 honestly ① (what's the oracle?), or ② (detection-by-audit argued) /
  ③ (minimal admins, Tier-1 creds)?**
- Body's honest split (signed Votes vs. unsigned AuditLog rows) is current and good —
  it's also the seam the NEW audit-suppression threat lives in; keep the two consistent.
- The users.yaml/config.yaml "Related — privileged config input" row is current
  (constraints.md §10) and worth keeping — it's the config-file analog that #121's
  residual also points at.
- Missing issues (X2): admin-action notifications, peer-approved admin actions, signed
  admin log.
- `related: [T6]` → add T15 (hijacked admin session collapses into T13 — T15 says so).

### T25 — No anti-automation · settled: introduced ①-once-#123 / ③-today, no split

- **Body is already the model** for the "① once the issue lands, honest today" pattern —
  the batch mostly needs to (a) swap "the in-proxy rate-limiting work item" for **#123**,
  (b) apply settled tags (`attack: T1110.001, T1499.003`).
- The `.scratch/security/0001-in-proxy-rate-limiting.md` reference in the Phase D
  inventory — confirm #123 captured its content, then the threat should cite only #123.
- Verified: failed attempts genuinely consume nothing (verifier records the TOTP step
  only after both factors pass) — the body's sharpest claim is true per
  approver-authentication.md.

### T15 — Proxy session hijacking · settled: introduced ②

- Body is detailed and current on the session model (every User gets a session;
  `session_expiry_hours` 8h verified in config.md).
- **Stale**: logout listed as planned but shipped (X4). Promote to current defenses with
  its test.
- **The ② argument's residual is load-bearing**: admin actions are *not* re-authed — a
  hijacked admin session drives the whole Admin Portal. The settled ② ("re-auth-gated
  voting, argued") is about *approval* authority; the admin residual needs either an issue
  (step-up re-auth, X2) or explicit accepted-residual prose. Grill which.
- `attack`: T1539 (steal web session cookie) / T1550.004 (use web session cookie) per the
  coverage map.

### T23 — bcrypt timing · settled: **inherited N/A**, slim entry

- Slim-down is the work: body keeps the applies-to-surface rationale ("considered, not
  forgotten") + net-cancellation sentence + cross-ref #123 (the limiter kills the oracle's
  request volume). The "Planned defenses / Operator configuration" rows should collapse —
  an inherited threat defended threat-by-threat contradicts the scope statement.
- `attack: T1040` with the noted weak-fit caveat (settled; taxonomies.md judgment call).

### T24 — Shared-account password reset · settled: **inherited N/A**

- Same slim-down treatment as T23; this is where the net-cancellation prose is written
  once (baseline PyPI account recovery has the identical out-of-band exposure).
- **Grill**: the body's "Planned defenses: intermediary email service, deferred" — for an
  inherited/N-A threat this should probably demote to a future-vision mention (or cite
  #34 if that's the intended vehicle; #34 is peer-approved *credential recovery*, which is
  adjacent but in-proxy). Don't leave a planned-defense row that implies ownership.
- Note: capability L7 (insider co-owner) — fine, but the *shared-account* concept itself
  is the general-purpose use case (#54, X7). If #109 narrows scope, T24's example should
  speak PyPI (the org account's recovery email), not generic shared accounts.

---

## Batch 3 — Data & credentials at rest (T5 ⊕ T7, T6, T26, NEW audit-suppression)

### T5 — Database read · settled: introduced ③ (creds ② once #122); absorbs T7

- The merge is cheap: T5's "what the attacker gains" **already enumerates plaintext TOTP**
  — absorbing T7 means deleting the file, adding the #122 forward-look ("uniformly ② for
  credentials once TOTP secrets are wrapped"), and keeping one line naming the
  cracked-bcrypt + TOTP = full-takeover combination that was T7's core.
- Settled stride drops EoP (X1).
- Verify at batch time: "bcrypt cost ≥ 12" and the salt sentence — the body says "128-bit
  random salt per user (PBKDF2)" while cryptography.md attributes the 128-bit salt to
  **bcrypt's** output format and cites SP 800-132's ≥128-bit for PBKDF2; make the body
  name which salt it means.
- The "ACL config is a YAML file, not in DB" aside is correct and worth keeping (it's why
  policy tamper lands in T6-via-config-vs-DB).
- T7 file deletion: T07's `related: [T5]` dies with it; **code comments repointing is
  Phase D** (models.py, hash_credentials.py — already inventoried). Nothing else in the
  catalog references T7 (T26 references T5, not T7).

### T6 — Database write · settled: introduced ①; absorbs quorum-policy tamper (#121)

- **The expansion is the work.** New attack line: the quorum snapshot on the request row
  is **unsigned** (verified: cryptography.md §Audit Trail Integrity — only Votes carry
  approver signatures) → an L5 attacker lowers an in-flight request's snapshot 3→1 and
  satisfies it with one genuinely-signed compromised vote. Planned defense = #121
  (bind snapshot into vote payload + execution-time config re-check). Same oracle as the
  existing tamper story.
- **Honest bucket phrasing (settled)**: ① once #121 lands, ③ (DB ACLs) today — mirror
  T25's pattern. Existing ① evidence for the *tamper-detection* half is real (X3: four
  signature tests).
- "What they cannot do" needs a caveat: "retroactively make a fabricated approval look
  valid without also controlling the public key" — an L5 attacker **can swap the stored
  public key** (the body's own gains-list says so). What breaks that? (Re-verification
  against an out-of-DB copy? Nothing today?) Grill the honest answer; it likely lands in
  audit-suppression/operator territory.
- Deletion disclaimed → cross-ref NEW audit-suppression threat, adjacent write per plan.
- Planned "external WORM log / triggers" — migrate to audit-suppression as operator
  config (X2), keep T6 focused on modification.

### T26 — API token theft · settled: **improved** ①

- Body is strong and spec-true (hash-at-rest, per-token revocation, `is_active` gating —
  all three verified by existing tests, X3). The work is the **improved-delta prose**:
  baseline = the same credential in the same CI slot with strictly more power (unilateral
  publish); proxy token = "may ask permission." Ian's line from the grill ("having it on
  one approver's machine is much more dangerous than in the proxy") belongs here.
- Settled stride adds Spoofing (X1); `attack: T1528, T1552, T1550.001`.
- Missing issues for the three planned defenses (X2) — or demote them to
  operator/future-mention; ① doesn't depend on them.
- The black-box ① test ("drive everything, assert PyPI mock never invoked") — closest
  existing: `test_a_denied_request_never_reaches_pypi` + token tests; the *combined*
  token-flood-never-publishes test may still be #111 curation work.

### NEW — Audit-trail suppression · settled: Repudiation · T1070, T1562 · introduced ③

- To write (provisional T28, X6). Settled content: deletion/reordering of audit records —
  exactly what T6's invariant does NOT cover (cryptography.md disclaims: no hash chain,
  non-vote lifecycle records unsigned — verified §Audit Trail Integrity). Evidence attack,
  not outcome attack (deleting a Deny doesn't unfreeze the request). ③ = INSERT-only DB
  ACL + external append-only log (operator). Hash-chaining named as promotion path, **not
  commitment**.
- First dedicated Repudiation threat — the empty STRIDE row fills at Phase D regen.
- Inherits from T6: the WORM-log operator guidance; from T13: the unsigned `AuditLog`
  rows. Cross-ref both + T19 (collusion evidence) and the destructive-availability threat
  (shared WORM/offsite defense).

---

## Batch 4 — Cryptographic design (T17, T20)

### T17 — Crypto implementation failure · settled: introduced ②

- **Four of the five listed invariants already have executable tests** (X3) — the body's
  "Planned defenses: unit tests asserting…" is stale. Rewrite: invariants 1–4 tested
  (name them), the fifth (plaintext-release-before-tag-verify) is enforced by the
  `cryptography` library's API shape (argued). Grill whether that inventory changes the
  bucket (② with named tests vs. a ① claim scoped to the invariants).
- If any ① promotion is claimed, it needs an issue (X2) — likely "CI invariant checks"
  as an expansion of the existing tests.
- `attack`: no Enterprise technique fits implementation bugs cleanly — likely
  empty-with-prose or the taxonomies.md weak-fit pattern (same convention as T23's
  T1040 caveat). **Decide the empty-`attack:` convention here** (also hits T3, T20).

### T20 — AES-GCM nonce exhaustion · settled: introduced ②

- Body verified consistent with cryptography.md (2^48 invocations / ≤2^-18 advantage /
  §8.3 rotation note). Cheap batch item.
- `test_invariant_4_each_encryption_uses_a_unique_iv` partially evidences the fresh-IV
  claim — cite it.
- `attack`: same empty-tag convention question as T17.

---

## Batch 5 — Approval-link & notification lifecycle (T8, T9, T10, T16)

### T8 — Approval link replay · settled: introduced ①

- Body is careful and current (single-use TOTP per RFC 6238 §5.2, ±1-step residual
  honestly stated, `auth.totp_window: 1` verified in config.md). Best-tested threat in
  the catalog (X3: five named tests incl. the cross-request burn).
- Planned "link expiration" has no issue — grill: fold into #30 (timeout freezes votes ⇒
  link dies with the request) or file separately (X2).
- Note the body lists `timed_out` among terminal states — true to request-lifecycle.md
  but that state is future (#30); phrase so the freeze claim doesn't imply timeouts ship
  today.
- `attack`: coverage map offers T1550.004 (web session cookie is a weak fit for an
  approval *link*) and T1111 relay is now T10's. Genuine grill decision — maybe
  T1550 (alternate auth material) parent.

### T9 — Enrollment link interception · settled: introduced ③

- Body fine; replace hardcoded "24 hours" with the config key
  (`auth.enrollment_link_expiry_hours`, default 24 — verified).
- "Admin must manually create the account" as a defense — now half-true: declarative
  provisioning (`users.yaml`) also mints enrollment links without per-account admin
  clicks. Check account-management.md phrasing at batch time.
- Missing issue: out-of-band enrollment confirmation (X2).
- Enrollment tokens stored hashed (T5 body says so) — a DB read can't mint enrollment
  links; worth one cross-ref line.

### T10 — Approval link phishing · settled: introduced ②; **absorbs AITM** — biggest rewrite of the batch

- **Current body is the weakest in the catalog** (3 thin rows) *and* its central "cannot
  do" claim is misleading: "captured credentials can't forge Ed25519 signatures without
  the database." A **real-time relay doesn't forge anything** — the attacker submits the
  relayed password+TOTP to the real proxy, and *the proxy itself* derives the signing key
  and signs the vote. The Ed25519 argument is no defense against AITM at all. This is
  exactly why Phase B expanded T10.
- Settled content to write: same lure, escalated capability (`attack: T1566.002, T1111,
  T1557`); T8's TOTP burn = *detection signal* (victim's concurrent legitimate login
  fails), not prevention; containment lives in T1 (one relayed session = one vote;
  baseline AITM = full account = full publish — that comparison is also improved-flavored
  prose worth one sentence even though delta stays introduced); residuals: TOTP is not
  phishing-resistant, single-approver relay succeeds, WebAuthn = promotion path, not
  commitment.
- Settled stride drops Information Disclosure (X1).
- `related: []` → T8 (burn signal), T1 (containment), T16 (channel), T25 (throttle slows
  interactive relay).

### T16 — SMTP channel · settled: introduced ③

- Body fine; "approval links are not secret" is consistent with T22's link-gating story —
  but note the tension to resolve in prose: T22 calls the link "unguessable, delivered
  solely to eligible approvers" (a mild secret), T16 says links aren't secrets (auth is
  the barrier). Both are true (view ≠ vote) — say it once, consistently, in both bodies.
- Cite #20 (Apprise). `fallback_to_portal` — verify the config key exists at batch time.

---

## Batch 6 — Web-edge request handling (T21, T22, T12, NEW app-vuln)

### T21 — CSRF · settled: introduced ① ("candidate CSRF test")

- **The body's threat statement is half-obsolete, in a good way.** Verified: the vote
  POST (`/approve/{id}`) carries username+password+TOTP **in the form body** — a
  cross-site attacker cannot supply credentials, so approve/deny CSRF is *structurally*
  infeasible, not "partially mitigated by stateless sessions." That's an argued-by-design
  win worth stating plainly.
- **But the unprotected CSRF surface moved**: session-cookie-gated state changes now
  exist — User Portal (mint/revoke API token, cancel request) and Admin Portal
  (create/deactivate/reset) — and **no CSRF tokens exist anywhere in src** (verified);
  `SameSite=Strict` is the only control. **Grill: re-scope T21** from "the approve/deny
  form" to "state-changing web-edge forms," with the vote as the solved case and the
  portals as the live one.
- Bucket ①'s oracle needs re-deriving after the re-scope: the executable negative for the
  vote is "credential-less forged POST records nothing" (close to
  `test_wrong_password_is_rejected_and_records_nothing`); for the portals it doesn't
  exist yet → CSRF-token issue (X2), "① once it lands, ② (SameSite argued) today"?
- Title/slug will likely change → reference-sweep implications (Phase D inventory).

### T22 — Quorum-status disclosure · settled: introduced ②, attack T1589

- Body is current, matches the #22 design, and both #111 boundary negatives already have
  tests (X3). Cheapest item in the batch — apply tags, cite tests, done.
- Only nit: "Planned defenses: None required" — restate as the accepted-design rationale
  (② argued) rather than "none," so the bucket and the row agree.

### T12 — Approval-request fatigue · settled: introduced ②, retitle (drop "MFA Bombing"), stride fix (X1)

- Settled: title becomes "Approval-request fatigue"; T1621 stays in the body as the
  analogy that doesn't apply (no unsolicited prompt exists to fatigue); `attack: T1656`;
  distinct from T27 (human-vigilance vs. mechanical flooding).
- **Body contradiction to fix**: "Current defenses: **None**" vs. settled ② resting on
  "approval context + hash display + m-of-n backstop." The hash display + artifact
  download are spec'd on the approve page (X4), and the body's own "cannot do" row
  already contains the m-of-n/explicit-vote argument. Rewrite the defenses row to name
  them; "None" belongs only to the *rate-limiting* half, which is #32's.
- Retitle → filename/slug change → Phase D sweep entry (overview + related: lists).
- Capability nit (X5).

### NEW — App-layer vulnerability · settled: introduced ② (provisional T29, X6)

- To write per the Phase B verdict: injection / SSRF / broken-object-authz / auth-bypass
  in the proxy's own FastAPI code; T4 assumes code-exec already, T17 is crypto-only, T18
  is dependencies-only — this fills the T1190 hole.
- ② argument: SQLAlchemy parameterization, Pydantic edge validation, small route
  surface, framework-free logic (slice rule). Residual to state: no pentest/fuzzing
  assurance. Authz regression tests = ① promotion candidate — **needs an issue if named**
  (X2).
- Placement note: `attack: T1190` — also the only threat where the ruff/ty/CI hygiene
  legs are legitimately part of the defense prose.

---

## Batch 7 — Availability & DoS (T2, T3, T27, NEW destructive-availability)

### T2 — Compromised approver as DoS · settled: introduced ④

- Body good — the flap analysis (self-limiting: each flip costs re-auth and is signed) is
  current with ADR 0009 and tested behavior (`test_a_flip_to_deny_before_quorum_closes_denied`
  — note a deny *closes* the request immediately; "flap while pending" only applies to
  approve→withdraw, worth one precision pass).
- Planned "rate limiting on denials / anomaly detection" — no issue; grill: the deny path
  is explicitly *never throttled* per T25's design. Denial anomaly detection may belong in
  #32 or drop to operator monitoring (X2 adjacent).
- Cite #30 for timeouts. ④ rationale (admin deactivation is the only lever) intact.

### T3 — Approver withholding · settled: introduced ④

- Verified accurate ("no expiration in MVP", #30 future). Cite #30 + #31/#99.
- `attack`: nothing fits passive inaction — the empty-`attack:` convention decided in
  Batch 4 (T17) applies.
- Grill (small): is T3 introduced or is there a baseline analog (a required PyPI
  maintainer sitting on a release)? Phase B settled introduced — the body should carry
  the one-line justification (the *approval gate* creating the liveness dependency is
  proxy-created).

### T27 — Request & resource flooding · settled: introduced ①-once-#32/#123 / ③-today

- Body accurate and honest (verified: `StagedArtifact.content` stages bytes in DB, no
  size/count cap anywhere). Mirror T25's honest-bucket phrasing with the issue keys.
- Upload-size cap: confirm whether #32's text covers it or file separately (X2).
- `attack: T1499` (+T1498 if amplification is claimed); T1499.003 is T25's.

### NEW — Destructive availability attack · settled: DoS · T1485, T1531, T1490 · introduced ③ (provisional T30, X6)

- To write per Phase B: one entry covering DB/state destruction, backup destruction, and
  mass approver lockout (quorum exhaustion). Shared attacker (privileged), shared impact
  (capability lost, never subverted), shared defense family (backups, restore,
  re-enrollment, ACLs).
- Must state: **fails safe** (pure availability — can never produce an unauthorized
  publish) and recovery is operator territory *by nature* (WORM/offsite defense shared
  with audit-suppression — cross-ref).
- Boundary prose to include: vs. T2/T3 (vote-level denial), vs. T27 (exhaustion by
  flooding vs. destruction), vs. T4/T5/T6 (the capability levels that enable it).

---

## Batch 8 — Infrastructure, host & network boundary (T4, T18, T14)

### T4 — Proxy host compromise · settled: introduced ④

- Body detailed and honest (memory-held credentials as documented MVP limitation;
  tamper-evidence of *past* records as the surviving guarantee). Planned defenses all
  have issues (#25, #29, #38) — cite inline.
- One precision item: "runtime memory zeroing should be confirmed in implementation" —
  either confirm (#38's scope) or keep as open residual; don't leave it dangling as a
  half-claim.
- Consequence-class kinship with T18 (④: in-process code/host owns everything) should be
  stated in both bodies — Ian's discriminator line ("if the operator can't completely
  defend it, we own it — accepted limitation") is the reusable sentence.

### T18 — Supply chain on the proxy · settled: introduced ④, body flips emphasis

- **Pre-req: merge `progress-report-4` into this branch first** (X4) — the CI audit leg
  (`uv audit`, commit 767f337) isn't on 107-threat-model-hardening yet, and the rewrite
  cites it as a current defense.
- Rewrite per settled decision: current defenses = uv.lock hash-pinning (**557 hashes**,
  verified) + CI dependency-audit leg + Dependabot alerts (verify repo setting once);
  operator items (trusted source, mirror, minimal image) = likelihood reducers around an
  accepted core; release signing / reproducible builds demoted to a mention, untracked.
- `attack: T1195.001`; capability representation (X5).
- delta justification to carry: introduced because the baseline has no self-hosted
  dependency tree between the maintainer and PyPI (settled).

### T14 — Network path bypass · settled: introduced ③

- Body fine as the purest ③ exemplar ("Current defenses: None — documented constraint" is
  the honest phrasing for operator-enforced).
- Cite #24 (Traefik) for the planned row.
- **X7 lands here hardest**: if the practicum narrows to package-publishing (#109),
  forward-auth — T14's entire subject — is future-vision. Decide the annotation in the
  X7 grill question before polishing this body.
- `attack`: coverage map suggestions (T1046 discovery / T1210 lateral) are weak fits for
  "topology allows bypass"; consider T1599 (Network Boundary Bridging) or the
  empty-tag convention.

---

## Suggested grill agenda (highest-leverage questions first)

1. **X7** — forward-auth threats vs. #109 scope (decides T14's framing + several bodies' examples).
2. **T13's bucket** — what is the ① oracle for admin compromise? (Batch 2's hardest call.)
3. **T21's re-scope** — vote-CSRF is solved-by-design; the live surface is the portals. New scope, new oracle, new issue.
4. **T10's rewrite** — confirm the relay analysis (proxy signs on relayed creds; Ed25519 row deleted).
5. **Empty-`attack:` convention** (T3, T17, T20, maybe T14) — one decision, four threats.
6. **X6** — provisional IDs T28/T29/T30 for the three new files.
7. **X2 sweep** — for each MISSING row: file issue, fold into existing issue, or demote the defense.
8. **T17's bucket** given invariants 1–4 already execute (② with named tests vs. scoped ①).
9. **X5** — capability representation for External/token-possession.
10. **T6's public-key-swap caveat** — what honestly breaks it today?
