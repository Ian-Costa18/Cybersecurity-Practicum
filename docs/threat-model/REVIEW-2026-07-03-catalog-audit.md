# Threat-catalog audit — full pass (2026-07-03)

A four-axis audit of the 28-threat catalog on `107-threat-model-hardening`, run as four
parallel review agents: **(1)** delta-classification re-derivation under the
net-cancellation rule, **(2)** a STRIDE-per-element completeness sweep against the system
specs, **(3)** test-backing verification (every cited test read in full, plus a reverse
sweep of the suite), and **(4)** a consistency/wording/contract pass over all 28 files and
the governing docs. State at audit: `msig-threats validate` clean; distribution
3 improved / 24 introduced / 1 inherited; all 23 issues cited in Planned-defenses sections
verified open on GitHub. **This is a findings report — no catalog file was changed.**

## Executive summary

**The hunch was right in direction, modest in magnitude.** "3 improved + 1 inherited out
of 28" undersells both classes — but not because the catalog missed the analysis wholesale.
Two `introduced` threats should reclassify to `inherited`
([PUB-3](PUB-3-external-account-recovery-bypass.md) firm,
[IDENT-3](IDENT-3-notification-channel-interception.md) recommended), one genuinely missing
*improved* threat exists (authorization repudiation — the Ed25519 non-repudiation story has
no improved-side entry), and one missing *inherited* entry (transport/PKI trust failure).
The defended end state is **~4 improved / ~24 introduced / ~4–5 inherited over 32–33
threats**. The deeper problem is rationale hygiene: several delta stories argue the exact
form CONTRIBUTING bans ("this surface exists only because the proxy exists → introduced");
most survive by luck because the surface really is proxy-only, but on PUB-3 and IDENT-3 the
banned reasoning flips the answer.

Beyond the hunch:

- **One concentrated coverage gap:** the credential-bearing config/provisioning files
  (`users.yaml`, `config.yaml`/`.env`). The specs document their trust posture in prose but
  no threat owns them → proposed **IDENT-6** (rogue-admin injection via declarative
  provisioning, strong) and **HOST-5** (configured service-credentials at rest, moderate).
- **All five bucket-① claims hold** — each rests on ≥1 genuinely adversarial test. One tier
  label is overstated (CORE-1 has no PyPI-mock-oracle test) and there is **one true
  miscite** ([IDENT-2](IDENT-2-enrollment-link-interception.md)'s "regeneration invalidates
  the old link" — the test doesn't check it and **the code doesn't do it**: a latent code
  gap worth an issue).
- **Every derivable table in [00-overview.md](00-overview.md) recomputed clean** against
  frontmatter — bucket distribution, both matrices, risk matrix, all 28 summary rows. The
  drift is textual: 4 defects, ~11 inconsistencies, ~8 nits (all itemized in §4).

Suggested order of work is in §6.

---

## 1. Delta classifications — the improved/inherited question

### 1.1 Systemic finding: the banned rationale

The net-cancellation rule (CONTRIBUTING §`delta`) states: *"A surface being new doesn't
make a threat introduced; the threat failing to cancel against the baseline's equivalent
does."* Yet the surface-novelty argument appears nearly verbatim as the delta story in
[IDENT-3](IDENT-3-notification-channel-interception.md),
[PUB-3](PUB-3-external-account-recovery-bypass.md),
[DOS-1](DOS-1-request-resource-flooding.md),
[DOS-2](DOS-2-destructive-availability-attack.md),
[HOST-4](HOST-4-database-repudiation-attack.md),
[VOTE-2](VOTE-2-captured-credential-replay.md), and others. On most, the conclusion happens
to coincide with correct net-cancellation reasoning (the surface genuinely has no baseline
equivalent), so only the prose needs fixing. On two, the answer flips:

### 1.2 RECLASSIFY (firm): [PUB-3](PUB-3-external-account-recovery-bypass.md) → `inherited`

The threat is "compromise the external PyPI account's out-of-band recovery flow → publish."
That mechanism exists identically at the baseline (recover the maintainer's PyPI account →
publish), and the proxy structurally cannot and does not touch it — PUB-3's own body says
"the proxy cannot gate an external service's recovery flow" and credits the
account-narrowing containment to CORE-1. Its delta prose argues introduced because "the
funnel account and the quorum it bypasses are both proxy constructs" — the banned
surface-counting form. Apply the inherited cross-check: likelihood **low = low**, severity
**critical = critical** → cancels cleanly. Its operator mitigations (PyPI 2FA, group
recovery inbox) are baseline PyPI-account hygiene, the defining trait of the inherited
class. Contrast [PUB-2](PUB-2-proxy-bypass.md), which correctly stays introduced because
its likelihoods *differ* (baseline high vs residual medium) — that asymmetry is the
principled line between the siblings.

```yaml
delta: introduced  →  inherited
likelihood_baseline: N/A  →  low        # equal to residual (inherited invariant)
severity_baseline:  N/A  →  critical    # recover account → unilateral publish
bucket: 3  →  N/A
```

Overview edits: move PUB-3 out of the ③ list and the owned count (27 → 26 owned), add it to
the Inherited scope statement, update the residual-matrix note.

### 1.3 RECLASSIFY (recommended): [IDENT-3](IDENT-3-notification-channel-interception.md) → `inherited`

The threat is "a security secret is intercepted in email transit / from a compromised
mailbox." The baseline runs the identical mechanism to the identical standard — PyPI emails
password-reset links whose interception yields account takeover, over the same
TLS + SPF/DKIM/DMARC channel. Likelihood **medium = medium**; severity differs only because
the proxy contains the payload (enrollment link = one seat vs baseline reset link = full
account), which is permitted for inherited and credited once to CORE-1. Honest caveat: the
proxy's `fallback_to_portal` can take the secret off the channel entirely, a
proxy-specific mitigation the baseline lacks — a reviewer could defend keeping introduced
on that ground. The audit leans inherited: the *interception threat itself* is
standard-practice-equivalent on both sides.

```yaml
delta: introduced  →  inherited
likelihood_baseline: N/A  →  medium
severity_baseline:  N/A  →  critical    # intercept PyPI reset email → full account
bucket: 3  →  N/A
```

### 1.4 KEEP but fix the delta prose

- **[IDENT-5](IDENT-5-no-anti-automation-on-authentication-endpoints.md)** — classification
  correct, rationale wrong. The body says "direct `twine upload` to PyPI has no equivalent
  login surface" — false; PyPI has a login surface with 2FA. The correct (and
  CONTRIBUTING's own worked-example) reason it stays introduced: PyPI rate-limits its auth
  endpoints and the proxy does not — a deviation *below* standard practice. Rewrite the
  rating-rationale opening.
- **[IDENT-4](IDENT-4-phishable-approver-authentication.md)** — introduced is defensible
  *only* via the below-standard-practice argument (PyPI offers phishing-resistant WebAuthn;
  the proxy MVP offers none). If the baseline maintainer is assumed TOTP-only, phishing
  cancels high=high → inherited. State the dependency explicitly so the classification
  isn't silently assumption-fragile.

### 1.5 Verdict table (all 24 introduced)

| ID | Baseline equivalent? | Cancellation analysis | Verdict |
|---|---|---|---|
| [IDENT-1](IDENT-1-admin-account-compromise.md) | No | No baseline roster to manufacture quorum from | KEEP |
| [IDENT-2](IDENT-2-enrollment-link-interception.md) | Partial | Enrollment into the proxy's roster is proxy-specific | KEEP |
| [IDENT-3](IDENT-3-notification-channel-interception.md) | **Yes** | Same channel, same standard, likelihoods equal → cancels | **RECLASSIFY → inherited** |
| [IDENT-4](IDENT-4-phishable-approver-authentication.md) | Yes, but | No WebAuthn option = below standard practice → breaks cancellation | KEEP (make the dependency explicit) |
| [IDENT-5](IDENT-5-no-anti-automation-on-authentication-endpoints.md) | Yes | PyPI rate-limits, proxy doesn't = below standard practice | KEEP (fix rationale) |
| [VOTE-1](VOTE-1-proxy-session-hijacking.md) | Partial | Rated critical leg (admin-portal takeover) is proxy-only; re-auth is a novel design claim | KEEP |
| [VOTE-2](VOTE-2-captured-credential-replay.md) | Partial | Per-vote re-auth + TOTP burn has no baseline per-publish analog | KEEP |
| [VOTE-3](VOTE-3-browser-borne-approval-coercion.md) | No | The approval form exists only in the proxy world | KEEP |
| [VOTE-4](VOTE-4-approval-request-fatigue.md) | No | The fatigued approver population is proxy-only | KEEP |
| [HOST-1](HOST-1-proxy-host-compromise.md) | No | Concentrated intermediary holding others' live token is new (baseline token exposure = CORE-2) | KEEP |
| [HOST-2](HOST-2-database-write-compromise.md) | No | No baseline approval store to tamper | KEEP |
| [HOST-3](HOST-3-database-read-compromise.md) | No | Proxy-only store; plaintext TOTP-at-rest is additionally below standard practice | KEEP |
| [HOST-4](HOST-4-database-repudiation-attack.md) | No | No baseline approval history to suppress | KEEP |
| [CRYPTO-1](CRYPTO-1-cryptographic-implementation-failure.md) | No | No baseline analog to the proxy's own crypto subsystem | KEEP |
| [PUB-1](PUB-1-package-swap-between-upload-and-publication.md) | No | `twine upload` has no staging window | KEEP |
| [PUB-2](PUB-2-proxy-bypass.md) | Partial | Likelihoods differ (high vs medium) → fails to cancel | KEEP |
| [PUB-3](PUB-3-external-account-recovery-bypass.md) | **Yes** | Proxy-untouched mechanism, likelihoods equal → cancels | **RECLASSIFY → inherited** |
| [DOS-1](DOS-1-request-resource-flooding.md) | No | Authenticated request-creation + DB-staged bytes are proxy-only | KEEP |
| [DOS-2](DOS-2-destructive-availability-attack.md) | No | The destructible state exists only because the proxy does | KEEP |
| [DOS-3](DOS-3-compromised-approver-as-denial-of-service.md) | No | No baseline quorum to veto | KEEP |
| [DOS-4](DOS-4-approver-withholding.md) | No | No one's silence blocks a baseline publish | KEEP |
| [CODE-1](CODE-1-application-layer-vulnerability.md) | No | The proxy's web app is net-new attack surface | KEEP |
| [CODE-2](CODE-2-supply-chain-attack-on-the-proxy-itself.md) | Partial | The proxy's own dependency tree is additional TCB | KEEP |
| [INFO-1](INFO-1-information-disclosure-via-quorum-status-approver-visibility.md) | No | No baseline vote to observe | KEEP |

---

## 2. Missing threats

### 2.1 IDENT-6 — Declarative-Provisioning Rogue-Admin Injection *(strong; propose adding)*

[account-management.md](../account-management.md) §Declarative provisioning and
[config.md](../config.md) §`users.yaml` introduce a credential-bearing file the proxy
reconciles **create-if-absent on every boot** via `msig-provision`, able to mint admins
(`is_admin: true`) and, in Mode B, create a user born enrolled from an offline
`hash-credentials` bundle. Two unowned legs: **(a) write/poison** — an attacker with write
access to `/config` (host or compromised deploy pipeline) adds a Mode-B admin entry with
attacker-controlled credentials and holds a legitimate admin on next boot, forging nothing;
the additive-only reconcile makes it *durable* (delete the rogue user from the DB and the
next boot re-mints it). **(b) read/offline-crack** — the file's own documented trust
posture is "offline-guessable credential material" (bcrypt hash + password-wrapped key
together); a leaked copy (git commit, config backup, world-readable mount) is attackable
offline like `/etc/shadow`, which config.md explicitly analogizes.

- **stride:** [Tampering, Information Disclosure, Elevation of Privilege]
- **attack:** [T1552.001, T1136.001, T1110.002]
- **capability:** [L6, external] — L6 to touch `/config` on the host; external for the
  off-boundary bundle leak
- **delta:** introduced (the surface exists only because the proxy exists; no baseline
  equivalent to cancel against) · baselines N/A
- **likelihood_residual:** low · **severity_residual:** critical (a rogue admin enrolls
  *m* attacker approvers → publish-at-will, no independent barrier — parity with IDENT-1)
- **bucket:** 3 (restrict `/config`, git-ignore the real file, `$ENV{}` the `totp_secret`,
  strong Mode-B passwords — none compellable by the proxy)
- **related:** [IDENT-1, HOST-1, HOST-3, CODE-2] (reciprocals in the same change)

### 2.2 CORE-4 — Authorization Repudiation *(medium-firm; the missing improved threat)*

At the baseline there is no signed record of who authorized a publish — a maintainer (or
whoever used their credential) can plausibly deny responsibility. The proxy makes every
approval an Ed25519-signed, independently verifiable vote
(`tests/approvals/test_votes.py::test_vote_is_ed25519_signed_and_verifies_offline`), so an
approver cannot repudiate their authorization. The catalog currently represents Repudiation
only on its *introduced* side (HOST-4, trail deletion); the improved side is absent. It is
distinct from [CORE-3](CORE-3-insider-collusion.md), whose measured delta is
likelihood-on-collusion and which mentions signing only as deterrence.

- **stride:** [Repudiation] · **attack:** [] (no Enterprise technique maps to passive
  repudiation; `[]` + body note per the DOS-4/CRYPTO-1 precedent)
- **capability:** [L7] · **delta:** improved
- **likelihood:** baseline high → residual low · **severity:** baseline medium → residual
  low (baseline strictly worse on both axes — passes the improved gate)
- **bucket:** 2 (offline-verify is tested, but the guarantee carries HOST-2's
  key-substitution and HOST-4's record-deletion caveats — argued, not cleanly demonstrated
  end-to-end)
- **related:** [CORE-3, HOST-2, HOST-4] ·
  **tests:** tests/approvals/test_votes.py::test_vote_is_ed25519_signed_and_verifies_offline
- Ordering wrinkle: CONTRIBUTING says CORE-3 closes the group thesis→residual; append-only
  numbering makes this CORE-4 but it reads best before CORE-3. Decide narratively.

### 2.3 CRYPTO-3 — Transport & PKI Trust Failure *(solid; the missing inherited entry)*

A network attacker with a mis-issued certificate or hijacked DNS for the proxy's origin can
MITM approver traffic — the identical pre-existing threat that applies to `pypi.org` at the
baseline, on the same public PKI/DNS trust chain, to the same standard. Currently assumed
away across IDENT-3/IDENT-4/VOTE-2 ("TLS everywhere") but never given a first-class
"considered" entry — exactly the considered-vs-forgotten line inherited entries exist for.

- **stride:** [Spoofing, Information Disclosure] · **attack:** [T1557] (DNS/passive facets
  in prose) · **capability:** [L1]
- **delta:** inherited · **likelihood:** low = low · **severity:** baseline critical (MITM
  maintainer↔PyPI → token → publish) → residual high (MITM one approver → one vote;
  containment credited to CORE-1) · **bucket:** N/A
- **related:** [IDENT-3, IDENT-4, VOTE-2, CRYPTO-2]
- Caveat to state in the body: inherited **under the operator-checklist assumption** (valid
  cert + HSTS); `pypi.org` is HSTS-preloaded and CT-monitored, a fresh self-hosted origin
  is not, so an under-configured deployment edges below standard practice.

### 2.4 HOST-5 — Configured Service-Credential Exposure at Rest *(moderate; needs a delta call)*

[config.md](../config.md) and [deployment.md](../deployment.md) put the **real PyPI upload
token** (plus SMTP password and `server.secret_key`) in `config.yaml`/`.env` on disk. A
read short of full process RCE — committed `.env`, leaked config backup, world-readable
mount — hands over the live token: direct publish, whole quorum bypassed (PUB-2's
position). [taxonomies.md](taxonomies.md) explicitly names *T1552.001 Credentials in Files
= PyPI token*, yet no threat owns the at-rest-in-file exposure: HOST-1 covers the
in-*memory* read (L6 RCE), CORE-2 is the *proxy-issued* token, HOST-3 is the database.

- **stride:** [Information Disclosure, Elevation of Privilege] · **attack:** [T1552.001]
- **capability:** [L6, external] · **likelihood_residual:** low ·
  **severity_residual:** critical · **bucket:** 3 (`$ENV{}` substitution, secrets manager,
  git-ignore, encrypted backups, file ACLs)
- **related:** [HOST-1, PUB-2, CORE-2, CODE-2]
- **Open decision:** the token-at-rest leg *partially cancels* against the baseline
  maintainer's own token storage (CI secret, keyring), so the delta is arguable
  (introduced-leaning vs inherited leg); alternatively fold the content into HOST-1 +
  PUB-2 as extensions. The audit leans standalone-introduced because the
  token-in-files surface is explicitly anticipated by the taxonomy shortlist and currently
  homeless — but this one deserves a human call.

### 2.5 Optional: Upstream Registry Failure (availability/compromise, inherited)

`pypi.org` unavailable or compromised affects both worlds identically; already acknowledged
in [DOS-2](DOS-2-destructive-availability-attack.md)'s prose ("PyPI's availability problem
in both worlds"). A slim entry (stride [Denial of Service], attack [], capability external,
inherited, low×low, bucket N/A, related [DOS-2]) buys only considered-not-forgotten
bookkeeping. Add only if every net-cancels item should be first-class.

### 2.6 Extensions to existing threats (legs to graft, not new threats)

- **[HOST-3](HOST-3-database-read-compromise.md)** — add the **off-host-copy leg**: the
  plaintext `totp_secret`, wrapped keys, and hashes leak via any backup, replica, or dev
  snapshot outside the DB's ACLs, not just a live L4 read. The operator checklist already
  mandates offsite copies; the body should name backups as a second read surface.
- **[DOS-1](DOS-1-request-resource-flooding.md)** — add the **single-worker
  connection-starvation leg**: [ADR 0013](../adr/0013-container-deployment-and-runtime-model.md)
  makes the one Uvicorn worker load-bearing, and the link-scoped SSE endpoints
  (`/approve/{id}/stream`, `/pending/{id}/stream`) can be held open or slow-read to exhaust
  its concurrency — distinct from DOS-1's noise/storage legs and IDENT-5's bcrypt-CPU leg.
- **[CORE-1](CORE-1-single-approver-account-compromise.md)** — name the honest-but-rogue
  *lone insider* as an instance of the contained class (the one-identity-one-vote mechanism
  already covers it; the framing currently reads as external compromise only).
- **Minor:** admin `account.*` events are recorded but, unlike Votes, not Ed25519-signed
  and are deletable — worth one body line in [HOST-4](HOST-4-database-repudiation-attack.md)
  or [IDENT-1](IDENT-1-admin-account-compromise.md) noting the unsigned-log repudiation
  surface on the admin path.
- **Minor:** `tests/approvals/test_votes.py::test_cast_vote_takes_a_row_lock_on_the_request`
  (quorum-race/TOCTOU serialization) backs no cataloged threat — a concurrent-vote
  double-count race is not enumerated. At minimum cite it from CORE-1's containment story.

### 2.7 Rejected candidates (considered, dropped — with reasons)

| Candidate | Reason rejected |
|---|---|
| Password brute-force / credential stuffing (inherited) | It's IDENT-5's surface, correctly *introduced* (below PyPI's rate-limiting standard) |
| Email account compromise of the human | A precondition, not a surface — tagged in IDENT-2 (T1586.002); at baseline it's the PUB-3 recovery route |
| Phishing the PyPI account behind the proxy | Manifests as PUB-2/PUB-3; unchanged by the proxy → the PUB-3 inherited story |
| bcrypt/TOTP parity (inherited) | bcrypt parity **is** CRYPTO-2; TOTP-at-rest is HOST-3's introduced below-standard gap, not parity |
| Compromised CI holding the token (improved) | That is CORE-2's scenario (token → request, not publish) |
| Token over-scoping (improved) | A facet of CORE-2's blast-radius story |
| Accidental/mistaken publish (improved) | No adversary — value-prop narrative, not a threat entry |
| SMTP notification suppression (DoS) | Fails safe; best-effort channel with specified portal fallback; generic network DoS |
| Host clock / NTP manipulation | Compound precondition; amplifies VOTE-2/IDENT-2 rather than opening a surface |
| Sensitive data in application logs | No spec states the proxy logs secrets — grounding it would be speculation |
| Upload-artifact parser / decompression bomb | MVP does no pre-upload parsing (raw bytes + SHA-256); parser bugs are CODE-1 |
| `secret_key` leak → session forgery | Defended by design: cookie HMAC protects a random id that must resolve to a server-side session row |
| Double-publish via redelivered handoff | Idempotent by uniqueness constraint + PyPI version immutability |

### 2.8 Element × STRIDE coverage (condensed)

Coverage is dense across the auth surface, the vote, the DB rungs, crypto, and the publish
boundary. The gap column is the config surface:

| Element | Uncovered cells |
|---|---|
| Upload edge, approve page, login/session, admin portal | none (owned by CORE/IDENT/VOTE/INFO entries) |
| Proxy → SMTP → inbox | none (IDENT-2/3/4) |
| Executor → PyPI | **at-rest token in config files** (→ HOST-5) |
| Database / artifact holding | none (HOST-2/3/4, PUB-1, DOS-2) |
| Config + secrets at boot | **I/E gaps** (→ HOST-5) |
| Declarative provisioning (`users.yaml`, `msig-provision`) | **S/T/I/E all gaps** (→ IDENT-6) |
| Backups | partial → HOST-3 extension |
| Enrollment / deactivation lifecycles | none (IDENT-2, DOS-3, by-design re-checks) |

---

## 3. Test backing

### 3.1 Bucket-① verdicts — all five claims hold

Every ① threat has ≥1 STRONG adversarial test (drives the attack, asserts it fails); none
rests solely on supporting tests. [CORE-2](CORE-2-api-token-theft.md),
[VOTE-2](VOTE-2-captured-credential-replay.md),
[VOTE-3](VOTE-3-browser-borne-approval-coercion.md), and
[PUB-1](PUB-1-package-swap-between-upload-and-publication.md) each have a genuine HTTP-edge
adversarial test; PUB-1 and CORE-2 are textbook black-box (`mock_pypi` never invoked at the
HTTP edge).

Two precision caveats:

- **[CORE-1](CORE-1-single-approver-account-compromise.md) — tier label overstated.** The
  overview claims all five ① threats sit in the black-box tier, but two of CORE-1's three
  cited tests run below the HTTP boundary (`votes.cast_vote`) and **none asserts the
  PyPI-mock oracle** (`mock_pypi` is not autouse; `test_two_approvals_over_http_reach_quorum`
  never requests it). The literal black-box demonstration of the quorum claim —
  `test_a_denied_request_never_reaches_pypi` — is cited by CORE-2 and PUB-1 but not CORE-1.
  Fix: add it to CORE-1's `tests:` (cheapest way to make the tier label true), or soften
  the overview's "all five" sentence.
- **VOTE-3 is the thinnest ①** — a single test, which drives bad credentials rather than a
  literal cross-site CSRF POST. It holds (the mechanism it demonstrates is the defense),
  but it is one test deep.

### 3.2 Findings (ranked)

1. **MISCITED + latent code gap —
   [IDENT-2](IDENT-2-enrollment-link-interception.md):27** claims "*the admin reissuing a
   link invalidates the old one*" citing
   `tests/accounts/test_admin_portal.py::test_regenerate_link_lets_a_pending_user_enroll` —
   but the test never creates a first link and asserts it dead, and the source confirms the
   claim is **false**: `mint_enrollment_link`
   ([enrollment_links.py](../../src/msig_proxy/accounts/enrollment_links.py)) only inserts
   a fresh token; `_valid_token` accepts any unconsumed, unexpired token, so multiple
   regenerated links stay simultaneously valid. Fix: soften the prose to what is true
   ("regeneration issues a fresh working link"), **and decide whether invalidation is
   intended — if so, file an issue** and add an old-link-after-regen → 400 test with it.
2. **VOTE-1's headline claim is unbacked in `tests:`** — "the cookie cannot be forged or
   tampered without the key" has an exact, existing STRONG test that is uncited:
   `tests/auth/test_sessions.py::test_a_tampered_or_wrongly_keyed_cookie_does_not_verify`
   (tampered signature, wrong key, malformed cookie all fail). Add it (optionally also
   `test_deleting_the_record_revokes_resolution`,
   `test_an_expired_session_is_invalid_and_cleaned_up`).
3. **[HOST-2](HOST-2-database-write-compromise.md)** — "public keys retained permanently →
   historical verifiability" is directly driven by
   `tests/approvals/test_votes.py::test_a_reenrolled_users_old_votes_still_verify` (and
   `test_admin_portal.py::test_delete_drops_private_key_but_keeps_public_key`); neither is
   cited. Add.
4. **[CRYPTO-1](CRYPTO-1-cryptographic-implementation-failure.md)** — the AEAD-gated
   signing invariant has an uncited STRONG test:
   `tests/core/test_crypto.py::test_sign_with_password_fails_with_wrong_password`. Add.
5. **[DOS-3](DOS-3-compromised-approver-as-denial-of-service.md)** — the core single-deny
   veto has a dedicated uncited test:
   `tests/approvals/test_votes.py::test_a_single_deny_closes_the_request_immediately`. Add.
6. **[CODE-1](CODE-1-application-layer-vulnerability.md):28** — prose cites behaviors with
   a wrong status code ("waiting room not-your-request → 403" — the guard returns **404**,
   per `test_user_portal.py::test_cannot_cancel_another_users_request`) and alludes to
   IDOR/admin-guard tests without node ids (also flagged by the consistency pass, §4 nit).
   Fix the code, cite the tests.
7. **Optional** — [IDENT-2](IDENT-2-enrollment-link-interception.md):
   `test_enrollment.py::test_password_below_minimum_length_is_rejected_and_link_survives`
   backs a retry-safe single-use property the body could claim.

### 3.3 Uncited adversarial tests (reverse sweep)

Plausible homes for security tests no threat cites (the contract says every body-cited test
belongs in `tests:`; these are body-claim-relevant candidates):

| Test | Plausible home |
|---|---|
| `test_sessions.py::test_a_tampered_or_wrongly_keyed_cookie_does_not_verify` | VOTE-1 (finding 2) |
| `test_votes.py::test_a_reenrolled_users_old_votes_still_verify` | HOST-2 (finding 3); also CORE-3 non-repudiation |
| `test_crypto.py::test_sign_with_password_fails_with_wrong_password` | CRYPTO-1 (finding 4) |
| `test_votes.py::test_a_single_deny_closes_the_request_immediately` | DOS-3 (finding 5) |
| `test_votes.py::test_wrong_password_is_rejected_and_records_nothing` + bad-TOTP + unknown-user | CORE-1 / VOTE-2 auth gate |
| `test_login.py::test_invalid_password_returns_401_and_creates_no_session` + 2 siblings | VOTE-1 / IDENT-4 |
| `test_upload.py::test_rejects_a_bad_token` / missing-token / wrong-username | CORE-2 / PUB-2 |
| `test_user_portal.py::test_cannot_cancel_another_users_request`, `::test_cannot_revoke_another_users_token` | CODE-1 |
| `test_admin_portal.py::test_admin_portal_requires_admin` + admin-guard siblings | IDENT-1 |
| `test_votes.py::test_cast_vote_takes_a_row_lock_on_the_request` | **no cataloged threat** (see §2.6) |
| `test_gate.py` forward-auth denials | out of evaluation scope — expected, not a gap |

---

## 4. Consistency & wording

### 4.1 Defects

1. **[CORE-1](CORE-1-single-approver-account-compromise.md):28 — Current defenses cites an
   unbuilt demo.** "plus the Act 2 demo (#114) as the black-box showcase" — #114 is open;
   the demo doesn't exist. The exact "audit, not an aspiration" violation. Drop the clause
   or move to Planned defenses ("no bucket change" — the ① claim rests on the tests).
2. **[CRYPTO-2](CRYPTO-2-cryptographic-side-channel-leakage.md):25–26 — gains row claims
   throttling that doesn't exist.** "a query volume that authentication throttling denies"
   contradicts IDENT-5:24 ("no actual rate limiting or lockout") and CRYPTO-2's own cannot
   row ("once #123's rate limit lands"). Today the attacker *can* sustain the oracle.
   Reword the gains row; move the "cannot sustain" claim out of the cannot row (it's future
   work, not containment by design).
3. **[CODE-2](CODE-2-supply-chain-attack-on-the-proxy-itself.md):24 — stale count.** "549
   `sha256` hashes" in `uv.lock`; the file currently has 676. Replace the exact number with
   "pins the full transitive tree with per-artifact `sha256` hashes."
4. **[CRYPTO-2](CRYPTO-2-cryptographic-side-channel-leakage.md):21–27 — missing "Operator
   configuration" row** (contract requires six rows; the overview's Summary Table even
   carries its operator action). Add the row, or amend CONTRIBUTING if inherited entries
   are meant to be exempt.

### 4.2 Inconsistencies

5. **[INFO-1](INFO-1-information-disclosure-via-quorum-status-approver-visibility.md):30** —
   "Planned defenses" appears as an anatomy-table *row* saying "None required", violating
   both the six-row layout and the omit-when-empty rule. Delete the row.
6. **[CORE-2](CORE-2-api-token-theft.md):25** — Category row omits Spoofing (frontmatter
   has it). Restate both tags.
7. **Missing/unjustified `related:` pairs** — PUB-2 ↔ PUB-3 missing (PUB-2's capability row
   literally names PUB-3's surface); VOTE-4 ↔ CORE-3 missing (VOTE-4:52 explicitly rates
   its critical tail "there" — the absorbs-the-residual criterion verbatim); PUB-3 ↔ HOST-1
   is linked but never explained in either body. Add the two pairs both directions; state
   or drop the third. *(Note: if PUB-3 reclassifies per §1.2, add PUB-3 ↔ CORE-1 for the
   containment credit while in there.)*
8. **Stale retired-process references in six files** — HOST-4:16, DOS-2:16, CODE-1:18 carry
   `<!-- Provisional ID (X6): … Phase D renumbering -->` comments for a renumbering that
   already happened (CODE-1's is doubly wrong — it isn't in the stated range); PUB-3:31
   defers a file rename that already happened; HOST-2:39 and IDENT-4:27 cite "the strawman"
   — a retired artifact a reader cannot follow. Delete the comments/sentence; reword the
   strawman mentions ("demoted from an earlier ① rating during the #107 deep-dive").
9. **[taxonomies.md](taxonomies.md):101 contradicts the catalog** — "Both are listed; T1621
   is the primary… T1111 is the primary tag" vs T1621 tagged nowhere and VOTE-4 recording
   it as a considered *non-mapping*. Amend to "T1111 is tagged (VOTE-2); T1621 is a
   considered non-mapping recorded in VOTE-4."
10. **[CONTRIBUTING.md](CONTRIBUTING.md):278 — stale non-commitment example** — "e.g.
    WebAuthn" is now planned work (#129, IDENT-4 Planned defenses). Swap for a still-true
    example (CODE-2's release signing / reproducible builds).
11. **[00-overview.md](00-overview.md):268–269 — matrix narrative miscount** — "three of
    the four are ② argued or ③ operator-enforced": all four are (three ②, one ③).
12. **[00-overview.md](00-overview.md) — forward-auth unmarked as future vision**, contra
    the scope rule (CONTRIBUTING:13–16): §System Summary presents "Two post-approval
    patterns exist … Forward-auth", and the Operator Checklist carries unmarked
    forward-auth items (bind backends privately, test direct-access blocking). Mark as
    future vision (#109) or cut.
13. **Body structure splits into two styles** — 13 files use `## Rating rationale`/`##
    Bucket` sections; 15 use bold-paragraph lead-ins (`**Delta.** … **Why bucket ③.**`),
    which are invisible to the tool's `sections` query that CONTRIBUTING promotes as the
    reading interface. Converge on the `##` style.
14. **[00-overview.md](00-overview.md):9–11** — frontmatter enumeration omits `tests` (line
    71 calls it "the test-to-threat map"). Add it.
15. **Extra anatomy-table rows in three files** — IDENT-1:29, HOST-2:27, HOST-3:27 add
    rows beyond the contract's fixed six. Content is good; move to prose or amend
    CONTRIBUTING to bless optional extra rows.

### 4.3 Nits

16. [IDENT-5](IDENT-5-no-anti-automation-on-authentication-endpoints.md):24 — "closed by
    #123" reads as done; #123 is open → "tracked in #123".
17. [IDENT-3](IDENT-3-notification-channel-interception.md):36–38 — "#20 appears above" →
    it first appears *below*.
18. Operator Checklist claims operator work the code already does — cookie flags
    (00-overview:361–363) are set by the proxy (VOTE-1:27); `fallback_to_portal: true` is
    the default (IDENT-2:28). Reword "set/enable" → "verify/keep".
19. [CORE-2](CORE-2-api-token-theft.md) — ① tier label missing ("black-box" stated by the
    other four ① threats; the overview's "all five" rests on it), and its tests are cited
    in `## Bucket` rather than the Current defenses row.
20. [CODE-1](CODE-1-application-layer-vulnerability.md):28 — uncited test allusions + wrong
    status code (merged with §3.2 finding 6).
21. Terminology drift — domain-term capitalization mixed across files
    (Approver/Requester/Vote vs lowercase; IDENT-1 mixes both); overview drops some title
    parentheticals and keeps others; issue-reference style mixed (bare `#123` vs full URL
    links); Category-row separator mixed (HOST-2/3 semicolons vs commas elsewhere).
22. Capability-ladder wobbles — CORE-1:25 calls a password+TOTP pair "L2" (ladder says
    that's L3; the L2 membership is actually justified via IDENT-5's brute-force, which the
    row conflates); the overview's L2 wording ("stolen one approver's password") is
    narrower than actual L2 usage (requester tokens, out-of-band credentials, recovery
    inboxes) — CONTRIBUTING's "single commodity credential" is the accurate phrasing;
    IDENT-1 rates admin compromise by acquisition cost (L3) while DOS-2 tags its lockout
    leg by position held (L8) — both defensible, worth one clarifying sentence.
23. [taxonomies.md](taxonomies.md):5 — "every `T*.md` file" predates the renumber; files
    are `<PREFIX>-<n>-<slug>.md`.

### 4.4 Cross-doc recomputation — clean

Every derivable cell in [00-overview.md](00-overview.md) was recomputed from the 28 files'
frontmatter and matches exactly: bucket distribution (①5 ②8 ③9 ④5 + 1 N/A), STRIDE×bucket
(all 6 rows), capability×bucket (all 10 rows), Residual Risk Matrix (all 12 cells),
improved-threats table, all 28 Summary Table rows, prefix/ID-range tables, and per-group
most-severe-first ordering. The only overview drift is textual (findings 11, 12, 14, 18).

---

## 5. Verified clean (audit coverage)

- `msig-threats validate`: no violations (28 threats).
- All five ① claims genuinely backed; no prose→frontmatter omissions in `tests:` (every
  node id named in any body is in that threat's frontmatter); every cited test describes
  real behavior for CORE-2, VOTE-2, PUB-1, CRYPTO-1, HOST-1, HOST-3, IDENT-1, IDENT-3,
  INFO-1, DOS-1, DOS-4.
- HOST-2 and IDENT-1 correctly sit at ② — the catalog is honest that the key-substitution
  and quiet-enroll forgeries fire no oracle.
- `attack: []` notes present and argued in all three cases; weak-fit caveats present for
  every soft tag; all 23 Planned-defenses issues verified open; L2 threats name their
  credential; CODE-2 justifies its external likelihood; every rated pair is supported by
  its body argument on the correct severity-ladder rung; per-leg bucket handling follows
  the sanctioned pattern everywhere it appears; H1/title/slug agreement in all 28 files; no
  dangling threat-ID references; all referenced repo artifacts exist.
- 22 of 24 introduced classifications survive re-derivation under net-cancellation.

## 6. Suggested order of work

1. **File the IDENT-2 regeneration question as an issue** (§3.2.1) — the only finding
   where doc and code disagree about intended behavior; everything else is documentation.
2. **Delta batch** (§1): reclassify PUB-3 (firm) and IDENT-3 (recommended); rewrite the
   IDENT-5/IDENT-4 delta prose; sweep the remaining surface-novelty delta stories to argue
   failure-to-cancel instead. Update the overview's delta cut and inherited scope
   statement.
3. **New-threat batch** (§2): add IDENT-6 and CORE-4; add CRYPTO-3; decide HOST-5
   (standalone vs fold-in); optionally the upstream-registry slim entry. Overview tables +
   `related:` reciprocals + `validate` per the adding-a-threat recipe.
4. **Tests batch** (§3): add the six missing citations; fix CORE-1's tier (add the
   denied-request test or soften the overview claim); label CORE-2's tier; graft the
   HOST-3/DOS-1/CORE-1 extension legs.
5. **Editorial batch** (§4): the four defects, then inconsistencies 5–15, then nits —
   mostly mechanical; converging the body-section style (finding 13) is the only one with
   real breadth.
