<!--
TEMPORARY WORKING DOC — progress tracker + prep worksheet for the threat-model deep-dive
(issues #107 + #111). Delete or archive this file when the deep-dive closes. It is not part of
the published catalog.
-->

# Threat Model Deep-Dive — Review Plan & Progress Tracker

Working tracker for the threat-model hardening pass. It owns the *process* and the *prep*; the
catalog itself (the `T*.md` files, `00-overview.md`, `taxonomies.md`) is the product.

- **Issues:** [#107](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/107) (harden + classify — the spine) and [#111](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/111) (map executable threats to tests — folded into Phase D; blocked-by #107).
- **Branch:** `107-threat-model-hardening` (off `progress-report-4`).
- **Started:** 2026-07-01.

---

## Ground rules

1. **Nothing is set in stone.** The whole threat model can be torn down and rebuilt. **Prefer making it look final over preserving what we had** — renumber, merge, split, rewrite, or drop threats freely if it makes the finished catalog cleaner. The only hard constraint is that every threat ID referenced elsewhere in the repo must resolve after the dust settles (see Phase D).
2. **Taxonomies in scope:** **STRIDE** (violated-property lens — already applied per-threat) + **MITRE ATT&CK Enterprise** (operational adversary-behavior lens — the completeness driver *and* the mapping target). CAPEC and OWASP ASVS are **deferred, not rejected**; the frontmatter tags are lists, so adding another axis later is non-destructive. Full reference: [taxonomies.md](taxonomies.md).
3. **Source of truth.** `docs/evaluation-plan.md` defines the `delta` and four-bucket *method*; this deep-dive owns the finished per-threat values. Do not re-litigate the method here.

---

## Frontmatter contract (target field order)

```yaml
id: T1
title: "..."
stride: [...]          # taxonomy labels (adjacent)
attack: [...]          # MITRE ATT&CK Enterprise technique IDs
capability: [...]      # adversary model (L1–L9)
delta: improved|inherited|introduced   # evaluation axes (adjacent);
bucket: 1|2|3|4|N/A                     # delta GATES bucket (inherited ⇒ N/A)
related: [...]
```

`delta` precedes `bucket` because an **inherited** delta forces `bucket: N/A`. `attack` is
appended after `stride` so the two external-taxonomy tags sit together.

---

## Classification axes (condensed from `evaluation-plan.md`)

**`delta` — relationship to the direct-publish baseline** (publish to PyPI with API token + account 2FA, no proxy):

- **improved** — pre-existing threat the proxy measurably *reduces*. Feeds the §1 value proposition.
- **inherited** — pre-existing *authentication-layer* threat the proxy leaves unchanged. Out of scope by design → `bucket: N/A`, reported once as a scope statement, never counted as a proxy weakness.
- **introduced** — attack surface that exists *only because the proxy exists*. The net-delta cost (§3).

**`bucket` — four-bucket mitigation classification** (only for **owned** = improved + introduced threats):

1. **Executably demonstrated** — an automated adversarial test drives the attack and asserts it fails. Two tiers: *black-box* (driven at the HTTP edge; oracle = PyPI mock never invoked) and *integrity/detection* (asserted at crypto/DB layer; oracle = `Ed25519Verify` fails).
2. **Argued by design** — reasoned mitigation, not script-drivable (crypto invariants, accepted info-leaks).
3. **Operator-enforced** — the system cannot defend it; it is config/topology.
4. **Accepted limitation** — documented, deliberate out-of-scope failure.

---

## Phases

### Phase 0 — Setup

- [x] Cut branch `107-threat-model-hardening` off `progress-report-4`.
- [x] Frontmatter placeholder pass: `attack: TODO` + `delta: TODO` added to all 27 files in contract order (verified 27/27).
- [x] Scaffold this tracker (`REVIEW-PLAN.md`).
- [x] Scaffold + fill `taxonomies.md` (reference doc).
- [ ] Setup commit + Phase A commit.

### Phase A — Taxonomy grounding (front-loaded, non-interactive)

- [x] `taxonomies.md`: STRIDE / ATT&CK explained, why we use each, sources, in-scope ATT&CK tactic→technique shortlist with discards.
- [x] `references.bib` entries: `attack-design-philosophy`, `stride-shostack` (generic `mitre-attack` already present). Broader citation coordination with #119 deferred.
- [x] Phase B coverage map + gap candidates drafted (below).
- [x] Phase C provisional classification strawman drafted (below).
- [ ] Phase A commit.

### Phase B — Completeness mapping ***(GRILL — interactive, `/grill-with-docs`)***

Walk ATT&CK Enterprise tactic-by-tactic at medium depth using the coverage map below. For each relevant technique: covered by an existing threat (or group)? If not, draft a **high-level** threat to fill the gap. Discard tactics/techniques with no connection. **Output:** a settled, complete threat list. Enters with the strawman below as the target to attack. Commit **per ATT&CK tactic**.

### Phase C — Per-threat deep pass (interactive-ish, one threat at a time)

For each threat, validate + finalize: category, capability, what-attacker-gains, what-they-cannot-do, **Current defenses (honest audit vs. the current spec — true or aspirational?)**, planned defenses, operator config, body prose. Then assign `stride` + `attack` tags, `delta`, and `bucket` (or `N/A`). Resolve the reclassifications #107 names (see strawman flags). Commit in **tight batches** of related threats.

### Phase D — Metadata, repo-wide sweep, and #111

- [ ] Regenerate `00-overview.md`: delta cut, four-bucket distribution over **owned** threats, Inherited listed separately as the scope statement, refreshed navigator tables.
- [ ] **Repo-wide reference sweep** — update EVERY threat-ID reference across docs + code to its new identity. Inventory below.
- [ ] **#111 mapping table:** each bucket-① owned threat → named test + explicit pass/fail oracle; four-bucket distribution over owned threats only; note gaps. Curation over the existing suite. Flagship T1 references the Act 2 demo (#114).
- [ ] Verify no stale references remain; delete/archive this tracker.
- [ ] Open PR against `progress-report-4`; manually close #107 and #111.

---

## Phase B prep — ATT&CK coverage map & gap candidates

Medium-depth pass of the [taxonomies.md](taxonomies.md) in-scope shortlist against the current 27
threats. "Covered by" is provisional (from the overview summary table, not yet the threat bodies).

| Tactic | Load-bearing in-scope techniques | Covered by | Gap? |
| --- | --- | --- | --- |
| Reconnaissance | T1595 Active Scanning; T1589 Gather Identity | T22, T27 (indirect) | no — recon is pre-attack, not a distinct proxy threat |
| Resource Development | T1586.002 Compromise Email; T1585 Establish Accounts | T9, T10, T16, T13 | no |
| Initial Access | **T1078 Valid Accounts**; T1190 Exploit Public-Facing App; T1566.002 Spearphishing Link; T1199 Trusted Relationship | T1, T13, T26 / T10 / T14 | **GAP #1 — T1190** app-level vuln (injection/SSRF/authz-bypass) has no dedicated threat |
| Execution | T1059.006 Python; T1053.003 cron | T4 | no |
| Persistence | T1556 Modify Auth (.006/.009); T1136.001 Create Account; T1098 Account Manip | T6, T13 | **GAP #2 — quorum-policy tampering** (lower `m` / disable MFA via config/DB): fold into T6 or split? |
| Privilege Escalation | T1548; T1068; T1098; T1055 | T4, T13, T18 | no |
| Defense Evasion | **T1562 Impair Defenses**; **T1070 Indicator Removal**; T1036; T1550.004 | T6 (tamper-evident), T4, T10, T8 | **GAP #3 — audit-log suppression** (disable logging, vs. tamper): implicit in T4/T6, name it? |
| Credential Access | **T1110 Brute Force**; **T1552 Unsecured Creds** (.001 token/.004 keys); T1003 Dumping; **T1111 MFA Interception**; **T1528 Steal App Token**; T1539/T1606.001 cookies | T25, T5/T7/T26, T4, T8/T10, T15 | **GAP #5 — real-time MFA relay/AITM** (T1111): covered by T8+T10 but not named as AITM |
| Discovery | T1087.001 Local Accounts; T1083/T1082; T1046 | T22, T4, T14 | no |
| Lateral Movement | T1550.004 Web Session Cookie; T1210 | T14, T15 | no (single host) |
| Collection | T1005; T1114 Email; T1213; T1557 AITM | T4/T5, T16, T10 | no |
| Command & Control | T1071.001; T1105; T1573 | T4 (post-compromise) | no — C2 is post-compromise, not distinct surface |
| Exfiltration | T1041; T1567.002; T1048 | T4/T5 | no |
| Impact | **T1565.001 Stored Data Manip**; **T1657 Financial Theft**; T1485 Destruction; T1499/T1498 DoS; T1531 Account Removal | T6/T11/T13, T1, T27/T25, T2 | **GAP #4 — data destruction / approver lockout** (T1485/T1531): partly operator-covered, name as DoS variant? |

**Gap candidates — investigated against the specs (verdicts for the grill):**

Ranked; each carries a verdict + the evidence found. New-threat numbering (T28+) is illustrative — tear-down freedom applies, so the grill decides new-threat-vs-fold and the final IDs.

1. **App-level vulnerability in the proxy's own code** (T1190) — **REAL GAP.** No threat covers injection / SSRF / broken-object-authz / auth-bypass bugs in the FastAPI code itself: **T4 *assumes* code-exec already**, T17 is crypto-only, T18 is dependencies-only. → New high-level threat, or widen T4 to cover both host compromise and app-layer bugs.
2. **Quorum-policy tampering** (T1556.009) — **REAL GAP.** T6 covers record/`is_admin` writes and T13 covers admin compromise, but neither names tampering with the *stored quorum threshold* or MFA-enforcement policy governing **future** requests. Nuance: quorum is **snapshotted at request creation**, so in-flight requests are immune — the exposure is the stored config for new requests. → New threat (audited/append-only policy changes + MFA-enforcement integrity), or an explicit T6 extension.
3. **Audit-log suppression** (T1562/T1070) — **PARTIAL / design-mitigated, not named.** `cryptography.md` §Audit Trail Integrity states per-record Ed25519 signatures detect *modification* but **not deletion or reordering** (no hash chain); deletion is mitigated only by the operator INSERT-only ACL + planned external append-only log. → Name it (new threat or a T6 sub-case) pointing at the append-only-log defense.
4. **Data destruction / approver lockout** (T1485/T1531) — **REAL GAP.** T2/T3 are individual-approver DoS and T27 is request flooding; none covers wiping the DB/audit state or systematically locking out *all* honest approvers (quorum exhaustion). → New availability threat covering data destruction + quorum exhaustion.
5. **Real-time MFA relay / AITM** (T1111) — **PARTIAL / implicitly prevented, not named.** T8 single-use burn + T10 + T15 layer to stop it (a fresh code is burned on first use), but no threat names the AITM-relay pattern. → Expand T8 to cover AITM relay as a variant, or a new cross-referenced threat.

**Net:** 2 clear new threats (Gaps 1, 4), 1 strong candidate (Gap 2), 2 name-or-fold decisions (Gaps 3, 5).

---

## Phase C prep — provisional classification strawman *(for grilling — NOT final)*

Seeded from `evaluation-plan.md` §"Provisional first-pass classification" + the coverage map above.
`⚑` marks a call to settle in the grill/deep-pass.

| ID | Prov. `delta` | Prov. `bucket` | Rationale / flag |
| --- | --- | --- | --- |
| T1 | improved | 1 | Baseline publishes on one stolen cred; quorum stops it. Flagship, Act 2 demo. |
| T2 | introduced | 4 | Deny-DoS exists only because the proxy has approvers; admin deactivation only. |
| T3 | introduced | 4 | Approver withholding / liveness; no timeout. Accepted. |
| T4 | introduced | 4 | Proxy host is new surface; creds in memory. Accepted. |
| T5 | introduced | 3 | Proxy DB is new surface; restrict DB access (operator); keys encrypted. |
| T6 | introduced | 1 | DB-write tamper; Ed25519 tamper-evident (integrity tier). May absorb GAP #2/#3. ⚑ |
| T7 | introduced | 4 | Proxy TOTP store plaintext; planned encryption. ⚑ introduced vs inherited? |
| T8 | introduced | 1 | Approval-link replay; signed votes + single-use TOTP + terminal freeze (black-box). |
| T9 | introduced | 3 | Enrollment-link interception; secure distribution (operator). |
| T10 | introduced | 2 | Approval-link phishing; auth required + domain verification. ⚑ ② vs inherited(phishing). |
| T11 | introduced | 1 | Payload substitution in upload→publish window; hash binding (black-box). |
| T12 | **split** | inherited N/A + introduced 3 | Individual MFA-bombing = inherited; approval-request fatigue = introduced (training/cooldown). ⚑ |
| T13 | introduced | 1 | Admin forgery detectable via Ed25519 (integrity) + operator (minimal admins). |
| T14 | introduced | 3 | Network path bypass; firewall/topology (operator). |
| T15 | introduced | 2 | Session hijacking; signed revocable cookie + re-auth-gated voting (argued). |
| T16 | introduced | 3 | SMTP channel; TLS/DMARC (operator). |
| T17 | introduced | 2 | Crypto implementation; argued by design + candidate ① invariant tests. |
| T18 | introduced | 3 | Supply chain on proxy deps; pinning/scanning (operator). ⚑ ③ vs ④. |
| T19 | introduced | 4 | Colluding quorum; accepted by design. ⚑ delta: introduced vs accepted-limit-of-improved. |
| T20 | introduced | 2 | AES-GCM nonce exhaustion; argued safe for MVP patterns. |
| T21 | introduced | 1 | CSRF; candidate CSRF test (black-box). |
| T22 | introduced | 2 | Quorum-status/endorser leak; argued (link-scoped, opt-in only). ⚑ ② vs ④. |
| T23 | inherited | N/A | bcrypt timing is auth-layer; library constant-time. ⚑ inherited vs introduced ②. |
| T24 | inherited | N/A | Shared-account password reset = account-recovery/auth-layer (#107 reclass). |
| T25 | **split** | inherited N/A + introduced 1 | Online TOTP brute = inherited; CPU-DoS/anti-automation = introduced (① once limiter, ③ today). Key reclass. |
| T26 | introduced | 2 | API token theft; hashed at rest, quorum/hash-bound, revocation. ⚑ introduced vs improved. |
| T27 | introduced | 1 | Request/resource flooding; ① for introduced portion once rate limiter lands, ③ today. |

**Distribution shape (provisional, owned threats only):** ① ≈ T1,T6,T8,T11,T13,T21,T25*,T27* · ② ≈ T10,T15,T17,T20,T22,T26 · ③ ≈ T5,T9,T14,T16,T18 · ④ ≈ T2,T3,T4,T7,T19. **Inherited (N/A):** T23,T24 + inherited portions of T12,T25. Plus any new threats from the gap candidates.

---

## Phase D reference inventory (candidates, from grep `\bT(1[0-9]|2[0-7]|[1-9])\b`)

Docs that reference threat IDs and must be re-checked after any renumber/restructure:

- `docs/web-proxy.md`, `docs/mvp-prd.md`, `docs/config.md`, `docs/evaluation-plan.md`
- `docs/notification-system.md`, `docs/request-lifecycle.md`, `docs/cryptography.md`
- `docs/architecture.md`, `docs/account-management.md`, `docs/approver-authentication.md`
- `docs/adr/0009-append-only-vote-model.md`
- `Practicum Work/Final Report/outline.md`
- `.scratch/security/0001-in-proxy-rate-limiting.md`
- threat-model dir self-references: `00-overview.md` + each `T*.md` `related:` (expected)

Code references (grep hits — **all confirmed real**, cited as `00-overview.md T<n>` in comments).
**T7, T8, T22 are load-bearing in code** — renumbering any of them requires touching these files:

- `src/msig_proxy/approvals/approve.py` — **T22** ×3
- `src/msig_proxy/core/models.py` — **T7**, **T8**
- `src/msig_proxy/accounts/hash_credentials.py` — **T7**
- `migrations/versions/0011_consumed_totp.py` — **T8**
- `tests/approvals/test_approve.py` — **T22**

(These cite the overview file + ID. Phase D should decide whether to repoint them at the specific
`T*.md` file, and must update the ID if T7/T8/T22 are renumbered.)

---

## Commit strategy

| Phase | Granularity |
|---|---|
| Setup | one commit (placeholders + tracker) |
| A | one commit (taxonomies.md + references + this prep) |
| B | one commit **per ATT&CK tactic** |
| C | **tight batches** of related threats |
| D | one commit for overview regen; one for the reference sweep; one for the #111 mapping |

---

## Resume protocol

This tracker holds live state (checkboxes above + the status grid below). On a hard stop, post a
comment on **#107** naming the current phase/step and the last-completed threat, then stop — do not
narrate to chat during unattended runs.

---

## Per-threat status grid

Legend: `·` = not started · `~` = in progress · `✓` = finalized this pass.

| ID | Threat | Reviewed | `stride` | `attack` | `delta` | `bucket` | Defenses audited |
|---|---|:--:|:--:|:--:|:--:|:--:|:--:|
| T1 | Single approver account compromise | · | ✓ | · | · | · | · |
| T2 | Compromised approver as DoS (deny) | · | ✓ | · | · | · | · |
| T3 | Approver withholding (liveness) | · | ✓ | · | · | · | · |
| T4 | Proxy host compromise | · | ✓ | · | · | · | · |
| T5 | Database read compromise | · | ✓ | · | · | · | · |
| T6 | Database write compromise | · | ✓ | · | · | · | · |
| T7 | TOTP secret exposure in database | · | ✓ | · | · | · | · |
| T8 | Approval link replay | · | ✓ | · | · | · | · |
| T9 | Enrollment link interception | · | ✓ | · | · | · | · |
| T10 | Approval link phishing | · | ✓ | · | · | · | · |
| T11 | Package swap (payload substitution) | · | ✓ | · | · | · | · |
| T12 | Approval fatigue / MFA bombing | · | ✓ | · | · | · | · |
| T13 | Admin account compromise | · | ✓ | · | · | · | · |
| T14 | Network path bypass (forward-auth) | · | ✓ | · | · | · | · |
| T15 | Proxy session hijacking | · | ✓ | · | · | · | · |
| T16 | SMTP channel attack | · | ✓ | · | · | · | · |
| T17 | Cryptographic implementation failure | · | ✓ | · | · | · | · |
| T18 | Supply chain attack on the proxy | · | ✓ | · | · | · | · |
| T19 | Insider collusion | · | ✓ | · | · | · | · |
| T20 | AES-256-GCM nonce (IV) exhaustion | · | ✓ | · | · | · | · |
| T21 | CSRF on the approve/deny form | · | ✓ | · | · | · | · |
| T22 | Info disclosure via quorum status | · | ✓ | · | · | · | · |
| T23 | Timing attack on bcrypt verification | · | ✓ | · | · | · | · |
| T24 | Shared account password reset bypass | · | ✓ | · | · | · | · |
| T25 | No anti-automation on auth endpoints | · | ✓ | · | · | · | · |
| T26 | API token theft | · | ✓ | · | · | · | · |
| T27 | Request & resource flooding (DoS) | · | ✓ | · | · | · | · |

**Current step:** Phase A complete — taxonomies.md, references, coverage map, and strawman drafted;
the 5 gap candidates are now verdict-tagged (2 clear new threats, 1 strong candidate, 2 name-or-fold).
**Next:** Phase B grill — walk the coverage map with Ian, settle the gaps + the `⚑` strawman flags,
then Phase C deep pass in tight batches. Awaiting Ian's return.
