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
likelihood_baseline: high|medium|low|N/A   # N/A iff delta: introduced
likelihood_residual: high|medium|low
severity_baseline: critical|high|medium|low|N/A   # N/A iff delta: introduced
severity_residual: critical|high|medium|low
bucket: 1|2|3|4|N/A                     # delta GATES bucket (inherited ⇒ N/A)
related: [...]
```

`delta` precedes `bucket` because an **inherited** delta forces `bucket: N/A`. `attack` is
appended after `stride` so the two external-taxonomy tags sit together. The four rated fields
(grill, 2026-07-02) sit between `delta` and `bucket` for the same gating reason: `delta:
introduced` forces both `_baseline` fields to `N/A`, so `delta` must come first; within each
pair, baseline precedes residual so the pair reads left-to-right as the delta story
("critical → medium").

---

## Classification axes (condensed from `evaluation-plan.md`)

**`delta` — relationship to the direct-publish baseline** (publish to PyPI with API token + account 2FA, no proxy):

- **improved** — pre-existing threat the proxy measurably *reduces*. Feeds the §1 value proposition.
- **inherited** — pre-existing *authentication-layer* threat the proxy leaves unchanged. Out of scope by design → `bucket: N/A`, reported once as a scope statement, never counted as a proxy weakness.

> **The net-cancellation rule (grill, 2026-07-01 — make this VERY obvious near the delta explainer in the regenerated overview):** delta is a **net** measure against the baseline world, not a gross surface count. Both worlds must have an authentication layer (baseline: PyPI login/2FA/sessions/reset; proxy: its own equivalents), so auth-layer threats appear on both sides of the ledger and **cancel when our instance is standard-practice-equivalent** → `inherited`. The cancellation **breaks** when we deviate below standard practice (T25 no rate limiting; plaintext TOTP pre-#122) or make a novel design claim (T15's re-auth-gated sessions) → owned (`introduced`/`improved`). *Surface being new doesn't make a threat introduced; the threat failing to cancel against the baseline's equivalent does.* Phase C: add this as a clarifying sentence to evaluation-plan.md's delta definition (interpretation note, not a method change).

- **introduced** — attack surface that exists *only because the proxy exists*. The net-delta cost (§3).

**`likelihood_*` + `severity_*` — the two rated axes (grill, 2026-07-02).** Authoritative
definition: `evaluation-plan.md` §3; this is the condensed working copy. Each axis is a
**baseline/residual pair**: *baseline* = the equivalent attack in the direct-publish baseline
world (the same PyPI + API token + 2FA world `delta` compares against); *residual* = under the
proxy's **current** design — honest-audit stance, same as the Phase C defense audit, not
aspirational. **Gating:** `delta: introduced` ⇒ both `_baseline` fields `N/A` (no
baseline-equivalent attack exists).

- **`likelihood`** (`high|medium|low`) — anchored to the **required precondition**. `capability`
  is unchanged and is *not* a rated axis: it is definitional (a proxy-world precondition; the
  L-ladder names proxy components that don't exist in the baseline world, so "baseline
  capability" is incoherent). Likelihood is its rated counterpart. Proxy-world **default** reads
  off the `capability` tag; deviations allowed, justified in the threat body. Baseline world:
  same precondition question, no L-labels.

  | `capability` | default likelihood | precondition class |
  | --- | --- | --- |
  | L1–L2 | high | remote position / single commodity credential theft |
  | L3–L5 | medium | full single-account compromise or database foothold |
  | L6–L9 | low | host code exec, insider, admin, multi-party collusion |

- **`severity`** (`critical|high|medium|low`) — the **mission outcome ladder**, read off the
  threat's "what the attacker gains" row. Mission = prevent an unauthorized package reaching PyPI.

  | rung | meaning |
  | --- | --- |
  | **critical** | mission failure — unauthorized artifact reaches PyPI, or durable ability to publish at will (quorum control, roster takeover) |
  | **high** | authorization integrity compromised (forged/miscounted vote, weakened quorum policy, class-of-credentials/signing-key compromise) but ≥1 independent barrier still stands |
  | **medium** | security-relevant loss that doesn't move a publish decision (evidence loss/repudiation, non-credential sensitive disclosure, a single bounded action such as one vote) |
  | **low** | availability or minor disclosure; fails safe; operator-recoverable |

**No computed risk score.** The (likelihood, severity) matrix cell *is* the risk statement;
ordinal arithmetic on the ratings (DREAD-style) is rejected.

**Delta cross-checks** (Phase C-verify enforces these):

- `improved` ⇒ baseline strictly worse than residual on **≥1 axis**. T1 improves on severity
  (critical→medium: one stolen baseline credential = unilateral publish vs. one vote); T19
  improves on likelihood (one insider alone → m coordinating colluders; severity stays
  critical→critical).
- `inherited` ⇒ likelihoods **equal** — that is what net-cancellation means (the mechanism
  cancels). Severity **may** differ: T24 baseline = whole PyPI account = critical; proxy = one
  approver account = one vote. That containment is T1's improvement counted once
  (cross-referenced); it does **not** flip T24's delta — delta classifies mechanism ownership,
  not outcome size. baseline≠residual severity on an inherited threat = **flag-for-review**, not
  auto-fail.
- `introduced` ⇒ both baselines `N/A`.

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

### Phase C — Per-threat deep pass (by related batch)

For each threat, validate + finalize: category, capability, what-attacker-gains, what-they-cannot-do, **Current defenses (honest audit vs. the current spec — true or aspirational?)**, planned defenses, operator config, body prose. Then assign `stride` + `attack` tags, `delta`, and `bucket` (or `N/A`). Each threat also gets the four `likelihood_*`/`severity_*` fields assigned in its batch (grill, 2026-07-02): likelihood defaults from the `capability` mapping, deviations justified in the body; no separate placeholder pass — the fields are added when each threat's frontmatter is rewritten. Resolve the reclassifications #107 names (see the Settled Threat List). **One commit per batch.**

**Phase C conventions (settled at Phase C open, 2026-07-02 — full contract in [CONTRIBUTING.md](CONTRIBUTING.md)):**

- **Buckets are current-state** (honest audit; confirmed in the grill after considering end-state semantics). The end state lives in a per-threat **`## Planned defenses`** body section — every entry cites a live issue and states its bucket impact ("promotes ③ → ① (detection tier)" / "no bucket change"). This section **replaces** the old "Planned defenses" summary-table row and is the structural home of the only-issues rule. When an issue closes, the entry moves into Current defenses and the bucket is raised — so the catalog always reads current-state with the promotion obvious.
- **`CONTRIBUTING.md` live-written now** (was a Phase D item): field-by-field contract, conventions, lifecycle recipes. Keep it live-updated as later batches settle anything new; Phase D reduces to a delta pass.
- **Capability conventions (X5):** possession of one leaked credential = **L2** ("single commodity credential theft" class) with the credential named in the body row — resolves T26 and T14; **`external`** sentinel for attackers outside the deployment trust boundary — resolves T18 (`capability: [external]`, no default likelihood, justified per-body); T12 stays `[L2]` with the insider-requester variant noted in prose.
- **Empty-`attack:` convention:** `attack: []` + one-line prose note where no Enterprise technique fits (T3, T17, T20); weak-fit = tag + body caveat (T23/T1040 pattern). Never force a tag.
- **New-threat IDs (X6):** **T28** audit-trail suppression · **T29** app-layer vulnerability · **T30** destructive availability — **provisional** (grill): Phase D keeps a renumbering/reordering pass at the very end, once it's known how few IDs move; IDs are stable only while Phase C is in flight.
- **Context hygiene (grill, 2026-07-02):** pause at **every batch boundary** — after each batch commit, stop and prompt for `/compact` before opening the next batch. Never roll from one batch into the next without the pause.
- **Grill presentation format (grill, 2026-07-02):** every per-threat grill question is self-contained (what it is / gains / cannot do / open items / recommendation) and ends with a **full classification table: every frontmatter field with a one-line reasoning** — verbose beats terse. Threat IDs link to their `T*.md` files and issue numbers link to GitHub on first mention (clickable, every time). ATT&CK technique IDs are never bare: give the technique name and a plain-language sentence of what it means (e.g. "T1078 — Valid Accounts: the attacker logs in with legitimate stolen credentials instead of exploiting a vulnerability").
- **T14 promotion filed as [#124](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/124)** (out-of-band publish reconciliation, detect + alert): bucket ③ today, ① (detection tier) once it lands.
- **Parallel sessions (2026-07-02):** Phase C runs in two sessions sharing this working tree — **top-down owns Batches 1–4** (T1, T19, T11 · T13, T25, T15, T23, T24 · T5⊕T7, T6, T26, T28 · T17, T20), **bottom-up owns Batches 8–5** (T4, T18, T14 · T2, T3, T27, T30 · T21, T22, T12, T29 · T8, T9, T10, T16). Each session edits **only its own batches' threat files** and only its own rows of the status grid. Cross-boundary `related:` links and cross-cutting discoveries go in **`PHASE-C-HANDOFF.md`** (temporary; dies with this tracker) — check it at every batch start. Commits stage explicit file lists only — never `git add -A` / `commit -a`.

**Batch order (grill — related threats together; numeric order doesn't matter):**

1. **Multi-party authorization core** *(the improved-delta value prop + what quorum authorizes)* — **T1** (flagship, improved ①), **T19** (collusion boundary, improved ④), **T11** (package-swap / hash-binding, introduced ①). Establishes the central guarantee first: quorum saves you (T1), collusion is its boundary (T19), the artifact hash is what an approval binds (T11).
2. **Approver authentication & session** *(the front door — approver-authentication.md / account-management.md)* — **T13** (admin compromise ①), **T25** (anti-automation ①, #123), **T15** (session hijacking ②), **T23** (bcrypt timing, inherited N/A), **T24** (password reset, inherited N/A). Both inherited auth-layer threats live here so the net-cancellation framing is written once.
3. **Data & credentials at rest** *(the database — cryptography.md § at-rest + models)* — **T5** (DB read ③, **absorbs T7** via #122), **T6** (DB write ①, **absorbs quorum-policy tamper** #121), **T26** (API token theft, improved ①), **NEW Audit-trail suppression** (introduced ③). Audit-suppression's deletion story is the counterpart to T6's tamper story — write them adjacent to keep "signatures detect modification, not deletion" consistent.
4. **Cryptographic design** *(cryptography.md algorithm level)* — **T17** (crypto impl ②), **T20** (AES-GCM nonce exhaustion ②).
5. **Approval-link & notification lifecycle** *(notification-system.md + link delivery)* — **T8** (link replay ①), **T9** (enrollment-link interception ③), **T10** (phishing + **AITM** ②), **T16** (SMTP channel ③).
6. **Web-edge request handling** *(the FastAPI edge / endpoints)* — **T21** (CSRF ①), **T22** (quorum-status info disclosure ②), **T12** (approval-request fatigue ②), **NEW App-layer vulnerability** (introduced ②).
7. **Availability & denial of service** *(STRIDE-D)* — **T2** (approver-as-DoS ④), **T3** (withholding ④), **T27** (request/resource flooding ①, #32/#123), **NEW Destructive availability attack** (introduced ③).
8. **Infrastructure, host & network boundary** *(deployment / topology — operator-flavored)* — **T4** (host compromise ④), **T18** (supply chain ④, shares T4's accepted consequence class), **T14** (proxy bypass ③, reframed — out-of-band publish credential).

29 entries across 8 commits (26 standalone after the T7→T5 merge, + 3 new). After Batch 8: run **Phase C-verify** (tag subagents), then Phase D.

### Phase C-verify — Independent tag verification (subagents; grill 2026-07-01)

After Phase C finishes and before the Phase D overview regen, run **one subagent per tag axis**, each re-reading every finalized threat body + frontmatter cold and flagging misfits:

- [x] Subagent 1 — **`attack`** (ATT&CK): does each technique ID's real definition match the threat's behavior? No outcome-padding (cf. the T1657 rule); sub-technique preferred where it exists.
- [x] Subagent 2 — **`stride`**: does each tag match the property actually violated in the body's "what the attacker gains"?
- [x] Subagent 3 — **`delta` + `bucket`**: baseline comparison sound (owned-vs-inherited discriminator: specific gap/claim vs. standard practice)? Bucket claims honest (① only with named tests that **exist**; promotions only in `## Planned defenses` with a live issue + stated bucket impact; inherited ⇒ N/A)?
- [x] Subagent 4 — **`likelihood_*` + `severity_*`**: residual likelihood consistent with the capability tag's default mapping (or deviation justified in the body)? Severity consistent with the "what the attacker gains" row against the mission ladder? Gating respected (introduced ⇒ baselines N/A)? Delta cross-checks hold (improved ⇒ strictly better on ≥1 axis; inherited ⇒ likelihoods equal, severity mismatch = flag-for-review not auto-fail)?

All four ran 2026-07-02. Consolidated findings + per-item recommendations: **§ Phase C-verify
findings** at the end of this file. **Adjudicated 2026-07-03 (grill) — all 17 items applied**
as the adjudication commit; Phase D is unblocked.

### Phase D — Metadata, repo-wide sweep, and #111

- [ ] Regenerate `00-overview.md`: delta cut, four-bucket distribution over **owned** threats, Inherited listed separately as the scope statement, refreshed navigator tables, a **residual-likelihood × residual-severity risk matrix**, and an **improved-threats baseline→residual table** (feeds the §1 value proposition).
- [x] **Overview rework / field explainers → landed in CONTRIBUTING.md** (live-written 2026-07-02 at Phase C open): per-field explainers with allowed-values tables, net-cancellation rule beside `delta`, anchors + gates for the rated axes, bucket semantics + Planned-defenses convention. The regenerated overview keeps only a **brief frontmatter legend + pointer to CONTRIBUTING.md** — no duplication.
- [ ] **CONTRIBUTING.md delta pass (was: write it):** the guide exists; at Phase D, sweep for anything the later batches settled that wasn't live-updated into it, and verify overview/CONTRIBUTING have clean separation (navigator vs. contract). **Adjudication carry-forwards (2026-07-03):** codify (a) the per-leg headline-bucket rule (J11: a threat's headline `bucket` is its *primary* leg's bucket; minority legs stated per-leg in the body — T21/T9 pattern) and (b) the critical-severity rule (J3: `critical` = the attacker can publish with **no remaining precondition on other approvers**; anything still gated on approvers approving caps at `high`).
- [ ] **Renumbering / reordering decision (end of Phase D):** with all content final, decide whether to reorder/renumber the catalog (T7 gap, T28–T30, any preferred grouping). Whatever the outcome, update CONTRIBUTING.md's ID-stability rule to its final form in the same change.
- [ ] **Repo-wide reference sweep** — update EVERY threat-ID reference across docs + code to its new identity (applies the renumbering outcome). Inventory below.
- [x] **#111 mapping table** (commit ea2a9b1): `test-mapping.md` — bucket-① demonstration map (CORE-1, CORE-2, VOTE-2, VOTE-3, PUB-1 → named tests + oracles; CORE-1 refs Act 2 demo #114), full owned-threat results table (27, delta/residual/bucket/backing-test-or-rationale), four-bucket distribution, CRYPTO-2 inherited excluded as scope statement. 18 cited tests verified present. Overview #111 pointer + docs/index.md wired. Note: integrity/detection ① tier has no owned occupant (Ed25519 verify underwrites HOST-2 ②).
- [x] **Bucket-① roll-up issue (grill)** — filed as [#131](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/131). Gathers every open issue a bucket-① claim depends on, as a checkable task list (issue → threat → promotion → tier → oracle). **Exhaustive scan found ten, not the six pre-listed:** #121, #123, #32, #126, #124, #125, #127 **plus #30 (DOS-4 ④→①), #128 (IDENT-2 detection ③→①), #129 (IDENT-4 capture leg ②→①)** — all three carry explicit "→ ①" promises in their threat's `## Planned defenses`, so they are the "+ any Phase C additions" the checkbox called for. Body notes the 5 current ① threats are *not* blocked (tests exist today) and that #121 is the only row filling the empty integrity/detection ① tier. Buckets ②–④ without an ① promise excluded (report-only, not must-fix).
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

1. **App-level vulnerability in the proxy's own code** (T1190) — **DECIDED (grill): NEW THREAT.** No threat covers injection / SSRF / broken-object-authz / auth-bypass bugs in the FastAPI code itself: **T4 *assumes* code-exec already**, T17 is crypto-only, T18 is dependencies-only. New high-level threat, `delta: introduced`. **`bucket: 2`** (grill-confirmed): argued by design — SQLAlchemy parameterization, Pydantic edge validation, small route surface, framework-free logic per the slice rule; body must state the residual (pentest/fuzzing assurance out of scope) and note authz regression tests as a ① promotion candidate.
2. **Quorum-policy tampering** (T1556.009) — **DECIDED (grill): EXPAND T6, keep bucket ① via a new design work item ([#121](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/121)).** Sharper finding than first investigated: the quorum **snapshot on the request row is unsigned** (cryptography.md § Audit Trail Integrity — only Votes are signed), so a DB-write attacker can lower an *in-flight* request's snapshot 3→1 and satisfy it with one genuinely-signed compromised-approver vote. The config file is the policy root of trust and startup validation floors `quorum ≥ 2`. Planned defense (the work item): **(a)** bind the quorum snapshot into each vote's signed payload; **(b)** execution-time consistency check of snapshot vs. live config, freeze on mismatch. Same oracle as T6's existing ① story (signature/binding verification fails). Residual: config-file tampering = host file-write → T4 (④). Honest phrasing: ① once the binding lands, ③ (DB ACLs) today — same pattern as T25/T27.
3. **Audit-log suppression** (T1562/T1070) — **DECIDED (grill): NEW THREAT ("Audit-trail suppression").** Deletion/reordering is exactly what T6's expanded "detected" invariant (#121) does NOT cover — `cryptography.md` disclaims it (no hash chain; non-vote lifecycle records unsigned). Separate threat keeps T6's ① honest and gives Repudiation its first strong dedicated threat. Body notes: evidence attack, not outcome attack (deleting a Deny doesn't unfreeze); hash-chaining named as future promotion path, not a commitment. **Classification:** stride: Repudiation · attack: T1070, T1562 · delta: introduced · bucket: ③ (INSERT-only ACL + external append-only log).
4. **Data destruction / approver lockout** (T1485/T1531) — **DECIDED (grill): ONE NEW THREAT ("Destructive availability attack").** Covers DB/state destruction, backup destruction, and mass approver lockout (quorum exhaustion) in one entry — shared attacker (privileged), impact (capability lost, not subverted), defense family (backups, restore, re-enrollment, ACLs). Body must state: (1) **fails safe** — pure availability, can never produce an unauthorized publish; (2) recovery is operator territory by nature (shared WORM/offsite defense with the audit-suppression threat). **Classification:** stride: Denial of Service · attack: T1485, T1531, T1490 · delta: introduced · bucket: ③.
5. **Real-time MFA relay / AITM** (T1111) — **DECIDED (grill): EXPAND T10, not T8, not new.** It's phishing escalated (same lure, same defenses); T8's burn is what relay *defeats*, so folding there would attach a non-defense — but burn gives a *detection signal* (victim's concurrent login fails), cross-referenced from T10. Containment lives in T1 (one relayed session = one vote; baseline AITM = full publish). Body residual: TOTP is not phishing-resistant; single-approver relay succeeds; WebAuthn named as promotion path, not commitment. **Classification (T10 expanded):** stride: Spoofing · attack: T1566.002, T1111, T1557 · delta: introduced · bucket: ②.

**Gap outcomes summary:** 3 new threats (#1 app-vuln ②, #3 audit-suppression ③, #4 destructive-availability ③) + T6 expanded (policy tamper, #121) + T10 expanded (AITM). Final IDs assigned in Phase C.

**Cross-cutting grill decisions:**

- **T1657 Financial Theft is dropped globally.** ATT&CK defines it as direct monetary theft (extortion/BEC/fraud); a malicious publish isn't that. Where the supply-chain outcome needs naming (T1, T11, T19), say it in **prose** as what downstream consumers experience (T1195.002) — never as an `attack:` tag. T1565.001 survives only where stored-data manipulation genuinely occurs (T6-style). Revise the taxonomies.md "notable judgment calls" section to match (Phase C).
- **Only-issues rule:** every planned defense referenced by a threat must be a GitHub issue, not a scratch note or "work item" (#121 policy binding, #122 TOTP wrapping, #123 auth throttle, #32 request-flood caps).

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
| T7 | **MERGE → T5** | — | DECIDED (grill): no standalone threat for stealing *wrapped* signing keys exists (it's a T5 line item), so plaintext TOTP shouldn't stand alone either — close the asymmetry via [#122](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/122) (wrap TOTP secrets with password-derived enc_key) and fold T7 into T5's "what a DB reader gains" enumeration. **T7 is load-bearing in code** (models.py, hash_credentials.py) → Phase D sweep must repoint those comments at T5. T5 stays: stride: Information Disclosure · attack: T1005, T1552.001/.004 · delta: introduced · bucket: ③ (ACLs) with ② at-rest arguments; uniformly ② for credentials once #122 lands. |
| T8 | introduced | 1 | Approval-link replay; signed votes + single-use TOTP + terminal freeze (black-box). |
| T9 | introduced | 3 | Enrollment-link interception; secure distribution (operator). |
| T10 | introduced | 2 | Approval-link phishing; auth required + domain verification. ⚑ ② vs inherited(phishing). |
| T11 | introduced | 1 | Payload substitution in upload→publish window; hash binding (black-box). |
| T12 | introduced | 2 | DECIDED (grill): **no split — narrow to "Approval-request fatigue," introduced-only.** MFA bombing (T1621) can't apply to an entered-TOTP factor (no unsolicited prompt exists to fatigue — consistent with taxonomies.md's T1111>T1621 call); it leaves the **title** but stays in the **body** as the analogy + a note on why it doesn't apply. Stays distinct from T27 (T27 = mechanical flooding/availability; T12 = human-vigilance degradation → bad approval). **Classification:** stride: Spoofing, Elevation of Privilege · attack: T1656 (cross-ref T27 flooding) · delta: introduced · bucket: ② (approval context + hash display + m-of-n backstop; human-factors residual). APPLIED (Batch 6): file → `T12-approval-request-fatigue.md` (Phase D sweep); likelihood high (L2 default) / severity **high not critical** (fatigue success is probabilistic, one-shot, loud — `critical` reserved for durable publish-at-will); planned defenses collapse to #32 (covers limits, cooldown-after-denial shape, burst alerting — no bucket change). |
| T13 | introduced | 2 | DECIDED (grill, 2026-07-02): **② not ①** — the roster-takeover attack casts *genuine* signed votes, so Ed25519 detects nothing. The real property is "takeover cannot be silent": victim notifications on reset/deactivate + atomic AuditLog journaling (components tested), argued by design. Quiet enroll-forward path traces only to unsigned journal rows → ② until admin-action notifications ([#125](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/125)) make enrollment alarm (② → ①). Snapshot (ADR 0008) blocks injecting voters into in-flight requests. attack: T1078, T1098, T1136.001 · L3 · likelihood medium / severity critical. Planned: #125, #121. |
| T14 | introduced | 3 | DECIDED (grill, 2026-07-02): **reframed + retitled "Proxy Bypass"** (general title per grill decision; file → `T14-proxy-bypass.md`, Phase D sweep). The abstract threat is **incomplete mediation** — an unmediated path to the protected action exists. Primary in-scope story: **out-of-band publish credential** — a maintainer retaining Owner/upload rights, a stale pre-adoption API token in CI, or the org-account recovery path publishes to PyPI *directly*: no request, no votes, no audit trail, invisible to the proxy. Strongest bypass in the catalog; states plainly that the proxy's guarantee is **conditional on credential exclusivity** (complete mediation, Saltzer & Schroeder — report citation). Forward-auth/network variant demoted to a one-line future-vision mention (#109: package-publishing is the only use case). ③ = credential-topology hygiene (operator): revoke all pre-existing project tokens at onboarding, demote maintainer accounts to non-upload roles, 2FA the org account, audit collaborators/tokens periodically. **Classification:** stride: Elevation of Privilege · attack: T1078 (valid out-of-band credential bypasses the control; T1599 moves to prose with the network variant) · delta: introduced (baseline has no enforcement claim to bypass — the threat is the gap between the proxy's claim and its reach) · bucket: ③ today, ① (detection tier) once [#124](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/124) lands (out-of-band publish reconciliation — detect + alert; tracked in T14's Planned defenses section). |
| T15 | introduced | 2 | Session hijacking; signed revocable cookie + re-auth-gated voting (argued). |
| T16 | introduced | 3 | SMTP channel; TLS/DMARC (operator). |
| T17 | introduced | 2 | Crypto implementation; argued by design + candidate ① invariant tests. |
| T18 | introduced | 4 | DECIDED (grill): ④ for consistency with T4 — in-process code *is* the proxy; no config survives it. Grill discriminator: "if the operator can't completely defend or prevent it, we own it — accepted limitation." Body rewrite flips emphasis: current defenses = **uv.lock hash-pinning (549 hashes — corrects stale 'None'; prep's 557 was pre-uv-audit)** + CI dependency scanning (added directly to ci.yml on progress-report-4, no issue — grill) + Dependabot alerts (were disabled — enabled 2026-07-02, Batch 8 grill); operator = trusted source/mirror/minimal image = likelihood reducers around an accepted core. Release signing / reproducible builds demoted to a mention, untracked. **Classification:** stride: Tampering, Elevation of Privilege · attack: T1195.001 · delta: introduced (no baseline-equivalent self-hosted dependency tree) · bucket: ④. |
| T19 | improved | 4 | DECIDED (grill): collusion is the *residual of the core improvement* (baseline: 1 insider publishes alone; proxy: m colluders + m signed votes), not new surface — flipping to introduced would put the biggest win on the cost ledger. ④ = deliberate design boundary (m-of-n cannot defend against all parties agreeing), bucket ④'s best exemplar. **Classification:** stride: Elevation of Privilege · attack: T1078 · delta: improved · bucket: ④. |
| T20 | introduced | 2 | AES-GCM nonce exhaustion; argued safe for MVP patterns. |
| T21 | introduced | 1 | CSRF; candidate CSRF test (black-box). DECIDED (Batch 6): **retitled "Browser-Borne Approval Coercion"** (invariant-vs-instance; file → `T21-browser-borne-approval-coercion.md`, Phase D sweep). Classic CSRF is architecturally foreclosed (no ambient credential — per-vote password+TOTP) and ① today via `test_a_vote_requires_fresh_reauthentication`; UI-redress leg ③ → ① once **#127 (new, filed Batch 6)** lands (in-app anti-framing headers). `attack: []` considered verdict (no CSRF/clickjacking technique in ATT&CK Enterprise; T1189/T1185/T1204 rejected). Likelihood low (justified deviation from L1 default) / severity high. |
| T22 | introduced | 2 | DECIDED (grill): ② — ④ would mislabel intended #22 transparency as a failure; method's own ② definition covers "accepted info-leaks." AMENDED (Batch 6): link obscurity is **not** a defense — the spec disclaims it (`web-proxy.md`: security rests on per-vote re-auth, not hiding the page) and the requester is a legitimate viewer of endorser names on their own request (approve page's missing ownership guard is deliberate). Real defense = the **disclosure boundary**, already ①-grade in tests: no/invalid link → 404; deniers/withdrawers/non-actors never named in any response (4 named tests in `tests/approvals/test_approve.py`). ② stands (②-vs-④ re-litigated and upheld: the disclosure is chosen and defensible, not undefendable). **Classification:** stride: Information Disclosure · attack: T1589 · delta: introduced · likelihood high / severity medium · bucket: ②. |
| T23 | inherited | N/A | DECIDED (grill): inherited by the net-cancellation rule — at standard practice (library constant-time), identical exposure both worlds, cancels. Stays in catalog (applies-to-surface test) as a slim entry; deletion would make "considered" indistinguishable from "forgotten." Cross-ref T25/#123 (limiter kills the oracle's request volume). **Classification:** stride: Information Disclosure · attack: T1040 (noted weak fit; no ATT&CK timing-side-channel technique) · delta: inherited · bucket: N/A. |
| T24 | introduced | 3 | DECIDED (grill, 2026-07-02): **reclassified inherited → introduced, retitled "External Account Recovery Bypass."** The funnel account (the single PyPI publisher account the proxy holds a token for) and the quorum its recovery bypasses are BOTH proxy constructs — baseline publishes from individually-managed maintainer accounts, no shared-recovery SPOF — so no baseline analog. Generalized: any external account the proxy funnels authority through (PyPI now; shared SaaS/cloud in #109 vision). ③ operator-enforced (2FA + group recovery inbox; the proxy cannot gate an external service's recovery flow). attack: T1078 (weak-fit caveat) · L2/L7 · likelihood low / severity critical. **T23 is now the sole inherited N/A entry.** |
| T25 | introduced | 1 | DECIDED (grill): **no split — wholly introduced/owned.** "Inherited" contradicted the method: the threat exploits a specific proxy gap (no limiter, free failed attempts) with a planned proxy defense + test — a threat we're fixing can't be disclaimed. Discriminator adopted: inherited = rely on standard practice, claim no delta; owned = specific gap or design claim. Defense now tracked as [#123](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/123) (auth-endpoint throttle; #32 covers T27's request-creation half). **Classification:** stride: Elevation of Privilege, Denial of Service · attack: T1110.001, T1499.003 · delta: introduced · bucket: ① once #123 lands, ③ today. |
| T26 | improved | 1 | DECIDED (grill): improved by the net-cancellation rule — baseline has the same credential in the same risky spot (PyPI token in CI) with strictly more power (unilateral publish); proxy hands automation a strictly weaker token ("may ask permission"). Second-strongest improved story after T1 (machine-credential analog). Grill: "having it on one approver's machine is much more dangerous than in the proxy." Bucket ① black-box: token-authenticated upload + drive everything → assert PyPI mock never invoked; companions: revoked token → 401, `is_active` kill-switch. **Classification:** stride: Spoofing, Elevation of Privilege · attack: T1528, T1552, T1550.001 · delta: improved · bucket: ①. |
| T27 | introduced | 1 | Request/resource flooding; ① for introduced portion once rate limiter lands, ③ today. DECIDED (Batch 7): promotion is per leg — #32 promotes the flooding legs, **#126 (new, filed Batch 7)** promotes the storage leg (upload size/count caps had no issue); attack T1499 parent (T1499.003 is T25's; T1498 not claimed). |

**Distribution shape (provisional, owned threats only):** ① ≈ T1,T6,T8,T11,T21,T25*,T27* · ② ≈ T10,T13,T15,T17,T20,T22,T26 · ③ ≈ T5,T9,T14,T16,T18,T24 · ④ ≈ T2,T3,T4,T7,T19. **Inherited (N/A):** T23 + inherited portions of T12,T25. Plus any new threats from the gap candidates. *(Batch 2 grill 2026-07-02: T13 ①→②, T24 inherited→introduced ③.)*

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

Legend: `·` = not started · `~` = in progress · `✓` = finalized this pass. The `likelihood` and
`severity` columns each cover the field's baseline/residual pair.

| ID | Threat | Reviewed | `stride` | `attack` | `delta` | `likelihood` | `severity` | `bucket` | Defenses audited |
|---|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| T1 | Single approver account compromise | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| T2 | Compromised approver as DoS (deny) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| T3 | Approver withholding (liveness) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| T4 | Proxy host compromise | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| T5 | Database read compromise | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| T6 | Database write compromise | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| ~~T7~~ | TOTP secret exposure — **merged → T5** (#122); tombstoned, deleted in Phase D | ✓ | — | — | — | — | — | — | — |
| T8 | Captured-credential replay (retitled 2026-07-02) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| T9 | Enrollment link interception | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| T10 | Phishable approver authentication (retitled 2026-07-02) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| T11 | Package swap (payload substitution) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| T12 | Approval-request fatigue (retitled 2026-07-02) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| T13 | Admin account compromise | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| T14 | Proxy bypass (reframed 2026-07-02) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| T15 | Proxy session hijacking | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| T16 | Notification-channel interception (retitled 2026-07-02) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| T17 | Cryptographic implementation failure (absorbs T20) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| T18 | Supply chain attack on the proxy | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| T19 | Insider collusion | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| ~~T20~~ | AES-256-GCM nonce exhaustion — **merged → T17** (Batch 4); tombstoned, deleted in Phase D | ✓ | — | — | — | — | — | — | — |
| T21 | Browser-Borne Approval Coercion (retitled 2026-07-02) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| T22 | Info disclosure via quorum status | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| T23 | Cryptographic side-channel leakage (generalized + retitled 2026-07-02, Batch 4 circle-back) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| T24 | External Account Recovery Bypass (retitled 2026-07-02) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| T25 | No anti-automation on auth endpoints | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| T26 | API token theft | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| T27 | Request & resource flooding (DoS) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| T28 | Database repudiation attack (new, Batch 3) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| T29 | Application-layer vulnerability (new, Batch 6) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| T30 | Destructive availability attack (new, Batch 7) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

**Current step:** **Phase D in flight** (2026-07-03). Adjudication commit landed (all 17
findings). **Renumber DONE** (commit 055d609): the flat T<n> scheme was replaced with
group-prefixed IDs (CORE/IDENT/VOTE/HOST/CRYPTO/PUB/DOS/CODE/INFO) — Ian chose renumber over
keep-gaps and specified a smart thematic reorder (nine severity-ordered groups; CORE runs
thesis→residual). T7/T20 tombstones deleted, T24 file renamed, repo-wide sweep applied (docs +
code + tests + report fragments), CONTRIBUTING rewritten for the scheme + both carry-forwards
(J11 per-leg bucket, J3 critical-severity). Tests 256 green, ruff clean.
**Overview regen DONE** (commit 5a20ce8): `00-overview.md` rewritten for the prefixed scheme —
group table, net-delta cut (improved 3 / introduced 24 / inherited 1), four-bucket distribution
(①5 ②8 ③9 ④5 = 27 owned + CRYPTO-2 inherited), narrative-ordered catalog, STRIDE×bucket and
capability×bucket navigators, residual risk matrix, improved-threats baseline→residual table,
re-cited operator checklist. All 28 links resolve; no stray flat T<n>. Verified: the
net-cancellation clarifying sentence is already present in evaluation-plan §3 (line 189) — no
edit needed there.
**#111 mapping DONE** (commit ea2a9b1): `test-mapping.md` created — bucket-① demonstration map
(CORE-1, CORE-2, VOTE-2, VOTE-3, PUB-1 → named tests + pass/fail oracles; CORE-1 refs Act 2 demo
#114), full 27-threat owned results table (delta/residual/bucket/backing-test-or-rationale),
four-bucket distribution, CRYPTO-2 inherited excluded as scope statement. 18 cited tests verified
present. Overview #111 pointer + docs/index.md wired. Note recorded: the integrity/detection ①
tier has no owned occupant (Ed25519 offline-verify underwrites HOST-2, which is ②).

**Bucket-① roll-up DONE** (issue [#131](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/131)):
checkable task list of all ten open ①-promotion issues (#121, #123, #32, #126, #124, #125, #127,
#30, #128, #129 — the last three found by exhaustive `## Planned defenses` scan, beyond the six
pre-listed). Labeled `evaluation`. Current ① threats noted as unblocked; #121 flagged as the sole
integrity/detection-tier filler.

**Next:** (1) cleanup — final stale-reference grep, then delete this tracker + PHASE-C-HANDOFF.md +
PHASE-C-PREP.md; (2) PR against `progress-report-4`, manually close #107 + #111. **ID map for any
sweep is commit 055d609 itself.** **Heads-up:** a parallel
session is building the #130 threat-model dashboard in this same tree (untracked `tools/`,
`tests/tools/`, notebook; marimo in pyproject/uv.lock; four one-line reciprocal `related:` edits
to CORE-2/IDENT-1/PUB-2/VOTE-2) — leave those uncommitted files alone; they are not part of the
deep-dive.

---

## Settled Threat List (Phase B output)

Final catalog after the grill: **T7 merges into T5**, **3 new threats added**, **T6/T10 expanded**.
`delta`/`bucket` below are settled; `stride`/`attack` are settled in the strawman/gap annotations and
applied to frontmatter in Phase C. Final IDs/renumbering deferred to Phase D (tear-down freedom).

| Threat | delta | bucket | Notes |
| --- | --- | --- | --- |
| T1 Single approver compromise | improved | ① | Flagship; Act 2 demo (#114) |
| T2 Compromised approver as DoS | introduced | ④ | |
| T3 Approver withholding | introduced | ④ | |
| T4 Proxy host compromise | introduced | ④ | Consequence class shared with T18 |
| T5 Database read compromise | introduced | ③ | **Absorbs T7**; credentials uniformly ② once #122 |
| T6 Database write compromise | introduced | ② | **①→② (grill 2026-07-02):** public-key substitution + unsigned config fields produce a *validly-signed* forgery no oracle catches (same evasion as T13); content-tamper leg tested. **Absorbs quorum-policy tamper**; #121 → ① |
| ~~T7 TOTP secret exposure~~ | — | — | **MERGED → T5** via #122 (Batch 3); tombstoned. **Decided 2026-07-02: delete the file + renumber in Phase D**; code/doc refs repoint then |
| T8 Approval link replay | introduced | ① | **APPLIED (Batch 5, 2026-07-02):** retitled **Captured-Credential Replay** (invariant: captured auth material inside its validity window; the link was never the asset). T1111; low/high (low = justified deviation: password + live TOTP capture + ~90 s race); Planned = #30 (request timeouts bound the window) |
| T9 Enrollment link interception | introduced | ③ | **APPLIED (Batch 5, 2026-07-02):** T1586.002; medium/high (high not critical — one durable seat still can't publish; m links needed). **#128 filed** (out-of-band enrollment confirmation) → detection leg ③→① |
| T10 Approval link phishing | introduced | ② | **APPLIED (Batch 5, 2026-07-02):** retitled **Phishable Approver Authentication**; absorbs AITM as planned. ⚑ resolved **introduced** (ceremony + approver population are ours; baseline PyPI offers WebAuthn). Ed25519 "cannot forge" row deleted (proxy signs server-side — nothing to forge). T1566.002+T1557; high/high; **#129 filed** (WebAuthn/FIDO2 per-vote auth) → capture-prevention leg → ① |
| T11 Package swap (upload→publish) | introduced | ① | |
| T12 Approval-request fatigue | introduced | ② | Retitled (drop "MFA bombing"); no split |
| T13 Admin account compromise | introduced | ② | ①→② (grill 2026-07-02): genuine-signature takeover, Ed25519 detects nothing; "can't be silent" argued. #125 promotes ②→① |
| T14 Proxy bypass | introduced | ③ | Reframed (out-of-band publish credential primary); retitled → Phase D sweep |
| T15 Proxy session hijacking | introduced | ② | |
| T16 SMTP channel attack | introduced | ③ | **APPLIED (Batch 5, 2026-07-02):** retitled **Notification-Channel Interception** (SMTP = MVP instance). T1114; medium/high (rated with T9, its worst payload). #20 reframed as per-channel re-inheritance, not mitigation; DMARC/DKIM/SPF moved Planned → operator row |
| T17 Cryptographic implementation failure | introduced | ② | **Absorbs T20** (Batch 4): nonce-uniqueness row. Rewrite keyed to the shipped invariant tests (`test_invariant_1..4`); ② is the ceiling by nature (no oracle for "no implementation bug exists") — terminal, no planned defenses |
| T18 Supply chain on the proxy | introduced | ④ | uv.lock 549 pins; CI uv-audit leg |
| T19 Insider collusion | improved | ④ | 1→m; drop T1657 tag |
| ~~T20 AES-256-GCM nonce exhaustion~~ | — | — | **MERGED → T17** (Batch 4 grill, per invariant-vs-instance finding); tombstoned. Deleted + renumbered in Phase D alongside T7 |
| T21 CSRF on approve/deny form | introduced | ① | |
| T22 Info disclosure via quorum status | introduced | ② | |
| T23 Cryptographic side-channel leakage | **inherited** | N/A | Net-cancellation; **sole N/A entry** (T24 reclassified introduced). Generalized + retitled from "Timing attack on bcrypt" (Batch 4 grill): three-instance table (bcrypt, TOTP compare, login-short-circuit username enumeration — live residual, accepted); T17's complement |
| T24 External Account Recovery Bypass | introduced | ③ | Reclassified inherited→introduced + retitled (grill 2026-07-02): funnel account + quorum both proxy constructs |
| T25 No anti-automation on auth | introduced | ① | Keyed to #123; ③ today. No split |
| T26 API token theft | **improved** | ① | Machine-credential analog of T1 |
| T27 Request & resource flooding | introduced | ① | Keyed to #32/#123; ③ today |
| **NEW** App-layer vulnerability (T1190) | introduced | ② | Gap #1 |
| **NEW** Audit-trail suppression (T1070/T1562) | introduced | ③ | Gap #3; Repudiation's dedicated threat |
| **NEW** Destructive availability attack (T1485/T1531) | introduced | ③ | Gap #4; fails safe |

**Distribution (owned = improved+introduced, 27 threats after the T7+T20 merges):** ① ≈ 7 (T1,T8,T11,T21,T25,T26,T27) ·
② ≈ 9 (T6,T10,T12,T13,T15,T17,T22,app-vuln) + T5-creds-once-#122 · ③ ≈ 7 (T5,T9,T14,T16,T24,T28,destructive-avail) ·
④ ≈ 5 (T2,T3,T4,T18,T19). **Inherited (N/A, reported once as scope statement):** T23 (sole entry; T24 reclassified introduced ③, Batch 2 grill 2026-07-02).
(Counts approximate pending Phase C final tags + Phase C-verify.)

---

## Invariant-vs-instance pass (subagent sweep, 2026-07-02)

Prompted by T24's reframe (shared-account-password-reset → External Account Recovery Bypass): swept every not-yet-grilled threat for the same flaw — stating one narrow *instance* when a broader *invariant* is the real threat. Findings are backup input for the batch that grills each threat; **apply at grill time, not now.** Already-grilled threats (Batch 1 T1/T19/T11, Batch 2 T13/T15/T23/T24/T25) came back clean or were handled directly. Bottom-up session: your threats are flagged below — see also PHASE-C-HANDOFF.md.

**Act on at grill time (retitle / reframe):**

- [x] ~~**T10 — Approval Link Phishing** (bottom-up Batch 5): instance = fake approval-link email → credential-capture page. Invariant = **approver auth rests on phishable, replayable factors** (password + TOTP typed into a page), so *any* capture channel (phishing link, AiTM relay, lookalike domain) harvests reusable factors; only phishing-resistant auth (WebAuthn/FIDO2, origin-bound) closes it. Rec: retitle+reframe toward "Phishable Approver Authentication," approval-link email as one instance. Confidence med-high.~~ **APPLIED (Batch 5, 2026-07-02):** retitled as recommended; #129 filed for the WebAuthn closer.
- [x] ~~**T16 — SMTP Channel Attack** (bottom-up Batch 5): instance = interception/injection on SMTP. Invariant = the proxy funnels security-relevant secrets (enrollment + approval links) through an **out-of-band notification channel it can't authenticate end-to-end**; its own Apprise multi-backend planned line (SMS, push, webhooks) re-inherits the threat per channel. Rec: retitle+reframe "Notification-Channel Interception," SMTP as the primary MVP instance. Confidence med.~~ **APPLIED (Batch 5, 2026-07-02):** retitled as recommended; #20 reframed as per-channel re-inheritance.
- [x] ~~**T20 — AES-256-GCM Nonce Exhaustion** (top-down Batch 4): instance = the 2^48 exhaustion bound. Invariant = **nonce-uniqueness**; the dominant, far-likelier failure is IV *reuse* from an implementation bug, which the exhaustion framing buries. Also overlaps T17 (one of its five bullets is "AES-GCM IV reuse"). Rec: reframe around nonce-uniqueness/reuse (exhaustion as one sub-case) AND reconcile scope vs T17 (detailed expansion of a T17 bullet, or fold in). Confidence med.~~ **APPLIED (Batch 4, 2026-07-02) — resolved as fold-in.** Post-reframe, T20's content *is* T17's IV-uniqueness invariant row (structural fresh-IV generation, pinned by `test_invariant_4`; exhaustion bound one sentence, unreachable at MVP usage). Merged into T17, tombstoned, deleted + renumbered in Phase D alongside T7. Grill also generalized **T23 → "Cryptographic Side-Channel Leakage"** (not a sweep finding — user-driven): correct-code residual side channels as T17's complement, three-instance table incl. the live login-short-circuit username-enumeration timing oracle (`verify_credentials` skips bcrypt for unknown users; accepted, wash vs public pypi.org identities).
- [x] ~~**T7 — TOTP Secret Exposure** (top-down Batch 3, merging into T5): instance = TOTP secret stored plaintext. Invariant = any secret the proxy must use without the user present cannot be password-wrapped…~~ **APPLIED (Batch 3, 2026-07-02).** Merged into T5, tombstoned. Invariant **refined in grill**: the finding's framing was slightly off — TOTP *can* be password-wrapped (login always presents the password), so the real invariant T5 now states is "**a credential at rest survives a DB read only if one-way-hashed or wrapped under a key the reader lacks**; TOTP is the sole credential that is currently neither, and #122 wraps it under the password-derived key." Not "server-usable without the user."
- **T21 — CSRF on Approve/Deny Form** (bottom-up Batch 6): instance = CSRF on the approve/deny POST. Invariant = **browser-borne coercion of the approval action** (CSRF + clickjacking/UI-redress — the body's "no iframe" operator note is already a clickjacking control, wider than CSRF). Note: architecture already defuses classic CSRF (fresh password+TOTP per vote = no ambient cookie to ride), so residual is small. Rec: body generalization note (CSRF → browser-borne approval coercion); retitle optional. Confidence med.

**Soft notes (borderline; body one-liner at most, not a retitle):**

- **T2 — Compromised Approver as DoS** (bottom-up Batch 7): "(Deny Button)" ties it to a UI element; the invariant is a **single approver's unilateral veto over quorum availability** (active deny + flapping + passive withhold T3). Body note + cross-link T3; title can stay.
- [x] ~~**T8 — Approval Link Replay** (bottom-up Batch 5): already thorough; optional note that the residual invariant is "captured auth material replayable within its validity window," not link-specific.~~ **APPLIED (Batch 5, 2026-07-02):** promoted beyond the soft note — grill adopted the invariant as the title (**Captured-Credential Replay**).
- [x] ~~**T9 — Enrollment Link Interception** (bottom-up Batch 5): shares the "bearer token over a channel the proxy can't secure" invariant with T8/T10; enrollment is the highest-severity instance (pre-identity takeover). Body note.~~ **APPLIED (Batch 5, 2026-07-02):** Scope paragraph carries the family invariant + highest-severity-payload framing.
- **T18 — Supply Chain on the Proxy** (bottom-up Batch 8): title is fine; the ATT&CK/defenses narrow to Python-dependency poisoning — invariant is "any upstream code entering the proxy's TCB" (base image, build/CI toolchain, install source). One-line body generalization.

**Clean (no action):** T1, T3, T4, T5, T6, T11, T12, T14, T17, T19, T22, T26, T27.

## Phase C-verify findings (2026-07-02) — ADJUDICATED 2026-07-03 (grill), all applied

The four tag-axis subagents ran 2026-07-02; 17 raw flags dedupe to the items below. **What came
back clean:** frontmatter field order 28/28 active files; all structural gates pass (introduced ⇒
baselines N/A; inherited ⇒ bucket N/A + equal likelihoods, T23 sole entry; improved ⇒ strictly
better on ≥1 axis for T1/T19/T26); 43 of 44 cited test names exist in `tests/`; the
empty-`attack:` considered verdicts, weak-fit caveats, and link-lifecycle tag division of labor
all hold; no file tags T1657. **All 17 items below adjudicated in the 2026-07-03 grill and
applied** (per-item outcomes inline); landed as one adjudication commit before Phase D.

### Mechanical fixes (apply as-is unless vetoed)

- [x] **M1 — T17:** cites `test_decrypt_fails_on_tampered_blob`, which doesn't exist. The real test is `test_decrypt_fails_when_ciphertext_is_tampered` (`tests/core/test_crypto.py`). Fix the name.
- [x] **M2 — T26:** the only bucket-① threat naming zero tests — the evidence exists (`test_a_denied_request_never_reaches_pypi`, `test_quorum_reached_only_at_the_threshold`, `test_a_revoked_token_is_rejected`, `test_a_token_of_an_inactive_user_is_rejected`). Name them.
- [x] **M3 — taxonomies.md:** still endorses the globally banned T1657 in its shortlist row and judgment-calls bullet — a Phase B cross-cutting todo that never got done. Strike it.
- [x] **M4 — T9:** the gloss of T1586.002 misstates the technique (it's Resource Development — compromising email accounts *to operate from*, not inbox harvesting). Fix the gloss and add the standard weak-fit caveat.
- [x] **M5 — T8/T9/T10/T16:** carry issue-backed planned defenses as a summary-table *row* instead of the `## Planned defenses` section the convention requires (content compliant — #30/#128/#129/#20 all cited with impact). Hoist into proper sections.
- [x] **M6 — T15 + T16:** the #125 entry (T15) and #20 entry (T16) never state bucket impact. Add the explicit "no bucket change" clause to each.

### Judgment calls (recommendation recorded; decide in the main thread)

- [x] **J1 — T6 + T28 likelihood.** [ADJUDICATED: both re-rated `medium`; body sentences corrected to claim the default, not a deviation.] Both say "low (the L5 default)" — but the L5 default is **medium**, and their only justification ("a deep capability") re-describes the rung, which the band already prices in. T11's low has a real justification (narrow time window); these don't. **Recommend:** re-rate both to `likelihood_residual: medium`.
- [x] **J2 — T1 severity vs. the method doc.** [ADJUDICATED: catalog wins — T1 `high`; eval-plan worked example critical→high, medium rung "(one vote)" struck, high rung gained explicit "genuine but unauthorized vote via a compromised approver" disjunct.] The catalog rates one-corrupted-vote `high` consistently (T1, T8, T10, T21); evaluation-plan.md's worked example says T1 residual is medium, and its medium rung lists "one vote" as an example — while its high rung lists "forged/miscounted vote." The ladder contradicts itself and the catalog picked a side in four separate grills. **Recommend:** catalog wins — T1 stays `high`; amend the eval-plan worked example (critical → high, still strictly improved) and fix the medium rung's ambiguous "one vote" example in the same change.
- [x] **J3 — T12 severity high vs. critical.** [ADJUDICATED: `high` stands; body now engages critical's first disjunct + cross-refs the full-quorum tail to T19. Rule adopted: critical = attacker can publish with no remaining precondition on other approvers; anything still gated on approvers approving caps at high.] The flag is real: a wrongful approval that completes quorum ships an artifact — the critical rung's *first* disjunct, and T11/T19 discount success-probability on likelihood, not severity. But full-quorum fatigue capture requires defeating *m* approvers independently — T19's shape. **Recommend:** keep `high`; strengthen the body to engage the first disjunct explicitly — T12's owned gain is the marginal wrongful vote with the m-of-n backstop standing; cross-ref the full-capture tail to T19. (Alternative: `critical` with likelihood carrying the discount — but that puts fatigue in the catalog's worst matrix cell, above database compromise, which misleads.)
- [x] **J4 — T26 stride.** [ADJUDICATED: retagged `["Spoofing", "Elevation of Privilege"]`.] Its own Category row says "(Requester impersonation)" and sibling T15 (same stolen-bearer shape) tags Spoofing. **Recommend:** `stride: ["Spoofing", "Elevation of Privilege"]`.
- [x] **J5 — T25 attack.** [ADJUDICATED: retagged `[T1110, T1499.003]` + deliberate-parent note.] T1110.001 is password *guessing*; the body guesses TOTP codes and explicitly rules password-guessing out. No sub covers online OTP guessing. **Recommend:** retag to parent — `attack: [T1110, T1499.003]` with a deliberate-parent note (T27 precedent).
- [x] **J6 — T28 attack.** [ADJUDICATED: `[T1070]`; T1562.001 dropped with a considered-and-dropped note pointing at T4.] T1562.001's gloss (disable the audit-writing path) is proxy code, unreachable at L5 — T4 territory; the narrated behavior is fully covered by T1070. **Recommend:** `attack: [T1070]`, drop T1562.001.
- [x] **J7 — T4 attack.** [ADJUDICATED: retagged `[T1003, T1005]`; T1552 dropped with a considered-and-dropped note pointing at T5.] T1552 is credentials *at rest*; the body narrates live memory scraping, which the shortlist itself assigns to T1003. **Recommend:** `attack: [T1003, T1005]`.
- [x] **J8 — T22 attack.** [ADJUDICATED: retagged `[T1589.003]`; roles/quorum-count remainder noted as prose.] A sub-technique exists for the narrated asset (employee names). **Recommend:** retag T1589 → T1589.003, with the roles/quorum-count remainder noted in prose.
- [x] **J9 — T5 attack.** [ADJUDICATED: `[T1005, T1552.001, T1110.002]` + offline/online division-of-labor note vs. T25.] The body's whole severity story hinges on offline bcrypt cracking, and the shortlist gloss already anticipated tagging it. **Recommend:** add T1110.002 — `attack: [T1005, T1552.001, T1110.002]`.
- [x] **J10 — T24 eval-plan staleness.** [ADJUDICATED: eval-plan inherited worked example swapped to T23; T24's SPOF-narrowing sentence tightened to the counted-once cross-ref pattern.] The eval-plan's inherited worked example still describes pre-reframe T24, which is now `introduced`. **Recommend:** swap the worked inherited example to T23 (now the sole inherited entry) and tighten T24's "reduces recovery SPOFs" sentence to the counted-once cross-ref pattern. Folds into J2's eval-plan edit.
- [x] **J11 — T21 bucket ① with a live ③ leg.** [ADJUDICATED: no change; carry to Phase D — codify in CONTRIBUTING the per-leg headline-bucket rule AND the J3 critical-severity rule (critical = attacker publishes with no remaining precondition on other approvers).] Flagged asymmetry vs. T9 (③ headline despite ①-grade legs) — but both files follow the same implicit rule: **headline = the primary leg's bucket** (T21's primary leg is CSRF, demonstrated ①; T9's is interception-prevention, operator ③). **Recommend:** no change; codify the per-leg headline rule in CONTRIBUTING during the Phase D delta pass.
