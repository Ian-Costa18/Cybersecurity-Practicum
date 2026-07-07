# Contributing to the threat model

How to read, edit, and extend the threat catalog in this directory. This guide is the
**operational contract** — the field-by-field rules and the recipes for keeping the catalog
honest as the system evolves. It distills the process used by the #107 deep-dive.

**Authority pointers** (on conflict, these win — this guide condenses, it does not redefine):

- Classification *method* (delta, buckets, likelihood/severity): [`docs/evaluation-plan.md`](../evaluation-plan.md), §"Security" and §"Risk rating — likelihood and severity".
- Tag *vocabulary* (STRIDE, MITRE ATT&CK Enterprise, version pins, in-scope technique shortlist): [`taxonomies.md`](taxonomies.md).
- The adversary capability ladder (L1–L9): [`00-overview.md`](00-overview.md).

**Scope.** The threat model's world is the **package-publishing use case** (self-hosted proxy
holding a PyPI API token, publishing after m-of-n approval). General-purpose /
forward-auth deployment is future vision (#109) and appears only as explicitly-marked
future-vision mentions — never as first-class threat surface.

## Tooling

Don't hand-read the catalog when a query will do. The `threat_model` tool (issue #130) reads
these files through the very contract this guide defines — so it is the fastest way to slice
the catalog and the mechanical check that your edits still satisfy the rules below. Run it
standalone from a repo checkout — `uv run tools/threat_model.py …`, no virtualenv needed.
(It is dev tooling, not an installed console command: it reads these catalog files, which
the wheel never ships.)

- **Query / read** (AI-usable, JSON by default): `uv run tools/threat_model.py query attack=T1078 --only id,title`.
  Filters AND across distinct keys / OR within a repeated key; `attack=` is prefix-aware
  (`T1078` also matches `T1078.001`); `--only` projects any mix of frontmatter fields,
  anatomy-row slugs (`gains`, `cannot`, …), and `##`-section slugs; `-H` switches to Markdown.
  `sections [ID]` lists a threat's section slugs (omit the ID for a catalog-wide map).
- **Validate** — `uv run tools/threat_model.py validate` mechanizes this contract: field presence + order,
  enum values, the `N/A` rules, group-prefixed id integrity, `related` symmetry, and the
  semantic cross-checks (`improved` ⇒ baseline worse; `inherited` ⇒ likelihoods equal).
  **Run it before committing any catalog edit.** It also runs in the pytest suite, so drift
  fails CI. (This is exactly the check that caught the renumber's broken `related` reciprocals.)

---

## Catalog anatomy

- One file per threat: `<PREFIX>-<n>-<slug>.md` — e.g.
  `CORE-1-single-approver-account-compromise.md`. The frontmatter `id:` is the same handle
  without the slug: `id: CORE-1`.
- IDs are **group-prefixed**. The catalog is organized into nine thematic groups, each with a
  short prefix and its own independent numbering, presented in this narrative order:

  | Prefix | Group |
  |---|---|
  | `CORE` | The core guarantee — threats the proxy measurably *improves* over the baseline |
  | `IDENT` | Approver identity & the authentication surface |
  | `VOTE` | The approval session & the vote itself |
  | `HOST` | The proxy host, database & records |
  | `CRYPTO` | Cryptography |
  | `PUB` | The publish boundary / mediation |
  | `DOS` | Availability & abuse |
  | `CODE` | The proxy's own code & supply chain |
  | `INFO` | Residual information disclosure |

  Within a group, threats are ordered **most-severe first**. The one exception is `CORE`,
  ordered thesis → residual: the flagship (`CORE-1`) opens the catalog, and the accepted
  limit of the *quorum* improvement (`CORE-3`, insider collusion) closes that arc. `CORE-4`
  (authorization repudiation) is appended after it by the append-only numbering rule, but
  reads as a distinct leg — the accountability guarantee, not the quorum residual — and its
  low×low residual sorts it last in the most-severe-first overview listing regardless.
- `00-overview.md` is the **navigator** — catalog tables, delta cut, bucket distribution,
  risk matrix, scope statement. It duplicates no methodology; it points here.
- **The catalog is append-only within a group.** A new threat takes the next free number
  under its group's prefix (`IDENT-6`, `HOST-5`); a genuinely new theme earns a new prefix.
  This is the point of the scheme — adding or retiring a threat touches at most its own
  group (≤5 files), never the whole catalog, so a change is cheap and local. Any ID change
  still carries a full repo-wide reference sweep in the same change
  (`grep -rnE '\b(CORE|IDENT|VOTE|HOST|CRYPTO|PUB|DOS|CODE|INFO)-[0-9]'` across docs, src,
  tests). Retiring a threat leaves a gap in its group, or — since a group is small — you may
  renumber just that group to close it.
- Retitling a threat renames its file → sweep every reference in the same change.

## Frontmatter contract

Field order is fixed. Ordering is semantic: `delta` precedes the rated pairs and `bucket`
because it **gates** them.

```yaml
id: CORE-1
title: "..."
stride: [...]          # STRIDE categories violated
attack: [...]          # MITRE ATT&CK Enterprise technique IDs
capability: [...]      # attacker's required position (L1–L9, or external)
delta: improved|inherited|introduced
likelihood_baseline: high|medium|low|N/A   # N/A iff delta: introduced
likelihood_residual: high|medium|low
severity_baseline: critical|high|medium|low|N/A   # N/A iff delta: introduced
severity_residual: critical|high|medium|low
bucket: 1|2|3|4|N/A                        # N/A iff delta: inherited
related: [...]         # symmetric cross-references
tests: [...]          # backing pytest node ids; optional, but required iff bucket: 1
```

| Field | Allowed values | What it answers |
|---|---|---|
| `stride` | `Spoofing`, `Tampering`, `Repudiation`, `Information Disclosure`, `Denial of Service`, `Elevation of Privilege` | Which security property is violated? |
| `attack` | ATT&CK Enterprise technique IDs (`Txxxx[.xxx]`), possibly `[]` | What adversary behavior does this operationally map to? |
| `capability` | `L1`–`L9` (ladder in [`00-overview.md`](00-overview.md)), or `external` | What position must the attacker already hold? |
| `delta` | `improved` \| `inherited` \| `introduced` | How does this threat relate to the direct-publish baseline? |
| `likelihood_*` | `high` \| `medium` \| `low` (+ `N/A` for baseline) | How demanding is the precondition? (baseline / residual pair) |
| `severity_*` | `critical` \| `high` \| `medium` \| `low` (+ `N/A` for baseline) | How bad is the outcome on the mission ladder? (baseline / residual pair) |
| `bucket` | `1` \| `2` \| `3` \| `4` \| `N/A` | What is the mitigation posture **today**? |
| `related` | Threat IDs | Which threats share a boundary with this one? |
| `tests` | pytest node ids (`tests/…::test_…`), optional | Which tests execute this threat's defense? |

### `stride`

One or more of the six categories, chosen against the body's **"what the attacker gains"**
row — tag the property actually violated, not every property brushed in passing.

### `attack`

MITRE ATT&CK Enterprise technique IDs (version pinned in [`taxonomies.md`](taxonomies.md)).
Conventions:

- Tag only techniques describing the attacker's **operation against this system's surface**.
  Prefer the sub-technique where one exists.
- **Downstream consequence is prose, never a tag.** The supply-chain outcome consumers
  experience (T1195.002) is discussed in body prose; it is not what the attacker does *to
  the proxy*. T1657 (Financial Theft) is never used.
- **Weak fit → tag + caveat** (CRYPTO-2's `T1040` pattern): when a technique is defensibly
  close but imperfect, keep the tag and state the imperfection in the body.
- **No fit → `attack: []` + a one-line body note** ("no Enterprise technique maps to …;
  nearest concepts discussed in prose"). Used where ATT&CK simply has no slot — e.g.
  passive withholding (DOS-4), implementation bugs and cryptographic limits (CRYPTO-1).
  Never force a tag to avoid an empty list: a false mapping poisons the #111 ATT&CK table.

### `capability`

The attacker's **required starting position** — definitional, not rated (its rated
counterpart is `likelihood_residual`). Values: `L1`–`L9` from the overview's ladder, plus
one sentinel:

- **`external`** — the attacker operates entirely outside the deployment's trust boundary
  (e.g. CODE-2: compromising an upstream dependency). No L-level applies and **no default
  likelihood applies** — the body must state and justify its own likelihood.

Possession of a single leaked credential (proxy API token, an out-of-band PyPI credential)
is **L2** — the ladder's "single commodity credential theft" class — with the specific
credential named in the body's capability row.

### `delta`

Relationship to the **direct-publish baseline**: a maintainer publishing to PyPI with an
API token + account 2FA, no proxy.

- **`improved`** — pre-existing threat the proxy measurably reduces. Feeds the value proposition.
- **`inherited`** — pre-existing authentication-layer threat the proxy leaves unchanged.
  Forces `bucket: N/A`; reported once as a scope statement, never counted as a proxy weakness.
- **`introduced`** — surface that exists only because the proxy exists. Forces both
  `*_baseline` ratings to `N/A`. The honest cost ledger.

**The net-cancellation rule.** Delta is a **net** measure, not a gross surface count. Both
worlds must run an authentication layer (baseline: PyPI login/2FA/sessions/reset; proxy:
its own equivalents), so auth-layer threats appear on both sides of the ledger and **cancel
when our instance is standard-practice-equivalent** → `inherited`. Cancellation **breaks**
when we deviate below standard practice or make a novel design claim → owned (`introduced`
/ `improved`). *A surface being new doesn't make a threat introduced; the threat failing to
cancel against the baseline's equivalent does.*

**Membership vs. delta.** "Does the attack apply to this system's surface?" decides whether
the threat is **in the catalog** (inherited threats stay, as slim entries — "considered"
must be distinguishable from "forgotten"). "Does the proxy change it vs. the baseline?"
decides **delta**. Don't conflate them.

### `likelihood_*` and `severity_*`

Two rated axes, each a **baseline/residual pair** (authoritative:
[`evaluation-plan.md`](../evaluation-plan.md) §"Risk rating"). *Baseline* = the equivalent
attack in the direct-publish world; *residual* = under the proxy's **current design** —
what is built, not what is planned. **Never compute a composite risk score** — the
(likelihood, severity) cell is the risk statement.

**Likelihood anchors to the precondition.** Default residual reads off `capability`;
deviations are allowed but must be justified in the body:

| `capability` | Default residual likelihood |
|---|---|
| L1–L2 | high |
| L3–L5 | medium |
| L6–L9 | low |
| `external` | no default — justified per-threat |

**Severity anchors to the mission outcome ladder** (mission: prevent an unauthorized
package reaching PyPI), read off "what the attacker gains": **critical** = the attacker
can publish with **no remaining precondition on other approvers** — an unauthorized artifact
reaches PyPI, or durable publish-at-will · **high** = authorization input corrupted but ≥1
independent barrier stands; *anything still gated on other approvers independently approving
caps here, no matter how many must fail* · **medium** = security-relevant loss that moves no
publish decision (evidence loss, non-credential disclosure, one bounded action) · **low** =
availability, fails safe.

**Cross-checks** (enforced by review): `improved` ⇒ baseline strictly worse on ≥1 axis ·
`inherited` ⇒ likelihoods equal (severity may differ — containment is credited to the
improving threat once, cross-referenced) · `introduced` ⇒ baselines `N/A`.

### `bucket`

Mitigation posture, **owned threats only** (`improved` + `introduced`):

1. **Executably demonstrated** — an automated adversarial test drives the attack and
   asserts it fails. Two tiers, labelled in the body: *black-box* (driven at the HTTP edge;
   oracle: the PyPI mock is never invoked) and *integrity/detection* (asserted at the
   crypto/DB layer; oracle: verification fails / the alarm fires — detection counts,
   tamper-evident ≠ tamper-proof).
2. **Argued by design** — reasoned mitigation, not script-drivable.
3. **Operator-enforced** — the system cannot defend it; config/topology can.
4. **Accepted limitation** — documented, deliberate boundary.

**The bucket records what is true TODAY** — the honest-audit stance. A designed defense
that hasn't landed does not raise the bucket; it goes in the threat's **Planned defenses**
section (below) with its tracking issue, and the bucket is raised **when the issue closes**.
Ratings and buckets must be allowed to produce non-flattering answers, or they are
worthless as evidence.

**Per-leg buckets.** A threat whose legs fall in different buckets takes its **primary
leg's** bucket as the headline `bucket:`; the minority legs are stated per-leg in the body,
not averaged into a single blended figure (the VOTE-3 / IDENT-2 pattern — a primary leg with
a distinct secondary leg carrying its own posture and its own promotion path).

### `related`

Threats sharing a boundary (same surface, same defense family, one absorbs the other's
residual). **Symmetric by construction**: adding `IDENT-5` to `CORE-1`'s list means adding `CORE-1` to
`IDENT-5`'s list in the same change.

### `tests`

The pytest node ids — `tests/<path>.py::<test_name>` — of the tests that **execute this
threat's defense**. List **every** test the body cites for this threat, whatever its bucket
(a ② threat's supporting tests belong here too, not just ①'s demonstrating ones). Optional:
a threat that cites no test omits the field.

This is the machine-checkable half of the audit — the [Tooling](#tooling) validator resolves
every entry to a real file **and** a real `def`, so renaming a cited test fails CI until the id
is fixed (it runs in the pytest suite). It is why the test-to-threat map lives here, in
frontmatter, rather than in a separate document that silently drifts.

- **Gate:** `bucket: 1` (executably demonstrated) **requires** at least one entry — a
  demonstrated claim with no backing test is a contract violation.
- The field is a list, so `uv run tools/threat_model.py query tests=<node-id>` finds every threat a given test
  backs, and `--only tests` projects it. Cite the test in the body's **Current defenses** row as
  well (prose); the frontmatter is the queryable index, the body is the argument.

---

## Body layout

```markdown
# <ID> — <Title>

| | |
|---|---|
| **Category** | <STRIDE, restated> |
| **Capability** | <L-level + one-line concrete meaning> |
| **What the attacker gains** | … |
| **What they cannot do** | … (by design — the containment argument) |
| **Current defenses** | HONEST audit: what is built and tested *now*; cite test names |
| **Operator configuration** | what deployment/config must enforce |

<prose sections as needed: delta story, residuals, boundary notes>

## Planned defenses

- **<defense>** — #<issue> — <bucket impact: "promotes ③ → ① (detection tier)" | "no bucket change">
```

Rules for the body:

- **Current defenses is an audit, not an aspiration.** Name the tests that exist
  (`tests/…::test_name`); if a spec promises something unimplemented, it is *not* a current
  defense. Cite specs for design-level defenses.
- **The `Planned defenses` section is the only home for future work**, and every entry
  **must** cite a live GitHub issue (the only-issues rule — no work items, no vague
  "should add X"). An entry that would change the bucket states the target bucket + tier.
  Deliberate non-commitments (named-but-unplanned ideas, e.g. CODE-2's release signing /
  reproducible builds) stay in prose as explicitly-marked mentions — they do **not** get a
  Planned defenses entry.
- Threats with no planned work simply omit the section.
- The **improved** threats carry the delta story in prose: what the baseline attacker got,
  what the proxy-world attacker gets, which axis improved.

## Lifecycle recipes

**Adding a threat.** Append within the threat's group — take the next free number under its
prefix (`IDENT-6`, `HOST-5`); a genuinely new theme earns a new prefix. Apply the membership test
(does it apply to this surface?), then the full frontmatter contract in order. Write the
body per the layout above. Add `related:` links **in both directions**. Add the row to
`00-overview.md`'s tables. Then run `uv run tools/threat_model.py validate` — it catches a one-directional
`related` link, a mis-ordered field, or an `N/A`-rule slip before you commit.

**Landing a planned defense.** When the issue closes: move the entry from Planned defenses
into Current defenses (now citing the real test/mechanism), **add the new test's node id to
`tests:`**, raise `bucket` to the stated target, re-derive
`likelihood_residual`/`severity_residual` if the defense changed them, and update the
overview's distribution/matrix. One commit per threat is fine. Run `uv run tools/threat_model.py validate`
before committing — it will reject the bucket-① promotion if `tests:` is still empty, or if the
node id you added doesn't resolve.

**Merging / retiring a threat.** Absorb the surviving content into the absorbing threat (the
absorbed threat's "gains" become line items). Delete the file and repoint **every**
reference — docs, code comments, tests. Because groups are small and independently numbered,
you may renumber just the affected group to close the gap, or leave the gap; either way the
blast radius stays within the one group. Run `uv run tools/threat_model.py validate` afterward to confirm no
`related` link now dangles (id↔filename mismatch and broken symmetry are exactly what it catches).

**Changing the method.** Don't do it here — the method lives in `evaluation-plan.md`.
Change it there first, then update this guide and the affected threat files in the same
change (the repo's same-change spec rule).
