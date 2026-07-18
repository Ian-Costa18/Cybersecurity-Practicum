<!-- LTeX: enabled=false -->
# Bibliography deep-dive — research process

How each **cluster of references** in [`references.bib`](../../../references.bib) goes from a bare
BibTeX stub to a **knowledge-store note** the final report can be *assembled from* — so that writing
§3, §4, §6, and §7 is *retrieval over vetted material*, not research-while-writing.

This is the sibling of [controls-matrix/research-process.md](../controls-matrix/research-process.md).
That process is **tight and verdict-driven** (one matrix row → four fixed cell verdicts, defended).
This one is **broad and knowledge-driven**: the output is a durable, quotable store of facts, not a
scorecard. The shape of each note is chosen per topic, not fixed in advance.

One topic at a time, six phases: **ground → hunt → grill → write → verify → compact.** When the whole
queue is done, a single **finalize** grill sweeps the store clean (see *Finalize*, after the phases).

## What this covers — and what to reuse rather than redo

This process owns everything the report will cite. But a lot of the reading is **already done** —
reuse it, do not redo it:

- **The §4 positioning controls** each have a defended note under
  [controls-matrix/](../controls-matrix/). Those notes are **matrix-cell-focused** (four verdicts),
  which is *thinner* than knowledge-store depth for the report prose. So the controls come back
  through this process as a **deepen-and-tag pass** (`↳CM` in the queue): keep the fixed verdicts,
  add the report-facing facts/quotes the prose needs, then tag the bib entries. Do **not** re-argue
  the verdicts.
- **Design-time research already in the repo** ([docs/research/](../../../../docs/research/index.md)):
  the crypto learning-records (Ed25519, PBKDF2, AES-256-GCM, bcrypt) and the threshold-signature
  notes (FROST, MuSig2, GG20, DKLS, MPC graphs) already exist with local source PDFs. The crypto
  buckets **consolidate and verify** those into a report/appendix note — they are not fresh reading.
  [Broad Literature Review.md](../../../../docs/research/Broad%20Literature%20Review.md) and
  [PyPi Use Case Research.md](../../../../docs/research/PyPi%20Use%20Case%20Research.md) are
  starting points for the incident-landscape and positioning buckets.

These two trees point at each other: [docs/research/index.md](../../../../docs/research/index.md)
has a *Report-facing evidence store* section linking here, and this process reuses that tree rather
than duplicating it — so neither home hides research from the other. `docs/research/` stays the
single home for the underlying reading; these notes **cite** it.

The genuinely-new reading is the two marquee incidents, the incident landscape, and the methodology
buckets. Full map in the **Topic queue**.

## Design principles — what makes this a reliable source of truth

Drawn from current practice on knowledge stores for AI-assisted research (sources at the bottom).
The point of the store is that **a fact is looked up once and never re-derived from the web**.

1. **Provenance anchors *citable facts*.** A fact the report will cite as a claim must carry a
   **verbatim quote** with a **URL/DOI + section-or-page anchor + access date** before it counts as
   load-bearing. The evidence-log shape is *Claim → Source → Exact quote → Context (scope, method,
   limits)*. **Your own synthesis, connective analysis, and context are welcome and are most of the
   store's value** — they are simply marked as synthesis, not passed off as sourced facts. The rule
   is not "no paraphrase"; it is "a claim the report leans on needs an anchor behind it."
2. **Compile up front.** Do the heavy reading and extraction now, while the source is open, so
   report-time is cheap retrieval. Long verbatim excerpts are **welcome** — this is a store, not a
   summary. Quote generously; mark every quote as a quote.
3. **Claim-linked.** Each note's front matter names the **report claim / outline section** it
   supports ([outline.md](../../outline.md): §3 incidents, §4 positioning, §6 security, §7
   discussion, Appendix). A fact with no report home is flagged, not silently kept.
4. **Grounded in what the proxy actually does.** Before researching a topic, read the proxy's own
   authoritative docs for it (pointers per bucket in the queue) so the note stays tied to real
   behavior — not a generic literature dump.
5. **Freshness is explicit.** Access dates on everything; when a newer/more-authoritative source
   supersedes an older one, the note says so and the older one is downgraded to context, not
   deleted silently.
6. **Only cite what was actually retrieved this session.** No citation from memory. If it could not
   be opened and quoted, it is a gap (see **Gaps** below), not a fact.

## The six phases (per topic)

### 1 — Ground

Read the **outline claim(s)** this topic serves, the proxy's own docs for it, and any **existing
repo research** (bucket pointers in the queue). Pull the topic's current `references.bib` stubs.
Look facts up from the **primary source** — never ask what can be looked up.
*Complete when:* the report claim(s) this topic carries are written down, the proxy-side grounding
and existing repo research are read, and the existing bib stubs are open.

### 2 — Hunt

Actively search for **better sources than the stubs we have**: a formal paper behind a blog post; a
later source that supersedes an early one written before the attack was understood; the primary
disclosure behind a secondhand write-up; a standards doc behind a vendor page. Note candidates with
why they're better. This is where the store gets *upgraded*, not just filled.
*Complete when:* each existing stub is judged keep / replace / supplement, and any new candidate is
named with a one-line reason.

### 3 — Grill

Run a [`/grilling`](../../../../../.claude/skills) session on **how this topic is used in the
report**: the exact claim it carries, how the proxy *relates to / improves on / honestly does not
beat* it, and which facts are load-bearing versus color. Settle the obvious calls; **stop only on
genuine forks** — one question at a time, in prose, each with a recommended answer. This is where
deep understanding is forged, so the reader can write the section cold afterward. Do not write the
note until understanding is shared.
*Complete when:* the topic's role in the report is agreed in one or two sentences, and the
proxy-relation line is settled (including any honest "does not beat this").

### 4 — Write

Write the topic note to the template below with `status: draft`, then **land its bib entries in the
same session** — this process touches the bibliography directly, so there is no deferral and no later
bib-landing step. For each source, **you MUST add the `references.bib` entry by invoking the
[`add-reference`](../../../../.agents/skills/add-reference/SKILL.md) skill** — do not hand-write the
BibTeX. The skill is the only sanctioned path in: it enforces the rules an ad-hoc edit skips (verify
every field against the live page, archive the source to `.references/`, dedupe the key and URL).
Hand-authored entries are the exact failure that prompted this instruction. If you delegate the
mechanical work to a **Sonnet subagent**, the subagent's task is *"invoke the `add-reference` skill
for this source,"* not *"format a BibTeX entry."* After the skill lands the entry, add a
`% RESEARCHED` tag above it (see *Conventions*).
There is no separate preview gate — the grill already settled the shape, so write the real note and
let the reader react to it, not to a table.
*Complete when:* the note exists as a `draft`, and every source it cites is a tagged `references.bib`
entry.

### 5 — Verify

The reader reads the finished draft end to end and reacts — what lands, what does not, what to change.
Revise with them until it holds up, then flip the front matter to `status: vetted`. This is the human
gate: concrete reaction to the actual note, and it is what gives the `status` field meaning
(`draft` = written, not yet read; `vetted` = the reader has signed off).
*Complete when:* the reader is satisfied and the note is `status: vetted`, **and the Topic queue is
updated** — check off this topic, mark the next `← next`, and record any new gaps.

### 6 — Compact

**Compact the context before starting the next topic.** Each note is self-contained and the queue is
the handoff, so a compacted (or fresh) agent resumes cleanly. Do not carry one topic's sources into
the next topic's window — it is wasted budget and cross-contaminates grounding. (Returning cold?
Start a fresh session pointed at this file; the queue tells it where to resume. The `handoff` skill
is only needed if you stop *mid-topic* with reasoning not yet written to the note.)

---

## Finalize — the closing grill (once, when the queue is done)

Everything above is per-topic. This runs **once, after the last topic is `vetted`** — a single
[`/grilling`](../../../../../.claude/skills) session across the *whole store*, so a cold report-writer
can assemble §3–§7 from it without ever tripping over how it was built. Three jobs.

**1 — Sweep the construction breadcrumbs.** Cut every reference to *how the store was built* that a
report-writer does not need: dangling threads to sources already dropped, work "moved out of / parked
from" another bucket, "widened to," "demoted," now-resolved issue numbers, `← next` and dated status
notes left on finished topics, and any "an earlier draft said X" residue. The store should read as if
it always said what it says now. **Two things are not breadcrumbs and stay:** (a) a `## Source
decisions` mini-ADR whose reasoning a future reader still needs, and (b) a substantive source-standing
note that a source is superseded / kept as context only (design principle 5 — it tells the reader
which source to trust, so it is content, not scaffolding). The grill makes the keep/cut call per item;
neither blanket-delete nor blanket-keep.

**2 — Resolve every open thread.** No note ships with a live *Open threads / to verify* section. Each
item is either anchored (promoted into *Key facts* with its quote), explicitly dropped with a one-line
reason, or escalated into the **Gaps** list. Empty the section or delete it.

**3 — Audit each fact against its source.** For every *Key facts* entry, re-open the cited source and
confirm the verbatim quote is actually there and says what the note claims — the anti-hallucination
double-check that everything in the facts section is genuinely stated by what it cites. A quote that
cannot be re-confirmed in its source this pass is pulled from *Key facts* and treated as a gap, not
shipped.

Settle the obvious cuts yourself; stop the reader only on a genuine "is this breadcrumb load-bearing?"
fork — one question at a time, in prose, each with a recommended answer.
*Complete when:* no note carries a stale construction breadcrumb or an unresolved open thread, every
*Key facts* quote has been re-confirmed against its source this pass, and the Topic queue's own
scaffolding (`← next`, dated per-topic status notes) reads as a finished record, not a work log.

### Review checkpoint

The closing review has completed the breadcrumb sweep and resolved the live open threads. The source
notes are ready for the remaining fact audit, which is intentionally separate and still pending. Do
not treat the evidence store as fully finalized until every *Key facts* quote has been re-confirmed
against its cited source.

---

## Note template (flexible — bend it to the topic)

Metadata is **YAML front matter** (machine-readable, greppable, consistent). The body is a
knowledge-store, not a scorecard — sections are *typical*, not mandatory; a crypto note and an
incident note will differ. What is **non-negotiable**: every citable fact has an anchored quote, and
the front matter names the report home.

```markdown
---
bucket: I1                       # queue id
title: Shai-Hulud npm worm (2025)
report_home:
  - "§3 — Background case study (marquee)"
  - "§4 — Stolen-credential column anchor"
proxy_grounding:
  - docs/threat-model/
  - research/controls-matrix/ctrl-mandatory-2fa.md
related_notes:
  - controls-matrix/ctrl-mandatory-2fa.md
bib_keys: [shai-hulud-cisa, shai-hulud-unit42]
status: draft                    # draft | vetted
---

## Why the report needs this
<2–4 sentences: the argument this topic supports, and how the proxy relates to it — improves on,
depends on, or honestly does not beat. Synthesis is fine here; mark it as such.>

## Sources (vetted this session)
- <title> — <URL/DOI> (accessed <date>) → `<bib-key>`  · <what it anchors> · [primary | formal | context]
- <superseded/weak source, kept as context only, with the reason>

## Key facts (anchored)
### <fact / sub-claim>
> "<verbatim quote>"
— <source, section/page anchor>

<one line: what report claim this fact backs, and any scope/limit on it>

## How the proxy relates
<the honest relation: the structural thing the proxy does that this improves on / the primitive it
reuses / the thing it explicitly does NOT beat. One coherent point, said once.>

## Open threads / to verify
<synthesis or claims not yet anchored — feeds the Gaps list>

## Source decisions <!-- optional: include ONLY if the grill surfaced a non-obvious call -->
<A mini-ADR, not a changelog. Record only a source decision whose reasoning would not be obvious
later: why a source was dropped or preferred over a near-equivalent, or why a plausible avenue was
deliberately not pursued. Omit the whole section when the choices were self-evident.>
```

---

## Topic queue

The completed queue records the coverage of the report-facing evidence store.

### Marquee incidents — §3 Background (deepest treatment, one file each)

- [x] **I1 — Shai-Hulud npm worm (2025)** → `incident-shai-hulud.md`
  - *Report home:* §3 case study; the Stolen-credential column anchor for the §4 matrix.
  - *Proxy grounding:* [docs/threat-model/](../../../../docs/threat-model/) (token-theft threats),
    [ctrl-mandatory-2fa.md](../controls-matrix/ctrl-mandatory-2fa.md) (the token-bypass cell it realizes).
  - *Scope:* token harvest → self-replication → auto-republish under legit identity; which controls
    it walked through.
- [x] **I2 — XZ Utils backdoor / CVE-2024-3094 (2024)** → `incident-xz-backdoor.md`
  - *Finding:* the proxy does NOT beat the review-surviving insider; this is the §3/§4/§7 “not a silver bullet” honesty anchor.
  - *Report home:* §3 case study; the Trusted-insider column anchor for the §4 matrix.
  - *Proxy grounding:* [ctrl-the-proxy.md](../controls-matrix/ctrl-the-proxy.md) Caveat 2
    (review-surviving payload — the XZ shape the proxy does *not* claim immunity to).
  - *Scope:* the trust build, payload hidden in build/test fixtures, SSH-latency discovery, and why
    authentication, authorization, and provenance did not stop it.

### Incident landscape — §3/§4 framing (one note)

- [x] **I3 — Supply-chain incident landscape** → `incident-landscape.md`
  - *Finding:* event-stream and ctx establish the single-actor-publish pattern; Backstabbers’ Knife and the CNCF catalog provide the taxonomy; SolarWinds is used only for the one-line build-pipeline scope boundary.
  - *Report home:* §3 framing ("the cost of the gap" beyond the two marquee cases) + §4 evidence.
  - *Existing research:* [Broad Literature Review.md](../../../../docs/research/Broad%20Literature%20Review.md).
  - *Scope:* enough per incident to cite pattern evidence; Backstabbers’ Knife and the CNCF catalog
    carry the taxonomy framing.

### Methodology — §6 Security + Appendix (two notes)

- [x] **M1 — Threat-modeling & risk-scoring methodology** → `method-threat-modeling.md`
  - *Report home:* §6 net-delta model + methodology justification; Appendix classification table.
  - *Proxy grounding:* [docs/threat-model/CONTRIBUTING.md](../../../../docs/threat-model/CONTRIBUTING.md),
    [evaluation-plan.md §3](../../../../docs/evaluation-plan.md).
  - *Scope:* `cvss-v4` is outside this report-facing bucket because it scores vulnerabilities, not
    baseline-relative design-time threats. The note covers why STRIDE is used for enumeration, why
    the DREAD critique steers us off additive scoring, and how ATT&CK grounds “pre-existing”
    techniques.
- [x] **M2 — Comparative-evaluation & formal-methods frameworks** → `method-evaluation-frameworks.md`
  - *Report home:* §4 (the matrix *is* a comparative-evaluation framework — cite the precedent) and
    §7 limitations (excluded human-subjects usability; formal-verification as future work).
  - *Scope:* the UDS comparative-matrix precedent supports the evaluation framework; usability
    studies support the §7 “usability excluded” limitation, and formal verification remains future
    work.

### Multi-party approval in industry — §4 positioning (one note)

- [x] **P1 — Multi-party approval in industry** → `primitive-multiparty-approval.md`
  - *Finding:* all three hyperscalers ship siloed multi-party controls; Azure PIM’s lack of quorum is the sharpest “under-used” data point. Vault seal/unseal is covered in C1, while Authelia is not the multi-party primitive.
  - *Report home:* §4 Move 3 (industry adoption = the gap is recognized). **§4 only** — this note is
    about the *multi-party-approval primitive*; forward-auth/shared-account generalizability is
    outside this bibliography deep-dive.
  - *Proxy grounding:* [docs/adr/0001-credential-backed-approval.md](../../../../docs/adr/0001-credential-backed-approval.md),
    [evaluation-plan.md](../../../../docs/evaluation-plan.md) Move 3.
  - *Sources:* `aws-mpa`, `aws-backup-mpa`, `google-cloud-pam`, `google-workspace-mpa`,
    `azure-pim-approval`, `azure-backup-mua`, `intune-maa`. The primitive exists and ships across
    all three hyperscalers, but is **siloed** inside each platform's own control plane — reinforcing,
    not filling, the registry gap. Vault seal/unseal belongs with C1; Authelia is single-user
    forward-auth, not the multi-party primitive.
- [x] **P2 — Multi-party authorization as an established primitive** → `primitive-sod-multiparty.md`
  - *Finding:* NIST AC-3(2) codifies two authorized individuals; the proxy generalizes the count and places it on the publish action. The §4 scope boundary is anchored here.
  - *Report home:* §2 Intro thesis (SoD is recognized, not invented) + §4 positioning (recognized,
    under-deployed) + §4 scope-boundary paragraph.
  - *Proxy grounding:* [docs/adr/0001-credential-backed-approval.md](../../../../docs/adr/0001-credential-backed-approval.md),
    [evaluation-plan.md](../../../../docs/evaluation-plan.md).
  - *Sources:* `nist-sp-800-53r5` (AC-3(2) headline + AC-5), `clark-wilson-integrity` (lineage),
    `birsan-dependency-confusion` + `ladisa-sok-supply-chain` (dependency-confusion scope boundary),
    `cisa-esf-developers` (adjacent non-authorization controls). *Finding:* NIST codifies the
    primitive, so the thesis reframes to "under-deployed in registries," not "overlooked."

### Cryptographic choices — System Design §5 / Appendix (one note, consolidate)

- [x] **C1 — Cryptographic choices & rationale** → `primitive-crypto-choices.md`
  - *Finding:* the note consolidates the existing cryptography and ADR material into one anchored line per primitive used and the why-not-threshold argument. Vault seal/unseal provides threshold-cryptography lineage; the remaining threshold-crypto material is appendix context.
  - *Report home:* §5 (the crypto is inherited-secure, not a novel claim) and the **tentative
    Appendix** item *"Cryptographic-choice rationale"* in [outline.md](../../outline.md) —
    credential-backed approval over threshold signatures, chosen for **usability**. Deranked in the
    body — not a large section.
  - *Existing research (primary input):* [docs/research/crypto/learning-records/](../../../../docs/research/crypto/learning-records/)
    (Ed25519, PBKDF2, AES-256-GCM, bcrypt, with local source PDFs) and
    [docs/research/Multi-Sig Authentication/](../../../../docs/research/Multi-Sig%20Authentication/)
    (FROST, MuSig2, GG20, DKLS, MPC graphs).
  - *Proxy grounding:* [docs/adr/0001-credential-backed-approval.md](../../../../docs/adr/0001-credential-backed-approval.md)
    (**the "not threshold signatures, and why" decision**),
    [docs/adr/0003-cryptographic-primitive-selection.md](../../../../docs/adr/0003-cryptographic-primitive-selection.md),
    [docs/cryptography.md](../../../../docs/cryptography.md).
  - *Two jobs, kept small:* (a) one anchored line per **primitive actually used** (Ed25519, AES-GCM,
    SHA-256, HMAC, TOTP, PBKDF2/bcrypt) tying standard → proxy use; (b) the **why-not-threshold**
    paragraph — the threshold-crypto stubs (`shamir-secret-sharing`, `bip11-multisig`, `frost`,
    `musig2`, `gg18`, `gg20`, `dkls18`, `dkls19`, `mpc-expander-graph`) are **context/lineage** for
    that one argument, not implemented tech. Drop any stub neither the code nor the argument uses.
  - *Vault seal/unseal provides the Shamir m-of-n facts (3-of-5 default) for the note’s why-not-threshold lineage, and its bib entry is `% RESEARCHED`-tagged to this note.

### Deepen existing controls-matrix notes — §4 prose (`↳CM`)
The seven [controls-matrix/](../controls-matrix/) notes are matrix-cell-thin. When the report's §4
prose needs more than a verdict from a control, deepen that note to knowledge-store depth (add
report-facing facts/quotes, keep the fixed verdicts) and **tag its bib entries then** — not before.
Pull these in as the writing surfaces the need, not as a blanket pass.

- [ ] Mandatory 2FA · Trusted Publishing · Build provenance · GitHub branch protection · CI/CD gates
  · Artifact-repo promotion · The proxy — each `↳CM`, deepen + tag on demand.

---

## Gaps — references the outline needs that are *not in the bib yet*

Unlike the buckets above (which start from an existing stub), a **gap is a citation the outline
requires for which there is no `references.bib` entry at all** — so the work is *find and create* the
source, not deepen it. Each becomes an **`add-reference` skill invocation** (the mandatory path for
any new entry — see *Conventions*) or an explicit "dropped, and why." Grow this list whenever a topic
surfaces an unsourced claim.

- **Software-supply-chain policy backdrop (NIST SSDF / EO 14028).** SSDF (SP 800-218) and EO 14028
  govern *process compliance* (SBOMs, signing attestations), not the multi-party-authorization
  primitive. They therefore do not reinforce the “under-deployed primitive” thesis and would invite
  scope questions; §3 framing is carried by the marquee incidents and the landscape note.

---

## Conventions

- **Citable facts carry an anchored quote; synthesis is welcome but marked as synthesis.** A claim
  the report will lean on, with no verbatim anchor yet, goes under *Open threads / to verify*, not in
  *Key facts*.
- **Front matter is the machine-readable index** — `bucket`, `report_home`, `proxy_grounding`,
  `related_notes`, `bib_keys`, `status`. Keep it accurate; it is how notes are found and audited.
  `status` flips `draft` → `vetted` only at the Verify gate (phase 5) — a `draft` note is written but
  not yet read-through by the reader.
- **Every fact names its report home** (§ + claim). A fact with no home is a signal to cut it.
- **Link, don't duplicate** — `↳CM` topics point back to the controls-matrix note and add only the
  new facts; existing `docs/research/` notes are cited, not copied wholesale.
- **Verbatim generosity is a feature** — long excerpts are fine and wanted; mark every one as a
  quote with its anchor.
- **The proxy-relation is one honest point per topic** — including, where true, "the proxy does not
  beat this" (XZ review-surviving payload, colluding quorum). No victory laps.
- **`## Source decisions` is optional and rare** — a mini-ADR at the note's foot, used *only* when
  the grill surfaced a non-obvious call (a source dropped or preferred over a near-equivalent, an
  avenue deliberately not pursued). If the choices were self-evident, leave it out entirely.
- **Every new bib entry MUST go through the `add-reference` skill — no exceptions, no hand-editing
  `references.bib`.** The skill verifies each field against the live source, archives it to
  `.references/`, and dedupes; a hand-written entry silently skips all three. Land entries in-session
  (delegating to a Sonnet subagent is fine — its instruction is *"invoke `add-reference`,"* not
  *"format BibTeX"*); do not defer.
- **`% RESEARCHED` tags keep the bib honest.** Above each covered `references.bib` entry, add
  `% RESEARCHED <date> -- <note path relative to Practicum Work/>`. BibTeX ignores `%` lines, so it
  never touches rendering; an entry with no tag has not been through this pass, so new additions are
  visibly un-researched. The convention is also documented in the `references.bib` header.
- **Compact between topics** (phase 6). The queue and the self-contained notes are the handoff.

---

## Sources that shaped this method

- PaperTrail: A Claim-Evidence Interface for Grounding Provenance in LLM-based Scholarly Q&A —
  https://arxiv.org/html/2602.21045v1
- RAS: Retrieval-And-Structuring for Knowledge-Intensive LLM Generation —
  https://arxiv.org/html/2502.10996v1
- Grounded Knowledge Graph Extraction via LLMs: An Anchor-Constrained Framework with Provenance
  Tracking — https://www.mdpi.com/2073-431X/15/3/178
- "How to Build an AI Research Agent That Cites Sources" (claim-level citation, retrieval-tied
  grounding) — https://pickaxe.co/post/ai-research-agent

*(These informed the design principles — anchored provenance, compile-up-front, claim-linkage,
retrieved-only citation. They are not report citations.)*
