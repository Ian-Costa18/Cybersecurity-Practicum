<!-- LTeX: enabled=false -->
# Bibliography deep-dive — research process

How each **cluster of references** in [`references.bib`](../../../references.bib) goes from a bare
BibTeX stub to a **knowledge-store note** the final report can be *assembled from* — so that when
[#119](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/119) is done, writing §3, §4,
§6, and §7 is *retrieval over vetted material*, not research-while-writing.

This is the sibling of [controls-matrix/research-process.md](../controls-matrix/research-process.md).
That process is **tight and verdict-driven** (one matrix row → four fixed cell verdicts, defended).
This one is **broad and knowledge-driven**: the output is a durable, quotable store of facts, not a
scorecard. The shape of each note is chosen per topic, not fixed in advance.

One topic at a time, six phases: **ground → hunt → grill → write → verify → compact.**

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

Work top to bottom. Do the first unchecked topic, run the six phases, check it off, mark the next
`← next`. A fresh agent reads this section first to see where to resume. **Coverage tag:** `NEW` =
fresh reading; `REUSE` = consolidate existing repo research; `↳CM` = deepen an existing
controls-matrix note (keep verdicts, add report facts, tag bib).

### Marquee incidents — §3 Background (deepest treatment, one file each)

- [x] **I1 — Shai-Hulud npm worm (2025)** → `incident-shai-hulud.md` · `NEW` · *(vetted 2026-07-17)*
  - *Report home:* §3 case study; the Stolen-credential column anchor for the §4 matrix.
  - *Proxy grounding:* [docs/threat-model/](../../../../docs/threat-model/) (token-theft threats),
    [ctrl-mandatory-2fa.md](../controls-matrix/ctrl-mandatory-2fa.md) (the token-bypass cell it realizes).
  - *Stubs:* `shai-hulud-cisa`, `shai-hulud-unit42`. *Hunt for:* npm/GitHub official advisory, a
    post-incident scope/IOC writeup. *Focus:* token harvest → self-replication → auto-republish under
    legit identity; which controls it walked through.
- [x] **I2 — XZ Utils backdoor / CVE-2024-3094 (2024)** → `incident-xz-backdoor.md` · `NEW` · *(vetted 2026-07-17 — the honesty anchor: proxy does NOT beat the review-surviving insider; §3/§4/§7 "not a silver bullet" framing traces here)*
  - *Report home:* §3 case study; the Trusted-insider column anchor for the §4 matrix.
  - *Proxy grounding:* [ctrl-the-proxy.md](../controls-matrix/ctrl-the-proxy.md) Caveat 2
    (review-surviving payload — the XZ shape the proxy does *not* claim immunity to).
  - *Stubs:* `cve-2024-3094`, `openwall-xz-backdoor`. *Hunt for:* a rigorous timeline/post-mortem
    (multi-year social-engineering reconstruction), maintainer statements. *Focus:* the trust build,
    payload hidden in build/test fixtures, SSH-latency discovery, why auth+authz+provenance did not
    stop it.

### Incident landscape — §3/§4 framing (one note)

- [ ] **I3 — Supply-chain incident landscape** → `incident-landscape.md` · `NEW` · ← next
  - *Report home:* §3 framing ("the cost of the gap" beyond the two marquee cases) + §4 evidence.
  - *Existing research:* [Broad Literature Review.md](../../../../docs/research/Broad%20Literature%20Review.md).
  - *Stubs:* `event-stream-incident`, `event-stream-analysis`, `ctx-pypi-incident`,
    `solarwinds-sunburst-cisa`, `mitre-c0024-solarwinds`, `backstabbers-knife`,
    `cncf-supply-chain-catalog`. *Focus:* just enough per incident to cite it as pattern evidence;
    `backstabbers-knife` and the CNCF catalog carry the taxonomy framing.

### Methodology — §6 Security + Appendix (two notes)

- [x] **M1 — Threat-modeling & risk-scoring methodology** → `method-threat-modeling.md` · `NEW` · *(vetted 2026-07-17)*
  - *Report home:* §6 net-delta model + methodology justification; Appendix classification table.
  - *Proxy grounding:* [docs/threat-model/CONTRIBUTING.md](../../../../docs/threat-model/CONTRIBUTING.md),
    [evaluation-plan.md §3](../../../../docs/evaluation-plan.md).
  - *Stubs:* `stride-shostack`, `dread-leblanc`, `mitre-attack`, `attack-design-philosophy`.
    `cvss-v4` is deliberately out of this report-facing bucket: it scores vulnerabilities, not
    baseline-relative design-time threats.
    *Focus:* why STRIDE for enumeration, why the DREAD critique steers us off additive scoring, how
    ATT&CK grounds "pre-existing" techniques. Coordinate with #107.
- [x] **M2 — Comparative-evaluation & formal-methods frameworks** → `method-evaluation-frameworks.md` · `NEW` · *(vetted 2026-07-18)*
  - *Report home:* §4 (the matrix *is* a comparative-evaluation framework — cite the precedent) and
    §7 limitations (excluded human-subjects usability; formal-verification as future work).
  - *Stubs:* `bonneau-quest-passwords` (the UDS comparative-matrix precedent — load-bearing),
    `reese-2fa-usability`, `de-cristofaro-2fa`, `mfkdf`, `trustee-social-auth`, `tamarin-prover`.
    *Grill:* which of these are actually cited vs. cut — the usability studies may only support the
    §7 "usability excluded" line.

### Multi-party approval in industry — §4/§7 positioning (one note)

- [ ] **P1 — Multi-party approval in industry** → `primitive-multiparty-approval.md` · `NEW`
  - *Report home:* §4 (industry adoption = the gap is recognized) + §7 generalizability.
  - *Proxy grounding:* [docs/adr/0001-credential-backed-approval.md](../../../../docs/adr/0001-credential-backed-approval.md),
    [evaluation-plan.md](../../../../docs/evaluation-plan.md) Move 3.
  - *Stubs:* `aws-mpa`, `aws-backup-mpa`, `vault-seal-unseal`, `authelia` (forward-auth reference
    arch for the §7 generalizability leg). *Focus:* the primitive exists and ships, but is
    **siloed** inside each platform's own control plane — reinforcing, not filling, the registry gap.

### Cryptographic choices — System Design §5 / Appendix (one note, consolidate)

- [ ] **C1 — Cryptographic choices & rationale** → `primitive-crypto-choices.md` · `REUSE`
  - *Report home:* §5 (the crypto is inherited-secure, not a novel claim) and the **tentative
    Appendix** item *"Cryptographic-choice rationale"* now stubbed in [outline.md](../../outline.md) —
    credential-backed approval over threshold signatures, chosen for **usability**. Deranked in the
    body — not a large section.
  - *Closing step (do last):* once the note is written, **enhance that outline Appendix item with
    the concrete learnings** — the decisive usability argument and the primitive list — so the
    outline reflects what the research actually found, not just the placeholder.
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

### Deepen existing controls-matrix notes — §4 prose (`↳CM`, after the NEW work)
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

- **Dependency confusion (Birsan, 2021)** — named in #119 for the §4 scope-boundary paragraph
  (attacks we deliberately don't address). No entry yet. Need the primary write-up + a formal echo.
  `ADD`.
- **CISA / NSA supply-chain guidance** — the other half of that scope-boundary line. Candidate: CISA
  "Securing the Software Supply Chain" series. `ADD`.
- **Separation-of-duties / dual-control / four-eyes** — the Intro thesis ("m-of-n *human*
  authorization is an under-used *general* primitive") currently asserts a well-established security
  principle with no citation. Candidate anchors: NIST SP 800-53 AC-5, Clark–Wilson, PCI-DSS dual
  control. **Judgment call — confirm in grill** whether the report cites this or treats it as common
  knowledge.
- **Software-supply-chain policy backdrop (optional)** — NIST SSDF (SP 800-218) / EO 14028, if §3
  wants the policy framing. `CONFIRM`.

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
