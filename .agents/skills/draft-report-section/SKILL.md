---
name: draft-report-section
description: Draft one section of the CS 6727 final report directly in LaTeX — mines the repo specs as the quarry, dispatches to writing-shape or writing-beats, wraps output in the aidraft tag, and holds to the outline's page budget.
disable-model-invocation: true
---

Draft **one** section of the final report per invocation, directly in LaTeX. The
report's structure is already decided — [outline.md](../../../Practicum%20Work/Final%20Report/outline.md)
is the **spine**; the **quarry** is two sources mined together: the repo specs (facts and
claims, source of truth) and [fragments.md](../../../Practicum%20Work/Final%20Report/fragments.md)
(Ian's own sentences and framings). This skill does not re-outline; it mines the quarry into
one section's `.tex`, dispatching to `writing-shape` (argument) or `writing-beats`
(narrative), and tags every Claude-authored passage with `aidraft` so Ian can rewrite it in
his own voice later.

## Steps

1. **Pick the section and its budget.** Read the spine. Confirm which outline section this
   run drafts, its claim tag, and its **page ceiling** from the budget table. One section
   per invocation — refuse to draft two.

2. **Load the quarry.** Read both sources for the section: the governing spec(s) from the
   dispatch map below (follow [docs/index.md](../../../docs/index.md) for anything the map
   doesn't name), **and** [fragments.md](../../../Practicum%20Work/Final%20Report/fragments.md)
   for any of Ian's sentences and framings that fit — a fragment that lands is preferred over
   prose Claude invents. Source-of-truth rule (CLAUDE.md): read the governing doc — never
   write a claim from a secondhand citation or memory. *Done when you can name every claim
   the section will make and the spec or `references.bib` entry each one traces to, and you
   have pulled every fragment that fits the section.*

3. **Draft into the section file, dispatching by type.** Prose lives in
   `Practicum Work/Final Report/sections/<file>.tex`, `\input` by `report.tex` (create the
   file and uncomment its `\input` line if it doesn't exist yet). Invoke `writing-shape` for
   an *argument* section or `writing-beats` for a *narrative* one (see map). The quarry is the
   pile; the section `.tex` is the article file. Write all prose inside
   `\begin{aidraft}…\end{aidraft}`. Open the file with the claim-tag cross-link as a LaTeX
   comment. Argue format (prose / list / `table*` / figure) as those skills do — but in
   LaTeX, not markdown. Stay within the page ceiling.

4. **Budget check.** Compile `report.tex` if a LaTeX toolchain is available and read the page
   count; otherwise estimate by column-inches against the ceiling. *Done when the section
   fits its ceiling, every claim traces to the quarry, and all Claude-authored prose sits
   inside `aidraft`.*

## Standing context

- **Spine:** [outline.md](../../../Practicum%20Work/Final%20Report/outline.md) — section order,
  claim tags, and the page-budget table. Decided; don't relitigate it here.
- **Quarry = source of truth.** Mine the specs; do not paraphrase a spec secondhand. If the
  quarry lacks something the section needs, name the gap — don't invent it.
- **Template:** IEEEtran two-column. Wide tables (the comparative matrix) are full-width
  `table*` floats. `references.bib` is already IEEE-styled.
- **Cross-link convention:** open each evaluated section with a LaTeX comment naming its
  [evaluation-plan.md](../../../docs/evaluation-plan.md) claim, mirroring the outline's claim tags.
- **Edit scope:** the "don't touch the report `.tex`" rule is **progress-reports only**
  (that's `finalize-progress-report`'s domain). The **final-report `.tex` is this skill's to
  write** — draft directly into it.

## Dispatch map (section → skill → primary quarry)

| Outline § | Type → skill | Primary quarry |
|---|---|---|
| 2 Introduction | argument → `writing-shape` | outline.md thesis, evaluation-plan.md, mvp-prd.md, [#109] |
| 3 Background — Incidents | narrative → `writing-beats` | `docs/research/`, `docs/threat-model/` (Shai-Hulud, XZ) |
| 4 Positioning & Gap | argument → `writing-shape` | evaluation-plan.md §1, `docs/research/` lit review |
| 5 System Design | argument → `writing-shape` | architecture.md, request-lifecycle.md, evaluation-plan.md §2 |
| 6 Security Analysis | argument → `writing-shape` | `docs/threat-model/`, evaluation-plan.md §3 |
| 7 Discussion | argument → `writing-shape` | constraints.md, `docs/use-cases/`, [#109] |
| 8 Conclusion | argument → `writing-shape` | (synthesize drafted sections; no new quarry) |

Narrative *figures* a section calls for (e.g. an illustrative timeline) are drafted with
`writing-beats` too — treat them as narrative beats within their host section, not as map rows
(the confirmed set lives in outline.md; don't hardcode a figure here that outline.md may cut).
The **abstract** is drafted last, with `writing-shape`, mining fragments.md heavily.

## The aidraft tag

`\begin{aidraft}…\end{aidraft}` (block) and `\aiphrase{…}` (inline) mark prose Claude wrote
that Ian has not yet rewritten. Defined in the [report.tex](../../../Practicum%20Work/Final%20Report/report.tex)
preamble: violet while the `\aidrafttrue` toggle is set, invisible when flipped to `\aidraftfalse` for submission,
greppable either way. Everything this skill writes goes inside the tag; when Ian rewrites a
passage in his own voice he unwraps it.

## Fragments are a first-class quarry

[fragments.md](../../../Practicum%20Work/Final%20Report/fragments.md) is not a side-door for a
couple of hard sentences — it is a co-equal quarry mined for **every** section. It holds Ian's
own sentences, analogies, and framings; where the specs supply the facts a section must state,
fragments supply the voice it should state them in. When a fragment fits, deploy it (reworked
to its surroundings) in preference to inventing prose. It carries the framings hardest to get
from specs alone — the general→concrete bookend especially. Ian fills it in separate
`writing-fragments` sessions; this skill consumes it.

[#109]: https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/109
