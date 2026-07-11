<!-- LTeX: enabled=false -->
# Progress Report 4 — Editing Notes

Carry-over edits identified while building the final-report outline. These reconcile the
report/PR with the just-landed evaluation reframe (`b8a8a2b` — net-delta security axis) and the
general→concrete "bookend" framing. Deal with these when building PR4. Ordered biggest-first.

## 1. Evaluation section — rewrite to the reframed three claims

The PR3 Evaluation paragraph still describes the **old** claims in the **old** order
("(1) it works, (2) resists the attacks it claims to [four buckets], (3) fills a gap").
Rewrite to match [evaluation-plan.md](../../docs/evaluation-plan.md):

1. **It solves a problem** (the gap — comparative matrix + case studies + industry-adoption trend). *Lead.*
2. **It works** (three-act demo + integration suite).
3. **It adds only a bounded set of new threats** — net-delta vs. the direct-publish baseline:
   *Improved / Inherited / Introduced*, then four mitigation buckets over the threats the proxy owns.

Note the security claim is now a **net delta, not an absolute** ("resists everything"); the
threat model is aligned to **MITRE ATT&CK**.

## 2. Report Outline section — point it at the outline

The PR3 "Report Outline" section is an empty placeholder. Populate it from — or point it at —
[Practicum Work/Final Report/outline.md](../Final%20Report/outline.md).

## 3. Problem & Solution statements — align to the general→concrete bookend

- **Problem statement:** currently concrete-first with generality as a tacked-on last sentence.
  Flip to **general-first, then narrow** to package-publishing, to match the report Intro's bookend.
- **Both statements:** make sure generality reads as **vision / framing**, not an *evaluated* claim
  (the [#109](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/109) scope decision:
  evaluation covers package-publishing only; general-purpose is future direction).

## 4. Appendix — add work-product pointers

Add to the PR4 appendix (the final-report appendix will mirror this):

- **Codebase pointer** (link to `src/`).
- **Full threat-model classification table** (net-delta *Improved / Inherited / Introduced* + the
  four mitigation buckets) — the finished per-threat table from
  [#107](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/107).

## 5. Questions I Have section

Per Ian: **ignore** — do not carry the PR3 self-grading / MITRE-anchor question forward
(it's resolved by the reframe). New question to be written fresh for PR4.
