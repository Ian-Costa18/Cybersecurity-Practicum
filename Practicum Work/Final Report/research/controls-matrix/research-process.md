<!-- LTeX: enabled=false -->
# Control-matrix research process

How one row of the [#113](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/113)
positioning matrix goes from an entry in the eval plan to a vetted research note. One control
(row) at a time, four phases: **ground → grill → preview → write**.

Verdicts are **fixed** by [evaluation-plan.md §1, Move 1](../../../../../docs/evaluation-plan.md) —
this process *sources and defends* them, it does not invent them. If a source contradicts a
drafted verdict, surface it against the spec rather than quietly keeping the verdict.

The four column scenarios, by name (never referred to by letter — nobody keeps A/B/C/D straight):
**Stolen credential** (Shai-Hulud 2025) · **Trusted insider** (XZ, CVE-2024-3094) ·
**Compromised CI** (authentically-built poisoned artifact) · **Direct publish** (straight to the
registry, bypassing repo and CI).

## Row queue

Work top to bottom. Do the first unchecked row, run the four phases, then check it off and mark the
next `← next`. This section is the handoff: a fresh agent reads it first to see where to resume.

- [x] 1 — Mandatory 2FA / MFA → `ctrl-mandatory-2fa.md`
- [x] 2 — Trusted Publishing (OIDC) → `ctrl-trusted-publishing.md`
- [x] 3 — Build provenance (Sigstore / SLSA / PEP 740) → `ctrl-build-provenance.md`
- [x] 4 — GitHub required reviews + branch protection / commit signing → `ctrl-github-branch-protection.md`
- [x] 5 — CI/CD deployment-approval gates (GH environments / GitLab) → `ctrl-cicd-deployment-gates.md`
- [x] 6 — Artifact-repo staging/promotion (Artifactory / Nexus) → `ctrl-artifact-repo-promotion.md`
- [x] 7 — The proxy → `ctrl-the-proxy.md` *(special: this **is** the proxy — "How the proxy beats this row" replaced with the honest caveats, PUB-2 sole-token / bucket ③ and CORE-3 colluding quorum / bucket ④)*

When the **last** row is checked, flip [#171](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/171)
from `needs-info` to `ready-for-agent` — every note's deferred bib keys are then final.

## 1 — Ground

Look up the control's **documented behavior** from primary sources before any discussion. Facts are
looked up, never asked. Find the crux fact: **what decision does this control actually gate?**
(login? repo merge? deploy job? internal promotion?) That answer is the axis, and it makes the
`✗` cells self-evident.

*Complete when:* the control's gated decision is stated in one sentence, and at least one verbatim,
anchored quote backs it.

## 2 — Grill

Walk the four scenarios and the proxy comparison as a `/grilling` session. Settle the obvious cells
yourself (a `✗` that follows directly from the axis needs no debate); **stop only on genuine
forks** — usually a `~` cell, whose partial verdict has to be justified as "catches case X, misses
case Y." One question at a time, in prose, each with a recommended answer. Do not write until the
reader confirms shared understanding.

*Complete when:* every cell's verdict has an agreed reason, and each `~` names the case it catches
and the case it misses.

## 3 — Preview

Before writing the note, show a **content table** for approval:

- the **sources** (few is fine) — key, source, what each anchors;
- the **per-column verdicts** with one-line catches/misses reasoning;
- the **caveat** text for any `~`;
- the **proxy-beats-this-row** one-liner;
- the **bib keys** to defer.

*Complete when:* the reader approves the preview.

## 4 — Write

Write `ctrl-<slug>.md` in this folder to the template below. New bib keys are **deferred** to
[#171](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/171), never landed inline —
list them under *references.bib — to add*.

*Complete when:* the note exists and matches the approved preview, **and the Row queue is updated**
— check off this row, mark the next one `← next`.

---

## Note template

```markdown
# <Control name> — row N

**Axis:** <the decision it gates>
**Verdicts:** Stolen credential `?` · Trusted insider `?` · Compromised CI `?` · Direct publish `?`

## Primary sources
- <title> — <URL> (accessed <date>) → `<bib-key>`

## What it actually gates
<one paragraph: the decision governed, hence the axis; makes the ✗ cells obvious>

## Documented behavior (anchored)
> "<verbatim quote>"
— <source, section anchor>

## Per-column analysis
| Scenario | Verdict | Catches / Misses | Source |
|---|:--:|---|---|
| Stolen credential | ? | <catches … / misses …> | `<key>` |
| Trusted insider | ? | … | … |
| Compromised CI | ? | … | … |
| Direct publish | ? | … | … |

> ⚠ **Caveat (<scenario>).** <factual conditional behind a ~; state the case caught and the case
> missed, no editorializing>

## How the proxy beats this row
<the structural thing the proxy does that this control cannot: m-of-n independent,
re-authenticated approvals bound to the exact artifact by hash, at authorization time>

## references.bib — to add (tracked in #171)
- `<key>` — <source>.
```

## Conventions

- **Named scenarios** in every header and table — never bare letters.
- **A ⚠ caveat box** sits directly below the per-column table, cross-referenced from the `~` row it
  explains; used only when a verdict is partial.
- **`~` means partial coverage** — blocks the attack in some cases, not others. State both cases;
  stop there.
- **The proxy section stands alone** — the proxy's advantage is one coherent structural point, said
  once, not repeated per cell.
- **A real incident per row, where one exists** — beyond the documented-behavior citation, anchor at
  least one cell to a named, primary-sourced incident where the control was in place and failed
  (e.g. Ultralytics for Trusted Publishing's Compromised-CI cell, Shai-Hulud for 2FA's
  Stolen-credential cell). It sharpens the `✗`/`~` and carries the "proxy beats this row" argument on
  evidence, not assertion.
