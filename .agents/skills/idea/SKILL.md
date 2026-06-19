---
name: idea
description: Turn a raw idea (or an ideas backlog) into well-bucketed GitHub issues — without forcing a vertical slice it isn't ready for.
disable-model-invocation: true
---

# Idea → issue

`to-issues` slices *committed* work into tracer-bullet vertical slices. An **idea** usually can't be sliced yet — the code it needs doesn't exist, or the design is unsettled. This skill captures an idea at its true **maturity** so it lives in the tracker without pretending it's ready.

The triage-label vocabulary and issue-tracker workflow are the single source of truth for label meanings and dependency mechanics — `docs/agents/triage-labels.md` and `docs/agents/issue-tracker.md`. This skill is the judgment that sits on top of them.

## Process

### 1. Gather the idea

Work from whatever is in context. If passed a reference (text, an `ideas.md` section, a path), read it. For a backlog file, take **one idea at a time** unless told to batch — and when batching, still bucket each idea individually.

### 2. Bucket by maturity

The core move. Two questions place every idea into exactly one bucket — they **do not stack**:

- **Is it a code/product change at all?** If it's research or coursework (formal verification, a write-up, an evaluation) → `practicum`, and skip the feasibility question.
- **Can it start against today's codebase?**
  - **Yes, but design questions remain** → `enhancement` + `needs-info`. We could cut a slice today; we just need the user to answer open questions first.
  - **No** — blocked on a prerequisite that doesn't exist yet, or it needs a full PRD before it can be sliced → `future-enhancement`. No amount of info unblocks it; something has to be built first.

`future-enhancement` *replaces* `enhancement`/`needs-info` — it is the "come back later" bucket, and it already answers *why* the idea isn't `ready-for-agent`.

### 3. Ground it in the codebase

Before drafting, check what already exists (`sverklo_search`, then Grep/Read) so you can:

- **Scope to the delta.** Don't restate behavior the MVP or an existing issue already covers — describe only what this idea *adds*.
- **Keep prose from going stale.** Reference a conceded limitation (e.g. `docs/mvp.md`) instead of asserting a current state that later phases will change.
- **Find the concrete blocker.** Which existing open issue, if any, actually gates this — that becomes the blocked-by link.

### 4. Split and cluster

- **Split** one idea into two issues when its halves carry different blockers or labels (e.g. a timeout half feasible now + a reminder half blocked on the notifier).
- **Cluster** related ideas with a `## Related` cross-link rather than merging them — separate issues, linked.

### 5. Draft and review

Print each proposed issue — title, labels, blocked-by, body — for the user. Iterate. **Do not create anything until the user approves** the breakdown.

### 6. Publish

Create each issue with its bucket's labels. Then wire relationships per `docs/agents/issue-tracker.md` § *Issue dependencies*:

- A **concrete open-issue blocker** → the GitHub **blocked-by dependency field** (not prose).
- A merely **related** issue → a prose `## Related` section referencing `#N`.

Cross-link `#N` references can only be filled once the issues exist, so create first, then patch the `Related` sections with the real numbers.

Titles use `Idea · <summary>` (or `Practicum · <summary>` for the practicum bucket).

## Issue body template

<template>
> Captured from `<source>`. One line on the bucket rationale — *why* it's
> `future-enhancement` / `needs-info` / `practicum`.

## Idea

What the idea is, in terms of end-to-end behavior — not layer-by-layer implementation.

## Why

The value: what it improves or defends against.

## Why this is blocked   ← future-enhancement
## What exists today      ← enhancement + needs-info (scope to the delta)

For `future-enhancement`: the missing prerequisite. For a feasible idea: what the
codebase already does, so the delta is unambiguous.

## Open questions / What's needed before `ready-for-agent`

- [ ] The decisions or prerequisites that stand between this and a slice. Carry
      forward any concerns already written in the source idea — don't flatten them.

## Related

Cross-links to clustered or split sibling issues (`#N`). Omit if none.

## Complexity

The original estimate, qualified by anything learned while grounding it.
</template>

Avoid file paths and code snippets in bodies — they go stale. Exception: a small schema/state-machine/type shape that encodes a decision more precisely than prose.
