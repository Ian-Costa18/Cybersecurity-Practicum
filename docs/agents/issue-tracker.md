# Issue tracker: GitHub

Summary

This repository uses GitHub Issues as its canonical issue tracker. Skills that create, update, or read issues should use the `gh` CLI when available. If `gh` is not present, skills will instruct the operator to use the GitHub web UI or fall back to a documented workflow.

Usage notes for skills

- Authentication: callers should ensure `gh auth status` succeeds; if not, prompt the operator to run `gh auth login`.
- Creating an issue (example):

```bash
gh issue create --title "Short summary" --body "Detailed description and reproduction steps" --label needs-triage
```

- Reading issues: skills may call `gh issue list` with label filters (e.g. `--label needs-triage`) and fetch single issues via `gh issue view <number>`.
- Labels: skills will apply labels described in `docs/agents/triage-labels.md`. If a label is missing, the skill may create it with a confirmation step.

Linking pull requests to issues

When a pull request resolves an issue, put a GitHub **closing keyword** — `Closes #N`, `Fixes #N`, or `Resolves #N` — in the PR body, not just a bare `#N`. The keyword makes GitHub link the PR to the issue and surface "linked a pull request that will close this issue" on the issue; a bare `#N` only leaves a cross-reference mention with no link.

- Use the keyword **even though** per-issue PRs target the integration branch (`progress-report-#`), not the default branch. GitHub only *auto-closes* an issue on merge into the **default** branch, so here the keyword creates the link but does **not** close the issue on merge — still close it manually (`gh issue close <#> -c "merged via #<pr>"`), per the branch & issue workflow.
- One keyword per issue the PR closes (e.g. `Closes #4`, `Closes #5`).

Issue dependencies (blocked-by / blocking)

When one issue blocks another, record it in GitHub's **blocked-by dependency field**, not only in prose. A line of body text like "Blocked by #11" is a cross-reference mention; it does not populate the structured dependency, so it won't show in the issue's dependency UI or gate the blocked work. Set the real field.

The dependency field is not exposed by `gh issue edit`; use the REST dependencies API via `gh api`. Two gotchas:

- The endpoint takes the blocking issue's **global database id**, not its `#number`. Fetch it first: `gh api repos/<owner>/<repo>/issues/<blocker#> -q .id`.
- Send it as an **integer** with `-F` (typed), not `-f` (string) — `-f` returns HTTP 422 "not of type integer".

```bash
# make issue #36 blocked-by #11
BLOCKER_ID=$(gh api repos/<owner>/<repo>/issues/11 -q .id)
gh api --method POST repos/<owner>/<repo>/issues/36/dependencies/blocked_by -F issue_id=$BLOCKER_ID
# verify
gh api repos/<owner>/<repo>/issues/36/dependencies/blocked_by -q '[.[].number]|join(", ")'
```

Use the field only when a **concrete open issue** is the blocker. For an architectural prerequisite with no single tracking issue (e.g. "needs the real credential-handling path"), state it in prose instead — there's nothing to link. For merely *related* issues that don't block (cross-linked clusters, "see also"), use a prose `## Related` section referencing `#N` rather than the dependency field.

Idea capture

Ideas that aren't yet committed work are filed as issues too, labelled per the idea-capture vocabulary in `docs/agents/triage-labels.md` (`enhancement` / `future-enhancement` / `practicum`, with `needs-info` for feasible-but-underspecified). Prefer this over an out-of-tree ideas file so everything lives in the tracker. When an idea is split (one ideas entry → two issues) or clustered (several issues share a theme), cross-link them with a `## Related` section, and set blocked-by where one genuinely gates another.

Local fallback

If the repository is offline or the operator prefers local files, use the `.scratch/` pattern and place markdown issue files under `.scratch/<area>/NNNN-title.md` with frontmatter `title`, `labels`, and `body` fields. Documented workflows in `.scratch/README.md` can be added later.
