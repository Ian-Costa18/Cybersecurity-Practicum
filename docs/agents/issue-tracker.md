# Issue tracker: GitHub

Issues and ideas for this repo live as GitHub issues. Use the `gh` CLI for all operations.

## Conventions

- **Authenticate**: ensure `gh auth status` succeeds; if not, prompt the operator to run `gh auth login`.
- **Create an issue**: `gh issue create --title "..." --body "..." --label needs-triage`. Use a heredoc for multi-line bodies.
- **Read an issue**: `gh issue view <number> --comments`.
- **List issues**: `gh issue list --state open --limit 100 --label needs-triage`. Keep `--limit` high (default `gh` returns only 30) so the full backlog is visible.
- **Comment on an issue**: `gh issue comment <number> --body "..."`
- **Apply / remove labels**: `gh issue edit <number> --add-label "..."` / `--remove-label "..."`. Labels follow `docs/agents/triage-labels.md`; if one is missing, create it with a confirmation step.
- **Close**: `gh issue close <number> --comment "..."`

Infer the repo from `git remote -v` — `gh` does this automatically when run inside a clone. If the repository is offline or `gh` is unavailable, use the [local fallback](#local-fallback).

## Pull requests as a triage surface

**PRs as a request surface: yes.** External PRs are treated as feature requests; `/triage` reads this flag and pulls them into the same queue as issues, running them through the same labels and states using the `gh pr` equivalents:

- **Read a PR**: `gh pr view <number> --comments` and `gh pr diff <number>` for the diff.
- **List external PRs for triage**: `gh pr list --state open --json number,title,body,labels,author,authorAssociation,comments` then keep only `authorAssociation` of `CONTRIBUTOR`, `FIRST_TIME_CONTRIBUTOR`, or `NONE` (drop `OWNER`/`MEMBER`/`COLLABORATOR` — collaborators' in-flight PRs are left alone).
- **Comment / label / close**: `gh pr comment`, `gh pr edit --add-label`/`--remove-label`, `gh pr close`.

GitHub shares one number space across issues and PRs, so a bare `#42` may be either — resolve with `gh pr view 42` and fall back to `gh issue view 42`.

## Linking pull requests to issues

When a PR resolves an issue, put a GitHub **closing keyword** — `Closes #N`, `Fixes #N`, or `Resolves #N` — in the PR body, not just a bare `#N`. A bare `#N` only leaves a cross-reference mention with no link. Use one keyword per issue the PR closes (e.g. `Closes #4`, `Closes #5`).

The catch: **GitHub only registers the linked-issue connection from a keyword when the PR's base is the default branch.** Per-issue PRs here target the integration branch (`progress-report-#`), not `main`, so the keyword alone leaves only a cross-reference — no link in the PR's Development sidebar (`closingIssuesReferences` stays empty). There is **no `gh`/GraphQL/REST mutation** for the manual "Link an issue from this repository" action (`addSubIssue` is issue→issue, `createLinkedBranch` is branch→issue; neither links a PR to an issue).

Working maneuver to create the link while keeping the integration-branch base:

```bash
# 1. Ensure the PR body has the keyword, e.g. "Closes #4."
# 2. Momentarily retarget the base to the default branch, then back:
gh pr edit <pr> --base main
gh pr edit <pr> --base <integration-branch>   # e.g. progress-report-3
# 3. Verify the link persisted:
gh pr view <pr> --json closingIssuesReferences -q '[.closingIssuesReferences[].number]'
```

The flip to the default branch forces GitHub to evaluate the keyword and register the connection, which **persists** after flipping back to the integration branch. No merge happens during the flip, and these PRs merge into the integration branch — not the default branch — so GitHub never auto-closes the issue. Still close it manually (`gh issue close <#> -c "merged via #<pr>"`), per the branch & issue workflow.

## Issue dependencies (blocked-by / blocking)

When one issue blocks another, record it in GitHub's **blocked-by dependency field**, not only in prose. A line like "Blocked by #11" is a cross-reference mention; it does not populate the structured dependency, so it won't show in the dependency UI or gate the blocked work.

The field is not exposed by `gh issue edit`; use the REST dependencies API via `gh api`. Two gotchas:

- The endpoint takes the blocking issue's **global database id**, not its `#number`. Fetch it first.
- Send it as an **integer** with `-F` (typed), not `-f` (string) — `-f` returns HTTP 422 "not of type integer".

```bash
# make issue #36 blocked-by #11
BLOCKER_ID=$(gh api repos/<owner>/<repo>/issues/11 -q .id)
gh api --method POST repos/<owner>/<repo>/issues/36/dependencies/blocked_by -F issue_id=$BLOCKER_ID
# verify
gh api repos/<owner>/<repo>/issues/36/dependencies/blocked_by -q '[.[].number]|join(", ")'
```

Use the field only when a **concrete open issue** is the blocker. For an architectural prerequisite with no single tracking issue (e.g. "needs the real credential-handling path"), state it in prose instead — there's nothing to link. For merely *related* issues that don't block, use a prose `## Related` section referencing `#N`.

## Idea capture

Ideas that aren't yet committed work are filed as issues too, labelled per the idea-capture vocabulary in `docs/agents/triage-labels.md` (`enhancement` / `future-enhancement` / `practicum`, with `needs-info` for feasible-but-underspecified). Prefer this over an out-of-tree ideas file so everything lives in the tracker. When an idea is split (one entry → two issues) or clustered (several issues share a theme), cross-link them with a `## Related` section, and set blocked-by where one genuinely gates another.

## Local fallback

If the repository is offline or the operator prefers local files, use the `.scratch/` pattern: place markdown issue files under `.scratch/<area>/NNNN-title.md` with frontmatter `title`, `labels`, and `body` fields. Documented workflows in `.scratch/README.md` can be added later.

## When a skill says "publish to the issue tracker"

Create a GitHub issue.

## When a skill says "fetch the relevant ticket"

Run `gh issue view <number> --comments`.
