## The specs are the source of truth — consult them before acting

This repo's prose docs (`CONTEXT.md`, `docs/` specs, `docs/adr/`) are the authoritative record of what has already been decided. Before any work whose correctness depends on what is *already specified*, **read the governing doc(s) first** — do not act from a secondhand citation (an issue body, a chat summary) or from memory. The map of where things live is `CONTEXT.md` → `docs/index.md`; the account/key/auth model lives in `docs/account-management.md` and `docs/approver-authentication.md`.

This applies across workflows:

- **Filing issues (QA/triage):** do not open an issue for something the specs already specify or already resolve. Check first; if it's specified, the issue is at most "code doesn't match spec," not a new decision.
- **Grilling / design:** know what the specs already settle *before* deciding what is genuinely new. Scope questions to the actual gaps and the implementation seams the specs don't cover — never re-litigate a decision already written down.
- **Implementation:** follow the documentation. The spec is the contract — implement what it says, **unless the issue or the initiating chat explicitly overrides it**, in which case the override wins *and* the spec must be edited to match (in the same change).
- **Documentation upkeep:** when a change deviates from a spec, you must know *which* doc and section encodes the old design and correct it in the same branch as the code — a spec that describes a rejected design is as harmful as code that contradicts the spec.

## Development commands

This project uses [`uv`](https://docs.astral.sh/uv/). Tests, lint, and type-check run through it — there is no separately activated virtualenv, and bare `python`/`pytest` will not find the deps.

- Run the test suite: `uv run pytest` (or a subset: `uv run pytest tests/test_post_approval.py`)
- Lint: `uv run ruff check`
- Type-check: `uv run ty check`

## Agent skills

### Issue tracker

This repository uses GitHub Issues as its issue tracker. Skills that create or read issues will use the `gh` CLI when available and will fall back to instructions in `docs/agents/issue-tracker.md`.

### Triage labels

Label vocabulary: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md` for mapping and usage.

### Branch & issue workflow

`main` is the default branch but is **not** the per-issue merge target. Work accumulates on an **integration branch** — the current progress-report branch (`progress-report-#`), which tracks everything done since the last progress report. **Do not open per-issue PRs into `main`.**

For each issue:

1. Cut a feature branch off the current integration branch: `git checkout <integration-branch> && git checkout -b phase<phase>-<issue#>-<slug>` (e.g. `phase0-2-identity-crypto`).
2. Implement, commit, push, then open the PR against the integration branch — **not** `main`: `gh pr create --base <integration-branch>`.
3. **Manually close the issue when its PR merges** (`gh issue close <#> -c "merged via #<pr>"`). Closing keywords (`Closes #N`) only auto-fire on merge into the *default* branch, so they will **not** close an issue merged into the integration branch.

The integration branch merges into `main` only at the progress-report milestone. If an issue's work landed directly on the integration branch (no feature branch), still close it manually.

### Domain docs

Layout: single-context — a single `CONTEXT.md` at the repository root and `docs/adr/` for ADRs. See `docs/agents/domain.md` for consumer rules.

### Sverklo — Code Intelligence

This project has the sverklo MCP server installed. Sverklo is a code-intelligence index: ranked search, dependency graph, persistent memory. Use it as the **default** tool for code discovery in this repo.

#### Always Do

- **MUST call `sverklo_overview` before exploring an unfamiliar directory.** It returns the PageRank-ranked map of the codebase in one call — much cheaper than `ls` + `Read` loops.
- **MUST use `sverklo_search` instead of Grep for any query that is conceptual or fuzzy** ("how does auth work", "anything related to billing", "where do we handle retries"). Grep is for exact strings only.
- **MUST use `sverklo_lookup` to find a symbol's definition** by name — never grep + Read for this.
- **MUST run `sverklo_impact` before renaming, deleting, or changing the signature of any function/class/method** that may be called from elsewhere. Report the blast radius (callers, depth) to the user before editing.
- **MUST use `sverklo_refs` to enumerate callers of a symbol.**
- **MUST use `sverklo_deps` to see imports + importers of a file** before moving or splitting it.
- **MUST call `sverklo_remember` when the user corrects you** with phrasing like "stop X", "never X", "always Y", "don't Y", "prefer Z", "remember that I want Q", "actually, do W". Save with `category:correction` (stop/never/don't) or `category:preference` (prefer/want/like), `kind:semantic`, and the user's instruction as content. Save before continuing the response. Do not ask permission — corrections are explicit instructions to persist behavior across sessions.
- **MUST call `sverklo_recall` at the start of work** on a non-trivial task to surface prior decisions and corrections.

#### Never Do

- **NEVER use Grep when the query is conceptual.** Grep cannot find "the auth flow" — sverklo_search can.
- **NEVER edit a function or class without first running `sverklo_impact`** on it. Silently breaking a caller is the most expensive bug this codebase produces.
- **NEVER ignore HIGH or CRITICAL impact warnings** without surfacing them to the user.
- **NEVER rename symbols with find-and-replace.** Use `sverklo_refs` first; it knows which "foo" is the function and which is a string.
- **NEVER save routine task summaries to memory.** `sverklo_recall` is only useful when hits are signal-dense — save only (a) bugs that took >1h to debug, (b) recurring mistakes, (c) non-obvious architectural decisions, (d) audit findings needing user judgment.
- **NEVER re-read a file sverklo just returned a path for.** Use `sverklo_lookup` for the specific symbol instead.

#### When Grep / Read still wins

| Task | Tool |
|---|---|
| Exact string match (`"TODO(alice)"`, error message text) | Grep |
| Read a known file at a known path | Read |
| Inspect a specific line range | Read with offset/limit |

#### Exploration order

`sverklo_overview` (1 call) → `sverklo_search` (1 call) → `sverklo_lookup` on the top hit → `sverklo_refs` / `sverklo_impact` only if you need the blast radius. If you've made 5 sverklo calls and still don't have the answer, **stop and ask a clarifying question** — don't burn 10 more.

#### Output discipline

No preambles ("Here are the results", "Great question"), no closing affirmations, no em-dashes as conversational pauses. State the finding, show the fix, stop. User instructions override this file.
