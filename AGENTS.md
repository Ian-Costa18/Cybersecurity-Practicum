## The specs are the source of truth — consult them before acting

This repo's prose docs (`CONTEXT.md`, `docs/` specs, `docs/adr/`) are the authoritative record of what has already been decided. Before any work whose correctness depends on what is *already specified*, **read the governing doc(s) first** — do not act from a secondhand citation (an issue body, a chat summary) or from memory. The map is `CONTEXT.md` → `docs/index.md`; the account/key/auth model lives in `docs/account-management.md` and `docs/approver-authentication.md`.

Two policies with teeth:

- **Overrides update the spec.** The spec is the contract — implement what it says, **unless the issue or initiating chat explicitly overrides it**, in which case the override wins *and* the spec must be edited to match in the same change. A spec describing a rejected design is as harmful as code that contradicts the spec.
- **Amending ADRs in place is fine** — edit them to match shipped reality. No `Superseded`/`Amended` marker, dated note, or superseding ADR required; this project keeps no audit trail of the old decision.

## Source layout — read before structural work

`src/msig_proxy/` is organized as **vertical slices** (lifecycle stages in front, service-type verticals in back), governed by a dependency rule: within a slice, only the web-edge files import FastAPI; the logic stays framework-free. The authoritative map is **[docs/source-layout.md](docs/source-layout.md)**; the decision and rationale are in [ADR 0012](docs/adr/0012-vertical-slice-package-layout.md).

- **Before** adding a module, moving logic, or wiring a route, read `docs/source-layout.md` to place it in the right slice and on the right side of the dependency rule.
- **You MUST update `docs/source-layout.md` in the same change** whenever you add, move, rename, or remove a slice or a slice's responsibility, or alter the dependency rule. Treat it like any other spec.

## Development commands

This project uses [`uv`](https://docs.astral.sh/uv/). Tests, lint, format, and type-check run through it — there is no separately activated virtualenv, and bare `python`/`pytest` will not find the deps.

- Run the test suite: `uv run pytest` (or a subset: `uv run pytest tests/test_post_approval.py`)
- Lint: `uv run ruff check`
- Format: `uv run ruff format` (CI enforces `uv run ruff format --check` — keep the tree formatted)
- Type-check: `uv run ty check`

## Evidence catalogs & their tooling

Two catalogs hold every **evidence item** (a named claim backed by tests): the threat catalog under `docs/threat-model/` (what the system *prevents*) and `docs/evaluation-capabilities.yaml` (what it *does*). Reach for the tools instead of hand-reading the files.

- **Query / read a threat** (AI-usable JSON): `uv run tools/threat_model.py query stride=Spoofing --only id,title` — filter by any frontmatter field (AND across keys, OR within a repeated key; ATT&CK matching is prefix-aware), project chosen parts with `--only`, `-H` for Markdown. `sections [ID]` lists a threat's `##` sections.
- **Validate** before committing any catalog edit: `uv run tools/threat_model.py validate` **and** `uv run tools/capabilities.py validate`. Both run in the pytest suite, so catalog drift fails CI.
- **The evaluation suite is the union of both catalogs' `tests:`** — `uv run tools/evidence.py suite` lists it, `uv run pytest $(uv run tools/evidence.py suite --format ids)` runs it.

Which catalog a claim belongs in: if an actor **invokes or receives** it, it is a capability; if it is a property the system holds so that an attacker cannot act — and an honest actor never observes it — it is a mitigation and belongs with its threat. The field contracts live in `docs/threat-model/CONTRIBUTING.md` §Tooling and in `docs/evaluation-capabilities.yaml`'s own header.

`docs/mvp-prd.md` §User Stories is **append-only**: capability entries cite those numbers, and nothing would catch a silent re-point.

## Agent skills

### Issue tracker

This repository uses GitHub Issues as its issue tracker. Skills that create or read issues will use the `gh` CLI when available and will fall back to instructions in `docs/agents/issue-tracker.md`.

### Triage labels

Label vocabulary: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md` for mapping and usage.

### Branch & issue workflow

`main` is the default branch but is **not** the per-issue merge target. Work accumulates on an **integration branch** — the current progress-report branch (`progress-report-#`), which tracks everything done since the last progress report. **Do not open per-issue PRs into `main`.**

For each issue:

1. Cut a feature branch off the current integration branch: `git checkout <integration-branch> && git checkout -b <issue#>-<slug>` (e.g. `100-declarative-provisioning`). (The retired `phase<phase>-` prefix came from the initial MVP build-out only — Phases 0–2 in [docs/mvp.md](docs/mvp.md). There is no Phase 3+; post-MVP work is enhancement-driven, named by issue.)
2. Implement, commit, push, then open the PR against the integration branch — **not** `main`: `gh pr create --base <integration-branch>`.
3. **Manually close the issue when its PR merges** (`gh issue close <#> -c "merged via #<pr>"`). Closing keywords (`Closes #N`) only auto-fire on merge into the *default* branch, so they will **not** close an issue merged into the integration branch.

The integration branch merges into `main` only at the progress-report milestone. If an issue's work landed directly on the integration branch (no feature branch), still close it manually.

### Domain docs

Single-context layout: a single `CONTEXT.md` at the repository root and `docs/adr/` for ADRs. See `docs/agents/domain.md` for consumer rules.

### Sverklo — Code Intelligence

Default to the sverklo MCP server for code discovery (its own usage instructions are injected separately). In this repo:

- Explore in order: `sverklo_overview` → `sverklo_search` → `sverklo_lookup` on the top hit. Grep only for exact strings; `sverklo_search` for anything conceptual.
- **MUST run `sverklo_impact` before any rename, deletion, or signature change** — silently breaking a caller is the most expensive bug here. Surface HIGH/CRITICAL warnings to the user.
- Save to memory (`sverklo_remember`) only on user corrections or signal-dense findings (bugs >1h, recurring mistakes, non-obvious architecture) — never routine task summaries.

### Output discipline

No preambles or closing affirmations, no em-dashes as conversational pauses. State the finding, show the fix, stop. User instructions override this file.
