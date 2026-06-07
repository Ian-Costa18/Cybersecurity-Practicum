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

Local fallback

If the repository is offline or the operator prefers local files, use the `.scratch/` pattern and place markdown issue files under `.scratch/<area>/NNNN-title.md` with frontmatter `title`, `labels`, and `body` fields. Documented workflows in `.scratch/README.md` can be added later.
