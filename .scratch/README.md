# Local issue fallback

`gh` was unavailable in the environment that created these files, so issues live
here as markdown stand-ins per [docs/agents/issue-tracker.md](../docs/agents/issue-tracker.md)
§Local fallback. Each file under `<area>/NNNN-title.md` carries `title`, `labels`,
and `body` frontmatter and should be promoted to a real GitHub issue (`gh issue
create`) when the CLI is configured, then deleted from here.
