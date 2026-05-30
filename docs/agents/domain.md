Domain docs (single-context)

Layout

This repository uses a single-context layout:

- `CONTEXT.md` at the repository root (contains project domain language, glossary, and high-level architecture notes).
- `docs/adr/` for Architecture Decision Records.

Consumer rules for skills

- Skills that consult domain context will look for `CONTEXT.md` at the repo root. If it is missing, skills should prompt the operator to provide one or proceed conservatively.
- ADRs should live under `docs/adr/` and be named with RFC-style filenames (yyyy-mm-dd-title.md). Skills will read ADRs to understand historical decisions.
- For monorepos or multiple domains, use a `CONTEXT-MAP.md` (multi-context); however this repository is configured as single-context.

Next steps

- Consider adding a minimal `CONTEXT.md` describing the repo purpose and key terms so agent skills can operate with better domain knowledge.
