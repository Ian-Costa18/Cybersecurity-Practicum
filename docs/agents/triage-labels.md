# Triage label vocabulary

This file documents the canonical triage labels used by skills that perform automated triage.

Mapping (defaults)

- needs-triage: maintainer needs to evaluate
- needs-info: waiting on reporter
- ready-for-agent: fully specified and AFK-agent-ready
- ready-for-human: needs human implementation
- wontfix: will not be actioned

Idea / enhancement capture (used by the idea-capture flow)

- enhancement: a feature/improvement that *could* be started against today's codebase
- future-enhancement: a valuable idea that *cannot* be started yet — blocked on a missing
  prerequisite (code/infrastructure that doesn't exist) or needing a full PRD first
- use-case: a whole new product capability / access pattern — a sibling to the existing
  forward-auth and one-time patterns, not an increment to one of them. A use case defines
  end-to-end behavior across the proxy, so it **requires a full PRD** before it can be
  sliced for an agent. It is never `ready-for-agent` on its own.
- practicum: a research/coursework deliverable, not a product feature (e.g. formal
  verification); will not become `ready-for-agent` for a coding agent

Distinguishing the "not yet actionable" cases — these answer *why* an idea isn't
`ready-for-agent`, and they do not stack:

- `enhancement` + `needs-info`: feasible now, but underspecified. We could cut a slice
  today; we just need the reporter to answer open questions first.
- `future-enhancement`: not feasible yet. No amount of info unblocks it — something has to
  be built first. Link the blocking issue in the GitHub blocked-by dependency field when a
  concrete open issue is the blocker; otherwise note the architectural prerequisite in prose.
- `use-case` + `needs-info`: a capability-scoped idea. It may even be buildable against
  today's codebase, but it is too large and cross-cutting to slice directly — it needs a
  full PRD authored first. `needs-info` tracks the gap until that PRD exists; the PRD, once
  written, is what unblocks slicing into `ready-for-agent` issues.

Notes

- Skills will attempt to reuse existing labels. If a label does not exist in GitHub, the skill may propose creating it.
- To override these names, edit this file and update the label strings. Re-run the setup skill if you want the agent to refresh its configuration.
