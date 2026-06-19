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
- practicum: a research/coursework deliverable, not a product feature (e.g. formal
  verification); will not become `ready-for-agent` for a coding agent

Distinguishing the two "not yet actionable" cases — these answer *why* an idea isn't
`ready-for-agent`, and they do not stack:

- `enhancement` + `needs-info`: feasible now, but underspecified. We could cut a slice
  today; we just need the reporter to answer open questions first.
- `future-enhancement`: not feasible yet. No amount of info unblocks it — something has to
  be built first. Link the blocking issue in the GitHub blocked-by dependency field when a
  concrete open issue is the blocker; otherwise note the architectural prerequisite in prose.

Notes

- Skills will attempt to reuse existing labels. If a label does not exist in GitHub, the skill may propose creating it.
- To override these names, edit this file and update the label strings. Re-run the setup skill if you want the agent to refresh its configuration.
