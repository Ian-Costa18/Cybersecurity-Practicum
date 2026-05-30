Triage label vocabulary

This file documents the five canonical triage labels used by skills that perform automated triage.

Mapping (defaults)

- needs-triage: maintainer needs to evaluate
- needs-info: waiting on reporter
- ready-for-agent: fully specified and AFK-agent-ready
- ready-for-human: needs human implementation
- wontfix: will not be actioned

Notes

- Skills will attempt to reuse existing labels. If a label does not exist in GitHub, the skill may propose creating it.
- To override these names, edit this file and update the label strings. Re-run the setup skill if you want the agent to refresh its configuration.
