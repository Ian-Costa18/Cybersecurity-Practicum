# Documentation Index

Navigation map for this repository's prose docs. Start here to find where a topic lives.
For domain terminology and architectural principles, see the root [CONTEXT.md](../CONTEXT.md).
For code discovery, use the sverklo index (`sverklo_overview` / `sverklo_search`) over [src/msig_proxy/](../src/msig_proxy/), not these docs.

## Specification & design

- [architecture.md](architecture.md) — System architecture: components and how a request flows through them.
- [source-layout.md](source-layout.md) — Package structure: the vertical slices in `src/msig_proxy/` and the dependency rule that governs them.
- [web-proxy.md](web-proxy.md) — Web proxy application specification (forward-auth and standalone behavior).
- [request-lifecycle.md](request-lifecycle.md) — Lifecycle of an Approval Request from creation to terminal state and post-approval handoff.
- [approver-authentication.md](approver-authentication.md) — How Approvers authenticate and how approvals are signed.
- [account-management.md](account-management.md) — User account management and admin authentication.
- [notification-system.md](notification-system.md) — Decoupled notification layer (SMTP-first; pluggable backends).
- [cryptography.md](cryptography.md) — Cryptographic design and primitive usage.
- [config.md](config.md) — Configuration reference (per-service YAML / ACL).
- [deployment.md](deployment.md) — Container deployment: the standalone image and the compose dev/demo stacks.
- [constraints.md](constraints.md) — System constraints and accepted MVP limitations.
- [threat-model/00-overview.md](threat-model/00-overview.md) — Adversary, goals, and defenses (entry point for the `threat-model/` per-threat catalog); carries the four-bucket classification and Residual Risk Matrix (#111).
- [threat-model/operator-checklist.md](threat-model/operator-checklist.md) — The deployment configuration an operator must apply — the concrete work behind every ③ operator-enforced threat.
- Test-to-threat mapping (#111) — each threat's `tests:` frontmatter field (backing pytest node ids, CI-validated to resolve to real tests). Query with `uv run tools/threat_model.py query bucket=1 --only id,tests`, or browse it live in the #130 dashboard (`threat-model/threat_model_dashboard.py`); the per-claim oracle prose is each threat's *Current defenses* row.

## Scope & planning

- [mvp.md](mvp.md) — MVP scope definition (in/out of scope).
- [mvp-prd.md](mvp-prd.md) — PRD: multi-party authorization for package publishing.
- [evaluation-plan.md](evaluation-plan.md) — How the MVP is evaluated: user-story coverage, the executable threat suite, the comparative positioning matrix, and why performance is excluded.
- [evaluation-capabilities.yaml](evaluation-capabilities.yaml) — The capabilities catalog: what the system does, the user stories each capability satisfies, and the tests that back it. With the threat catalog it forms the evidence catalog, whose union of tests *is* the evaluation suite (`uv run tools/evidence.py suite`).
- [evaluation-demo.md](evaluation-demo.md) — PRD for the runnable "it works" demo: a marimo notebook driving the live compose stack through Act 0 (setup) + Act 1 (normal publish) + Act 2 (the 2 a.m. compromise deny).
- [evaluation-action-plan.md](evaluation-action-plan.md) — Living tracker for executing the evaluation plan: phases, dependencies, and remaining work.
- Future ideas — tracked as GitHub issues labelled [`enhancement` / `future-enhancement` / `practicum`](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues?q=is%3Aissue+label%3Aenhancement%2Cfuture-enhancement%2Cpracticum), explicitly out of scope for the MVP.

## Decisions

- [adr/](adr/index.md) — Architecture Decision Records (numbered, RFC-style). See the [ADR index](adr/index.md).

## Use cases

- [use-cases/00-overview.md](use-cases/00-overview.md) — Overview of the multi-party authorization use cases (entry point for the `use-cases/` directory).

## Research

- [research/](research/index.md) — Literature review, use-case research, and the applied-cryptography study track. See the [research index](research/index.md).

## Agent operations

- [agents/domain.md](agents/domain.md) — Domain-docs layout and consumer rules for skills (single-context).
- [agents/issue-tracker.md](agents/issue-tracker.md) — Issue-tracker conventions (GitHub Issues / `gh`).
- [agents/triage-labels.md](agents/triage-labels.md) — Triage label vocabulary and usage.
