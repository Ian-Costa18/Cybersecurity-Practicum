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
- [threat-model/00-overview.md](threat-model/00-overview.md) — Adversary, goals, and defenses (entry point for the `threat-model/` per-threat catalog).
- [threat-model/test-mapping.md](threat-model/test-mapping.md) — Test-to-threat mapping: bucket-① claims → named tests + pass/fail oracles, plus the four-bucket results table over owned threats (#111).

## Scope & planning

- [mvp.md](mvp.md) — MVP scope definition (in/out of scope).
- [mvp-prd.md](mvp-prd.md) — PRD: multi-party authorization for package publishing.
- [evaluation-plan.md](evaluation-plan.md) — How the MVP is evaluated: user-story coverage, the executable threat suite, the comparative positioning matrix, and why performance is excluded.
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
