# TODO

## From Last PR (Progress Report 1)

- [x] Decide on a multi-sig authentication scheme (ADRs 0001–0008, `docs/cryptography.md`)
- [x] Create a flowchart: client machine → web proxy → notification to approvers → approvals → access allowed/denied (`docs/architecture.md`)
- [x] Write authentication system specification (`docs/cryptography.md`, `docs/account-management.md`)
- [x] Write web proxy application specification
- [x] Write notification system specification (`docs/notification-system.md`)
- [x] Write approval system specification (ADR 0001, `docs/approver-authentication.md`)
- [x] Define the request lifecycle state machine (`docs/request-lifecycle.md`)

## System Design

- [x] Create MVP specification document.
- [x] Create a threat model for the entire system. See [threat-model.md](threat-model.md).
- [x] Create a documented constraints file.
- [x] Run a cross-document consistency audit and remediate all findings (R1–R21) across the `docs/` set — security-guarantee gaps (deny-precedence, TOTP single-use, hash re-verify), concurrency/lifecycle correctness, config/spec ownership, design-mismatch rewrites, and research-verified external-claim corrections.

## PRD

- [x] Write a Product Requirements Document (PRD) that captures the problem statement, user stories with acceptance criteria, and evaluation/success metrics. See [mvp-prd.md](mvp-prd.md). Complements `docs/mvp.md` and `docs/architecture.md` without duplicating them.

## Research
