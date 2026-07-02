---
id: T22
title: "Information Disclosure via Quorum Status & Approver Visibility"
stride: ["Information Disclosure"]
attack: TODO  # MITRE ATT&CK Enterprise technique IDs — issue #107
capability: [L1]
delta: TODO  # net-delta class: improved | inherited | introduced — #107
likelihood_baseline: TODO  # high|medium|low; N/A iff delta: introduced — #107
likelihood_residual: TODO  # high|medium|low — #107
severity_baseline: TODO  # critical|high|medium|low; N/A iff delta: introduced — #107
severity_residual: TODO  # critical|high|medium|low — #107
bucket: TODO  # four-bucket evaluation classification — owned by issue #107
related: []
---

# T22 — Information Disclosure via Quorum Status & Approver Visibility

| | |
|---|---|
| **Category** | Information Disclosure |
| **Capability** | L1 |
| **What the attacker gains** | The approve/deny page shows live quorum status and, per #22, the **identities of the Endorsing Approvers** (Users whose effective vote is approve — e.g. "Approved by Alice & Bob — 2 of 3, waiting on 1 more"). A holder of the approval link learns *who* has approved and how many approvals remain. Approvers who denied, withdrew, or have not yet acted are **not** named. Residual leak: the endorser set could assist social engineering ("Alice and Bob are in; I'll lean on whoever's left"). |
| **What they cannot do** | Forge approvals, or learn the identities of approvers who have not endorsed — deniers, withdrawals, and non-actors are never named, so the silent roster is not exposed. |
| **Current defenses** | The approve/deny page (and its live endorser list) is reachable only with the request's **approval link, an unguessable random UUIDv4**, delivered solely to the eligible approvers via the `request.created` notification. Casting a vote additionally requires fresh password + TOTP re-authentication; *viewing* the page requires only possession of the link. Disclosure is limited to effective-approvers, which is an opt-in act (approving); non-endorser identities are withheld by design. |
| **Planned defenses** | None required. Endorser-identity disclosure to link-holders is an accepted design decision (#22): the link is unguessable and approver-only, only opt-in endorsers are named, and the information cannot forge a vote — judged a low residual risk. |
| **Operator configuration** | No action required. If endorser-identity disclosure among approvers is itself a concern, document the expectation with approvers; the silent roster (non-actors) is never revealed. |
