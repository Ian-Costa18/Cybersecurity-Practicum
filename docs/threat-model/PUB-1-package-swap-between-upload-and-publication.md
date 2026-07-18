---
id: PUB-1
title: "Package Swap Between Upload and Publication (Payload Substitution)"
stride: ["Tampering"]
attack: [T1565.001]
capability: [L5]
delta: introduced
likelihood_baseline: N/A
likelihood_residual: low
severity_baseline: N/A
severity_residual: critical
bucket: 1
related: [HOST-1, HOST-2, CORE-2]
tests:
  - tests/service_types/one_time/test_publish.py::test_matching_hash_publishes
  - tests/service_types/one_time/test_publish.py::test_a_mutated_artifact_refuses_and_never_calls_pypi
  - tests/test_execution.py::test_a_mutated_payload_is_refused_at_publish
  - tests/test_execution.py::test_a_denied_request_never_reaches_pypi
  - tests/approvals/test_approve.py::test_artifact_download_returns_the_staged_bytes
---

# PUB-1 — Package Swap Between Upload and Publication (Payload Substitution)

| | |
|---|---|
| **Category** | Tampering |
| **Capability** | L5 — write access to the database, which *is* the artifact store (`StagedArtifact.content` holds the staged bytes) |
| **What the attacker gains** | If the swap succeeded: their artifact on PyPI wearing the quorum's approval — malicious bytes published under approved provenance. |
| **What they cannot do** | Succeed within the upload→publish window. The payload is SHA-256-hashed at upload; approvers approve that specific hash; the Executor re-verifies `SHA-256(held artifact) == action_hash` immediately before publishing, so a swapped artifact mismatches and publication is refused — even against full write access to the artifact store. **Out of scope:** a fully compromised proxy (L6) holding the live upload token can ignore its own check and publish anything — an accepted MVP limitation ([mvp-prd.md](../mvp-prd.md) Security ②) owned by [HOST-1](HOST-1-proxy-host-compromise.md). |
| **Current defenses** | Hash binding, executably demonstrated: `test_matching_hash_publishes`, `test_a_mutated_artifact_refuses_and_never_calls_pypi` (`test_publish.py`); `test_a_mutated_payload_is_refused_at_publish`, `test_a_denied_request_never_reaches_pypi` (`test_execution.py`). Approver-side cross-check: the approve page displays the artifact's SHA-256 and a download link so approvers can inspect the exact bytes they authorize ([web-proxy.md](../web-proxy.md) § Approve/Deny Page Content; the download path is tested: `test_artifact_download_returns_the_staged_bytes`). |
| **Operator configuration** | None required. Verify the deployed proxy computes and re-verifies the hash as specified. |

The ATT&CK mapping is T1565.001 (Stored Data Manipulation): the attacker modifies data at
rest — the staged artifact row — so that a downstream process (the Executor) acts on
attacker-chosen content. The consequence consumers would experience is prose-only, per the
catalog convention.

## Rating rationale

`delta: introduced` — the upload→publish window exists only because the proxy stages
artifacts for review; a direct `twine upload` has no such gap, so both baseline ratings
are N/A.

Residual likelihood is **low**, a deliberate deviation below the L5 capability default
(medium): position is not the binding constraint here. A database writer can swap bytes
freely and publication still refuses — succeeding requires producing a SHA-256
second-preimage (cryptographically infeasible) or escalating to executor control, which is
L6 and [HOST-1](HOST-1-proxy-host-compromise.md)'s accepted limitation. Residual severity stays
**critical**: any swap that did succeed would ship unauthorized bytes to PyPI under
approved provenance, the top of the mission ladder.

Bucket ① (black-box tier): the oracle is that the PyPI mock is never invoked with tampered
bytes — four named tests above drive the mutation and assert the refusal.
