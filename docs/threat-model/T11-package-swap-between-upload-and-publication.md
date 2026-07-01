---
id: T11
title: "Package Swap Between Upload and Publication (Payload Substitution)"
stride: ["Tampering"]
capability: [L6]
bucket: TODO  # four-bucket evaluation classification — owned by issue #107
related: []
---

# T11 — Package Swap Between Upload and Publication (Payload Substitution)

| | |
|---|---|
| **Category** | Tampering |
| **Capability** | L6 (proxy compromise) or attacker with write access to the artifact store |
| **What the attacker gains** | If an attacker can substitute a different artifact after approvers have reviewed and approved the original, the malicious artifact gets published under the approved provenance. |
| **What they cannot do** | Succeed in the **upload→publish substitution** — hash binding blocks it. The payload is hashed at upload time; approvers approve that specific hash; the Executor **re-verifies `SHA-256(held artifact) == action_hash` immediately before publishing**, so if the artifact changes the hash will not match and publication is blocked. **Out of scope:** a *fully compromised proxy that holds the live upload token* could ignore its own hash check and publish a different artifact straight to PyPI — hash binding does not defend that case (an accepted MVP limitation; see [mvp-prd.md](../mvp-prd.md) Security ②). |
| **Current defenses** | Hash binding: payload SHA-256 is computed immediately on upload, recorded in the approval request, and re-verified by the Executor before publishing. Any substitution **in the upload→publish window** causes a hash mismatch and publication is blocked — this holds even against an attacker with write access to the artifact store. It does **not** defend a fully compromised proxy that holds the live token and bypasses its own executor. |
| **Planned defenses** | The hash binding mechanism is a fundamental design principle and effective against payload substitution within the upload→publish window (not against a token-holding compromised proxy — see above). Future enhancements: surface the hash prominently in the approve/deny UI so approvers can cross-check against their local copy. |
| **Operator configuration** | No additional configuration required. Operators should verify the proxy implementation computes and checks the hash as specified in the design. |
