---
id: T27
title: "Request & Resource Flooding (Denial of Service)"
stride: ["Denial of Service"]
attack: TODO  # MITRE ATT&CK Enterprise technique IDs — issue #107
capability: [L2]
delta: TODO  # net-delta class: improved | inherited | introduced — #107
bucket: TODO  # four-bucket evaluation classification — owned by issue #107
related: [T12, T25, T26]
---

# T27 — Request & Resource Flooding (Denial of Service)

| | |
|---|---|
| **Category** | Denial of Service |
| **Capability** | L2 (compromised requester account) or any authenticated requester / API-token holder |
| **What the attacker gains** | The resource-saturation half of request abuse (split from **T12**, which keeps the social-engineering/approval-fatigue half): (a) **Noise** — legitimate requests are buried under a flood. (b) **Retry amplification** — because a single denial immediately closes a request and the Requester can immediately reopen one, a denial→retry loop generates sustained notification traffic. (c) **Storage / DB exhaustion** — one-time uploads stage the artifact bytes in the database (`StagedArtifact.content`) with **no size or count cap**, so large or repeated uploads can exhaust storage. There is currently no rate limit, quota, or upload-size limit. |
| **What they cannot do** | Force an approval or bypass quorum (that is T12's fatigue angle, not this one). Exceed their authenticated footprint — every flood still rides a valid account or API token, so deactivation/revocation stops it. |
| **Current defenses** | None specific. Deactivating the abusing account or revoking its token (**T26**) halts the flood; `is_active` gating makes that immediate. |
| **Planned defenses** | The shared in-proxy rate limiter (**T25**) extended to the request-creation endpoint with **per-requester / per-service quotas** and a **cooldown after denial**. A **configurable maximum upload size** and artifact-count cap for one-time services. Anomaly alerting when a requester's volume exceeds its historical baseline. |
| **Operator configuration** | Until limits land: monitor approval-request and upload volume and investigate bursts; deactivate requester accounts (or revoke tokens) showing anomalous behavior; watch database/storage growth, since staged artifacts live in the DB. |
