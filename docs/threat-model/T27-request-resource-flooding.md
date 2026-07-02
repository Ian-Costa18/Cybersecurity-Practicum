---
id: T27
title: "Request & Resource Flooding (Denial of Service)"
stride: ["Denial of Service"]
attack: [T1499]
capability: [L2]
delta: introduced
likelihood_baseline: N/A
likelihood_residual: high
severity_baseline: N/A
severity_residual: low
bucket: 3
related: [T2, T12, T25, T26, T30]
---

# T27 — Request & Resource Flooding (Denial of Service)

| | |
|---|---|
| **Category** | Denial of Service |
| **Capability** | L2 — one leaked requester credential: a requester account password or an API token. Every flood rides a valid authenticated identity. |
| **What the attacker gains** | The resource-saturation half of request abuse (split from [T12](T12-approval-request-fatigue.md), which keeps the human-vigilance half). Three legs: (a) **Noise** — legitimate requests buried under a flood of junk ones. (b) **Retry amplification** — a denial closes a request immediately and the requester can immediately open another, so a deny→retry loop generates sustained notification traffic. (c) **Storage exhaustion** — one-time uploads stage raw artifact bytes in the database (`StagedArtifact.content`, `LargeBinary` in `src/msig_proxy/core/models.py`) with **no size or count cap**, so a handful of multi-GB uploads exhausts storage without ever tripping a rate limit. Nothing today limits, throttles, or caps any of the three. |
| **What they cannot do** | Force an approval or bypass quorum — degrading approver judgment is T12's angle, not this one. Nor exceed their authenticated footprint: every flood is attributable to one account or token, so deactivation/revocation stops it cold. |
| **Current defenses** | None specific to flooding. The kill switch is identity revocation: deactivating the abusing account or revoking its token ([T26](T26-api-token-theft.md)) halts the flood immediately — executable-verified by `tests/test_token_auth.py::test_a_token_of_an_inactive_user_is_rejected` and `test_a_revoked_token_is_rejected`. |
| **Operator configuration** | Until limits land, this is the whole defense: monitor approval-request and upload volume and investigate bursts; deactivate requester accounts (or revoke tokens) behaving anomalously; watch database/storage growth, since staged artifacts live in the DB. |

**Boundaries.** vs. [T12](T12-approval-request-fatigue.md): T27 is mechanical — it
saturates queues, notifications, and storage; T12 is the human-factors consequence of the
same request stream (a fatigued approver making a bad call). vs.
[T30](T30-destructive-availability-attack.md): exhaustion by flooding is reversible —
throttle or revoke and the system recovers; destruction is not. vs.
[T25](T25-no-anti-automation-on-authentication-endpoints.md): T25 owns the
*authentication* endpoints (and the T1499.003 sub-technique); T27 owns the authenticated
request-creation and upload surface.

**Delta.** Introduced: the request-creation surface and DB-staged artifact bytes exist only
because the proxy does. In the baseline direct-publish world, flooding PyPI is PyPI's
availability problem, not the maintainer's.

**Ratings.** Likelihood residual `high` — the L2 default, no deviation; if anything the
default is understated while no limit, quota, or cap of any kind exists. Severity residual
`low`: availability only, and it fails safe — a flooded or storage-exhausted proxy stalls
publishes; no unauthorized artifact moves.

**Why bucket ③ (today).** The only live defenses are operator actions — monitoring,
deactivation, revocation. The promotion path is per leg, tracked below: each planned limit
has a black-box oracle, so the flooding legs and the storage leg each move ③ → ① as their
issue lands.

**ATT&CK mapping.** T1499 — *Endpoint Denial of Service*: the attacker exhausts a service's
capacity through the application itself rather than the network — here, request floods,
notification churn, and uncapped uploads. The parent technique, deliberately: the
*Application Exhaustion Flood* sub-technique (T1499.003) is
[T25](T25-no-anti-automation-on-authentication-endpoints.md)'s tag for the auth endpoints,
and T27 spans more than flooding. T1498 (*Network Denial of Service*) is **not** claimed —
the "amplification" here is application-level notification churn, not volumetric network
traffic, and tagging it would force a false mapping.

## Planned defenses

- **Request-creation rate limiting, per-requester/per-service quotas, post-denial cooldown, volume anomaly alerting** — [#32](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/32) — promotes the flooding legs (noise, retry amplification) ③ → ①: flood → throttled is black-box testable.
- **Maximum upload size + per-service artifact-count cap** — [#126](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/126) — promotes the storage leg ③ → ①: oversized upload → rejected is black-box testable. Filed from this review; deliberately separate from #32 (different mechanism — upload-edge validation vs. rate limiting — against a different resource).
