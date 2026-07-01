---
id: T25
title: "No Anti-Automation on Authentication Endpoints"
stride: ["Elevation of Privilege", "Denial of Service"]
capability: [L1, L2]
bucket: TODO  # four-bucket evaluation classification — owned by issue #107
related: [T1, T8, T12, T14, T23, T27]
---

# T25 — No Anti-Automation on Authentication Endpoints

| | |
|---|---|
| **Category** | Elevation of Privilege (second-factor bypass), Denial of Service |
| **Capability** | L2 (knows the password → online TOTP brute-force); L1 (unauthenticated CPU exhaustion) |
| **What the attacker gains** | There is no rate limiting, lockout, or backoff on any authentication path, and **failed attempts consume nothing** — the verifier records the TOTP time-step only *after* both factors verify ([approver-authentication.md](../approver-authentication.md)), so guessing is unlimited. (a) **Second-factor bypass (L2):** an attacker who already holds the password can brute-force the 6-digit TOTP online — at `totp_window: 1` roughly three of 10^6 codes are valid at any instant, with unlimited tries — defeating the TOTP factor and collapsing the L2→L3 gap that **T1** leans on ("both factors must be compromised simultaneously"). (b) **CPU-exhaustion DoS (L1):** every attempt forces a full bcrypt verification (~300 ms), so a flood of bogus logins saturates CPU. The gap spans `POST /login` and `POST /approve/{id}` (shared verifier) and `POST /pypi/legacy/` (API-token resolution). |
| **What they cannot do** | Brute-force the **password** online (each attempt would also need a simultaneously-valid TOTP — infeasible). Reach quorum from one bypassed account — m-of-n still holds, so a single second-factor bypass cannot unilaterally approve (it lowers the cost of the L3 capability in **T1**, not of quorum). Replay an *accepted* TOTP code — single-use enforcement (RFC 6238 §5.2) burns it (**T8**). |
| **Current defenses** | The bcrypt cost (~300 ms/attempt) is an *incidental* throughput cap, not a real limiter. The indistinguishable-failure property (no leak of which factor failed or whether the account exists) denies the attacker an oracle. TOTP single-use prevents replay of a redeemed code. There is **no actual rate limiting or lockout** — a documented gap. |
| **Planned defenses** | **In-proxy per-IP throttle with backoff** (`429 + Retry-After`, *not* a hard per-account lock — a per-account lock would just trade this threat for a fresh DoS, letting an attacker lock out an honest approver), implemented as a DB-backed counter mirroring the existing single-use-TOTP ledger and gated by a `Depends` guard on the auth endpoints; the `Deny` path is never throttled. The client IP is taken from `X-Forwarded-For` only behind a declared trusted reverse proxy (else the raw socket IP), so a direct attacker cannot forge fresh IPs. This is **testable as an executable threat** ([evaluation-plan.md](../evaluation-plan.md) bucket ①), which is the point — it converts T25/T23 and part of T12/T27 from operator-config into a regression test. Tracked as the in-proxy rate-limiting work item. |
| **Operator configuration** | Where a reverse proxy or WAF fronts the proxy, enable request rate limiting on `/login`, `/approve`, and `/pypi/legacy/` **today** (available now in forward-auth deployments). Deploy over TLS; alert on bursts of authentication failures. **Residual:** per-IP limiting is only as good as the trusted-proxy boundary (cf. T14), and NAT / shared egress means thresholds must be generous and *alerting*, not hard blocks. |
