---
id: T25
title: "No Anti-Automation on Authentication Endpoints"
stride: ["Elevation of Privilege", "Denial of Service"]
attack: [T1110, T1499.003]
capability: [L1, L2]
delta: introduced
likelihood_baseline: N/A
likelihood_residual: high
severity_baseline: N/A
severity_residual: high
bucket: 3
related: [T1, T8, T12, T14, T23, T27]
---

# T25 — No Anti-Automation on Authentication Endpoints

| | |
|---|---|
| **Category** | Elevation of Privilege (second-factor bypass), Denial of Service |
| **Capability** | L2 (knows the password → online TOTP brute-force); L1 (unauthenticated CPU exhaustion) |
| **What the attacker gains** | There is no rate limiting, lockout, or backoff on any authentication path, and **failed attempts consume nothing** — the verifier records the TOTP time-step only *after* both factors verify ([approver-authentication.md](../approver-authentication.md)), so guessing is unlimited. (a) **Second-factor bypass (L2):** an attacker who already holds the password can brute-force the 6-digit TOTP online — at `totp_window: 1` roughly three of 10^6 codes are valid at any instant, with unlimited tries — defeating the TOTP factor and collapsing the L2→L3 gap that [T1](T01-single-approver-account-compromise.md) leans on. (b) **CPU-exhaustion DoS (L1):** every attempt forces a full bcrypt verification (~300 ms), so a flood of bogus logins saturates CPU. The gap spans `POST /login` and `POST /approve/{id}` (shared verifier) and `POST /pypi/legacy/` (API-token resolution). |
| **What they cannot do** | Brute-force the **password** online (each attempt would also need a simultaneously-valid TOTP — infeasible). Reach quorum from one bypassed account — m-of-n still holds, so a single second-factor bypass cannot unilaterally approve (it lowers the cost of the L3 capability in [T1](T01-single-approver-account-compromise.md), not of quorum). Replay an *accepted* TOTP code — single-use enforcement (RFC 6238 §5.2) burns it ([T8](T08-approval-link-replay.md)). |
| **Current defenses** | The bcrypt cost (~300 ms/attempt) is an *incidental* throughput cap, not a real limiter. The indistinguishable-failure property (no leak of which factor failed or whether the account exists) denies the attacker an oracle. TOTP single-use prevents replay of a redeemed code. There is **no actual rate limiting or lockout** — a documented gap, closed by #123. |
| **Operator configuration** | Where a reverse proxy or WAF fronts the proxy, enable request rate limiting on `/login`, `/approve`, and `/pypi/legacy/` **today**. Deploy over TLS; alert on bursts of authentication failures. **Residual:** per-IP limiting is only as good as the trusted-proxy boundary (cf. [T14](T14-proxy-bypass.md)), and NAT / shared egress means thresholds must be generous and *alerting*, not hard blocks. |

The ATT&CK mapping is two techniques. **T1110 (Brute Force):** unlimited online guessing of the 6-digit TOTP second factor, because failed attempts are never counted or throttled. The parent is tagged deliberately: no sub-technique covers online OTP guessing — T1110.001 (*Password Guessing*) would misstate the guessed factor, and the body rules password-guessing out (same deliberate-parent pattern as [T27](T27-request-resource-flooding.md)'s T1499). **T1499.003 (Endpoint Denial of Service: Application Exhaustion Flood):** flooding the authentication endpoints so each attempt burns a full ~300 ms bcrypt verification, saturating CPU.

## Rating rationale

`delta: introduced` — the approver-authentication endpoints and their missing-limiter gap are proxy machinery; direct `twine upload` to PyPI has no equivalent login surface. Both baselines are N/A. Residual likelihood is **high**: no limiter exists today, so online guessing and flooding are genuinely unbounded. Residual severity is **high**, taken from the worse of the two heads — the second-factor bypass corrupts an authentication input while quorum (≥1 barrier) still stands, so no unilateral publish, which is high; the CPU-exhaustion head is availability-only (low). The threat is rated at the maximum of the two.

## Bucket

Bucket ③ **today** (operator-enforced: reverse-proxy / WAF rate limiting), promoting to **①** once #123 lands. The in-proxy throttle is deliberately testable as an executable threat — hammer `/login` with bogus credentials and assert `429 + Retry-After` fires before CPU saturation; drive online TOTP guesses against a known password and assert backoff defeats the rate — which is the point: it converts T25 (and [T23](T23-timing-attack-on-bcrypt-verification.md), and part of [T12](T12-approval-fatigue-mfa-bombing.md) / [T27](T27-request-resource-flooding.md)) from operator-config into a regression test.

## Planned defenses

- **In-proxy per-IP throttle with backoff (`429 + Retry-After`, *not* a hard per-account lock)** — #123 — a DB-backed counter mirroring the single-use-TOTP ledger, gated by a `Depends` guard on the auth endpoints; the Deny path is never throttled, and the client IP is trusted from `X-Forwarded-For` only behind a declared reverse proxy (else the raw socket IP), so a direct attacker cannot mint fresh IPs. Moves the bucket **③ → ①**. A hard per-account lock is deliberately rejected — it would trade this threat for a fresh DoS that locks out honest approvers.
