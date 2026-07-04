---
id: CORE-2
title: "API Token Theft"
stride: ["Spoofing", "Elevation of Privilege"]
attack: [T1528, T1552.001]
capability: [L1, L2]
delta: improved
likelihood_baseline: high
likelihood_residual: high
severity_baseline: critical
severity_residual: medium
bucket: 1
related: [CORE-1, HOST-3, PUB-1, PUB-2, VOTE-1, DOS-1, HOST-5]
tests:
  - tests/test_execution.py::test_a_denied_request_never_reaches_pypi
  - tests/approvals/test_votes.py::test_quorum_reached_only_at_the_threshold
  - tests/test_token_auth.py::test_a_revoked_token_is_rejected
  - tests/test_token_auth.py::test_a_token_of_an_inactive_user_is_rejected
---

# CORE-2 — API Token Theft

| | |
|---|---|
| **Category** | Elevation of Privilege (Requester impersonation) |
| **Capability** | L1/L2 — possession of one leaked API token. An API Token is a long-lived bearer credential a User issues for non-interactive tooling (Twine), and it lives where automation runs — CI logs, a `.pypirc` on disk, environment variables, or a non-TLS channel. |
| **What the attacker gains** | Whoever holds the plaintext can impersonate the **Requester** on the submission endpoints (`POST /pypi/legacy/` and equivalents): upload artifacts and open Approval Requests as that User. This is a distinct theft surface from the password + TOTP pair, which the API Token deliberately bypasses (it carries no TOTP step). |
| **What they cannot do** | Get anything published without quorum — every submitted artifact is still hash-bound and m-of-n-gated (the token opens a *request*, not an *outcome*; see [PUB-1](PUB-1-package-swap-between-upload-and-publication.md)). Approve or deny, or log into the User or Admin Portal — the token is scoped to upload endpoints only ([web-proxy.md §API Tokens](../web-proxy.md)). Recover the User's other tokens, password, or TOTP. |
| **Current defenses** | Tokens are stored only as a SHA-256 **hash**; the plaintext is shown once and never persisted (a database read yields useless hashes — see [HOST-3](HOST-3-database-read-compromise.md)). Each token is **individually revocable** without touching the User's other credentials. **Token auth is gated on the owning User's `is_active` at request time**, so a single admin deactivation instantly disables *every* one of that User's tokens without enumerating them ([account-management.md](../account-management.md)) — the fastest containment for a leaked CI credential. TLS protects the token in transit. |
| **Operator configuration** | Store tokens in a secrets manager or the CI platform's secret store, never in a committed `.pypirc`. Rotate (revoke + reissue) on any suspected exposure. To contain a compromised User wholesale, deactivate the account — this kills all their tokens at once. Ensure submission endpoints are reachable only over TLS. |

The mapping is two techniques. **T1528 (Steal Application Access Token):** the API Token is a long-lived application bearer credential; whoever obtains it acts as the issuing User without the interactive password + TOTP flow. A mild fit — T1528's canonical setting is cloud OAuth tokens — but the mechanism is identical: a stolen non-interactive token grants the application's access. **T1552.001 (Unsecured Credentials: Credentials in Files):** the token characteristically leaks from where automation stores it — a committed `.pypirc`, a CI log, an environment dump.

## Rating rationale

`delta: improved` — this is the machine-credential analog of the flagship [CORE-1](CORE-1-single-approver-account-compromise.md). Baseline: a stolen PyPI upload token publishes at will, instantly, with no second party — severity **critical**, likelihood **high** (tokens leak constantly from CI). Through the proxy, a stolen token only lets the holder impersonate the Requester and *open* a hash-bound, m-of-n-gated request; it cannot publish. The theft stays just as likely (likelihood **high** → **high** — the token leaks the same way), but the consequence drops to **medium**: a bounded action — impersonate the Requester, open requests, spend approver attention — that fails safe at quorum. The improvement registers on the severity axis (critical → medium), satisfying the `improved` gate (strictly better on ≥ 1 axis).

## Bucket

Bucket ① (executably demonstrated). *A stolen token cannot publish without quorum* rides the same firing oracle as [PUB-1](PUB-1-package-swap-between-upload-and-publication.md): a submission opens a `pending` request, and the Executor never reaches the PyPI publish path without m signed Votes over the bound hash. Submission is not publication, and that separation is demonstrated, not merely argued: `test_a_denied_request_never_reaches_pypi` (`tests/test_execution.py`) and `test_quorum_reached_only_at_the_threshold` (`tests/approvals/test_votes.py`) assert the publish path is never reached without m signed Votes. The containment mechanics are tested too: `test_a_revoked_token_is_rejected` and `test_a_token_of_an_inactive_user_is_rejected` (`tests/test_token_auth.py`) demonstrate that revocation and `is_active` gating disable a leaked token. No promotion pending — the threat is already at its bucket ceiling; the residual medium consequence (impersonation / request-opening) is an accepted property of any bearer-token surface, contained operationally by revocation and `is_active` gating.
