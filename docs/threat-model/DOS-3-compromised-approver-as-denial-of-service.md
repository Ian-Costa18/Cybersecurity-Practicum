---
id: DOS-3
title: "Compromised Approver as Denial-of-Service (Deny Button)"
stride: ["Denial of Service"]
attack: [T1078]
capability: [L3, L7]
delta: introduced
likelihood_baseline: N/A
likelihood_residual: medium
severity_baseline: N/A
severity_residual: low
bucket: 4
related: [CORE-1, DOS-4, DOS-1, DOS-2]
tests:
  - tests/accounts/test_admin_portal.py::test_deactivate_revokes_session_and_blocks_login
  - tests/accounts/test_admin_portal.py::test_a_deactivated_approver_cannot_vote
  - tests/approvals/test_votes.py::test_a_flip_to_deny_before_quorum_closes_denied
  - tests/approvals/test_votes.py::test_withdraw_drops_an_approval_below_quorum
---

# DOS-3 — Compromised Approver as Denial-of-Service (Deny Button)

| | |
|---|---|
| **Category** | Denial of Service |
| **Capability** | L3 or L7. L3, not L2: casting any vote (including every flip) costs a fresh password **and** TOTP re-authentication, so a bare stolen password is not enough. |
| **What the attacker gains** | The ability to halt any request by clicking Deny, regardless of how many other approvers have already approved — one approver identity blocks quorum. Under the append-only vote model ([ADR 0009](../adr/0009-append-only-vote-model.md)) the same identity can also *flap* — repeatedly approve-then-withdraw while the request is `pending` — to spam endorser-outcome notifications ([DOS-1](DOS-1-request-resource-flooding.md)) and game quorum timing. |
| **What they cannot do** | Approve the action unilaterally — the veto only blocks, it never redirects. And they cannot act *silently*: every deny and every flip is an individually signed, attributed, audited vote (see [DOS-4](DOS-4-approver-withholding.md) for the traceless alternative). |
| **Current defenses** | Admin portal account deactivation: setting `is_active = false` immediately revokes the approver's session and blocks both login and voting on in-flight requests — executable-verified by `tests/accounts/test_admin_portal.py::test_deactivate_revokes_session_and_blocks_login` and `test_a_deactivated_approver_cannot_vote`. This is a response lever, not prevention: the denies already cast stand. |
| **Operator configuration** | Maintain a responsive admin contact who can deactivate accounts quickly. Set quorum so losing one approver to deactivation does not block legitimate requests (e.g., 2-of-4 still works with one account out). Write an incident runbook for approver deactivation. Monitor denial patterns as *alert-only* judgment calls — see below for why this cannot be automated. |

**The underlying invariant is the single-approver availability veto**: one enrolled identity
can unilaterally block quorum liveness. Active denial and flapping (this threat) and passive
withholding ([DOS-4](DOS-4-approver-withholding.md)) are the same truth in different clothes — the
"(Deny Button)" in the title names this file's *expression* of the veto, not its extent. The
split into two files earns its keep because the expressions have opposite audit
characteristics: a deny is a signed, non-repudiable, immediately visible vote; withholding
leaves no trace at all.

**Flap mechanics, precisely.** A deny *closes* the request immediately
(`tests/approvals/test_votes.py::test_a_flip_to_deny_before_quorum_closes_denied`), so there
is no deny-flapping — flapping is approve→withdraw churn while the request is still
`pending` (`tests/approvals/test_votes.py::test_withdraw_drops_an_approval_below_quorum`).
Each flip costs a fresh password + TOTP re-authentication and lands as its own signed,
audited vote, so the tactic is rate-bound by the attacker's own re-auth effort and fully
non-repudiable.

**Why denial anomaly detection stays manual.** An automated "this approver denies too much"
signal cannot distinguish an attack from the system *working*: one malicious requester plus
one diligent approver produces exactly the same denial spike. Rate-limiting the deny path is
ruled out by design — the deny is the fail-safe action, and
[IDENT-5](IDENT-5-no-anti-automation-on-authentication-endpoints.md)'s settled limiter design
deliberately never throttles it (a throttled deny would turn an anti-DoS control into a DoS
vector against legitimate denials). Both ideas from earlier drafts are therefore demoted to
alert-only operator monitoring, above.

**Delta.** Introduced: the deny button exists only because the proxy has approvers — the
baseline direct-publish world has no quorum for anyone to block.

**Ratings.** Likelihood residual `medium` — the cheapest listed rung is L3 and the default
applies; no deviation claimed. Severity residual `low`: pure availability, and it **fails
safe** — a blocked publish moves no unauthorized artifact; the bottom rung of the mission
ladder.

**Why bucket ④.** The discriminator: if the operator cannot completely defend or prevent it,
we own it — accepted limitation. A compromised approver's deny is indistinguishable from a
legitimate one at decision time, and the deny path is deliberately never throttled; the
operator's only lever (deactivation) is response after the fact.

**ATT&CK mapping.** T1078 — *Valid Accounts*: the attacker operates a legitimate account's
credentials instead of exploiting a vulnerability — here, a genuine approver identity used
to cast genuine (hostile) votes. ATT&CK has no technique for abusing an approval workflow's
deny action itself; the mapped behavior is the credentialed misuse that enables it.

## Planned defenses

- **Approval request timeouts (auto-deny on deadline)** — [#30](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/30) — no bucket change for DOS-3: the timeout bounds the veto's *silent* form (stalling instead of denying, which is [DOS-4](DOS-4-approver-withholding.md)'s threat and where #30's bucket impact lands); it does not prevent a deny.
