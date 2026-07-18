---
id: VOTE-4
title: "Approval-Request Fatigue"
stride: ["Spoofing", "Elevation of Privilege"]
attack: [T1656]
capability: [L2]
delta: introduced
likelihood_baseline: N/A
likelihood_residual: high
severity_baseline: N/A
severity_residual: high
bucket: 2
related: [VOTE-3, INFO-1, IDENT-5, DOS-1, CORE-3]
---

# VOTE-4 — Approval-Request Fatigue

| | |
|---|---|
| **Category** | Spoofing, Elevation of Privilege |
| **Capability** | L2 — one compromised requester credential (account password or API token). The insider variant — a legitimate requester running their own fatigue campaign — is the same attack from an L7-flavored position and is covered by this entry, not tagged separately. |
| **What the attacker gains** | The human-vigilance half of request abuse (the mechanical half — buried queues, notification traffic, storage — is [DOS-1](DOS-1-request-resource-flooding.md)). The attacker floods Approvers with repeated approval requests, exploiting the MVP's immediate-retry-after-denial (the "Request again" button, [web-proxy.md](../web-proxy.md)), so that worn-down Approvers eventually wave one through without real review. The goal is a **wrongful approval**, not unavailability. [INFO-1](INFO-1-information-disclosure-via-quorum-status-approver-visibility.md) sharpens the campaign: the requester's own approve-page view names the endorsers live, telling the attacker exactly who is left to pressure. |
| **What they cannot do** | Force any vote. There is no one-click approval to fatigue: every vote requires the Approver to open the page, enter username + password + TOTP, and explicitly click Approve. The flood pressures judgment; it never bypasses the ceremony, and every flooded request and every vote is journaled and attributed to the flooding identity. |
| **Current defenses** | The design's friction, argued in "Why bucket ②" below: the per-vote authentication ceremony, the artifact hash + download link giving each Approver something concrete to verify, and the m-of-n backstop — all m Approvers must independently lapse for a wrongful publish. The kill switch is shared with DOS-1: deactivating the flooding account (or revoking its token) stops the campaign cold. |
| **Operator configuration** | Onboard Approvers with the one rule that defeats this attack: **never approve a request you cannot positively account for** — an unexplained repeat is a reason to deny, not to give in. Until rate limiting lands: monitor request volume per requester, investigate bursts, and deactivate accounts showing fatigue-campaign patterns. |

**Delta.** Introduced: the approval queue and the humans reviewing it exist only because
the proxy exists — the baseline direct-publish world has no Approver to fatigue.

**Scope.** This threat was previously titled "Approval Fatigue / MFA Bombing." The MFA
push-bombing analogy (ATT&CK T1621, *Multi-Factor Authentication Request Generation*)
stays in the body as an explicit **non-mapping**: push bombing works by spamming an
unsolicited prompt the victim can end with one tap of "Approve," and no such prompt exists
here — the proxy's TOTP is *entered* by the Approver during a deliberate ceremony, never
pushed at them (consistent with [taxonomies.md](taxonomies.md)'s T1111-over-T1621 call).
What survives of the analogy is the psychology — wearing a human down with volume — and
that is exactly the residual this entry owns.

**Why bucket ②.** Argued by design. The argument has three legs: (a) there is no reflexive
approval path — each vote is a full authenticated ceremony, so fatigue must defeat a
deliberate act, not a tap; (b) the Approver is handed verification material (artifact
SHA-256 and a download link) that makes "actually check it" cheap; (c) m-of-n means a
single diligent Approver stops the publish — the attack must win *every* seat. The
residual — human judgment degrading under volume — is precisely what a design argument can
cover and no test can demonstrate.

**Ratings.** Likelihood residual `high` is the L2 default, honestly earned today:
retry-after-denial is free and nothing rate-limits request creation (a documented MVP
limitation), so mounting the campaign costs nothing. Severity residual `high`, engaging
the critical rung's first disjunct head-on: yes, a fatigue campaign that defeats **every**
seat ships an artifact — but that tail requires m approvers to independently lapse through
the full authenticated ceremony, which is [CORE-3](CORE-3-insider-collusion.md)'s m-party shape
and is rated there, not re-counted here. What VOTE-4 *owns* is the marginal fatigue-won vote:
an authorization-integrity hit with the m-of-n backstop still standing — the same rung as
every other one-compromised-approver threat ([CORE-1](CORE-1-single-approver-account-compromise.md),
[VOTE-2](VOTE-2-captured-credential-replay.md), [IDENT-4](IDENT-4-phishable-approver-authentication.md)).
`critical` is reserved for an attacker who can publish with **no remaining precondition on
other approvers** ([HOST-1](HOST-1-proxy-host-compromise.md)'s live token,
[CORE-3](CORE-3-insider-collusion.md)'s reliable colluders); fatigue still needs approvers to
approve. Its success is also probabilistic, one-shot, and loud: every campaign is
attributable in the journal, each approver can refuse, and each further bad publish needs
a fresh flood against humans who may have wised up.

**ATT&CK mapping.** T1656 — *Impersonation*: the adversary leans on a trusted identity to
make malicious asks read as routine — here, the compromised requester account lends the
flood the shape of a colleague's ordinary requests. T1621 is named above as the considered
non-mapping.

## Planned defenses

- **Request-abuse limits and burst detection** —
  [#32](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/32) — no bucket
  change (likelihood reducer; ② rests on the design argument, and no test can demonstrate
  human vigilance). #32's body covers all three shapes this file has proposed over time:
  per-requester/per-service rate limits, cooldown-after-denial (a shape of its per-service
  limit question), and burst detection/alerting.
