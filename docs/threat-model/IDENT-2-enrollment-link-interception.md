---
id: IDENT-2
title: "Enrollment Link Interception"
stride: ["Spoofing", "Elevation of Privilege"]
attack: [T1586.002]
capability: [L1]
delta: introduced
likelihood_baseline: N/A
likelihood_residual: medium
severity_baseline: N/A
severity_residual: high
bucket: 1
related: [VOTE-2, IDENT-4, IDENT-1, IDENT-3]
tests:
  - tests/accounts/test_activation.py::test_unactivated_seat_cannot_vote_until_admin_activates
  - tests/accounts/test_activation.py::test_enrollment_completion_notifies_the_enrolled_address
  - tests/accounts/test_activation.py::test_activation_requires_a_completed_enrollment
  - tests/accounts/test_activation.py::test_reenrollment_after_reset_lands_in_pending_confirmation
  - tests/accounts/test_admin_portal.py::test_regenerate_link_lets_a_pending_user_enroll
  - tests/accounts/test_admin_portal.py::test_regenerate_invalidates_the_previous_link
  - tests/accounts/test_admin_portal.py::test_deactivate_invalidates_outstanding_enrollment_links
  - tests/accounts/test_enrollment.py::test_expired_link_is_rejected
  - tests/accounts/test_enrollment.py::test_used_link_cannot_be_replayed
---

# IDENT-2 — Enrollment Link Interception

| | |
|---|---|
| **Category** | Spoofing, Elevation of Privilege |
| **Capability** | L1 — a network or mailbox attacker with access to the delivery path (realistically: a compromised email account); no proxy standing required. |
| **What the attacker gains** | A whole Approver identity, from birth. Enrollment is where the identity is created: the admin provisions the account, the proxy delivers a single-use link, and whoever opens it first sets the password, TOTP secret, and Ed25519 keypair. Intercepting the link before the legitimate Approver uses it is not credential theft — it is identity **pre-emption**: the attacker holds a legitimate quorum seat with genuine keys, and the real Approver just finds a dead link. |
| **What they cannot do** | **Vote from the stolen seat before an admin confirms (#128):** completing enrollment lands the account in *pending-confirmation* (`is_active` false), and login and per-vote re-auth both gate on `is_active`, so the intercepted seat casts **no counting vote** until an admin activates it after out-of-band confirmation the attacker cannot obtain — the ① oracle, `tests/accounts/test_activation.py::test_unactivated_seat_cannot_vote_until_admin_activates`. Reuse a consumed link: `tests/accounts/test_enrollment.py::test_used_link_cannot_be_replayed`. Use an expired link — default 24 h, `auth.enrollment_link_expiry_hours` (`src/msig_proxy/core/config.py`): `tests/accounts/test_enrollment.py::test_expired_link_is_rejected`. Survive the admin's remediation — minting a fresh link voids all prior unconsumed links (`tests/accounts/test_admin_portal.py::test_regenerate_invalidates_the_previous_link`), and deactivating or deleting the account voids them without replacement (`::test_deactivate_invalidates_outstanding_enrollment_links`), so an intercepted link dies the moment the admin regenerates, resets, deactivates, or deletes. Publish alone — one stolen seat is one vote of m; reaching a publish means capturing **m separate enrollment links** (or combining with [VOTE-4](VOTE-4-approval-request-fatigue.md)-style coercion of the remaining seats). |
| **Current defenses** | **Admin-gated activation (#128), the detection leg at ①.** A completed enrollment no longer activates the seat: it lands *pending-confirmation* (`is_active` false — enrolled, keys set, but cannot log in or vote), and an admin flips it live via `POST /admin/users/{id}/activate` only after confirming out-of-band that the intended human enrolled. This is **channel-independent** — it does not rely on the email path the interception assumes is compromised — so a silent takeover becomes a race the attacker loses loudly: the real Approver reports "I never enrolled" before the seat can ever vote. Activation itself demands **step-up re-authentication** (fresh password + single-use TOTP, #135 / [VOTE-1](VOTE-1-proxy-session-hijacking.md)), so a hijacked *admin session* cannot self-activate an intercepted seat to complete the takeover without the second factor it never carries (`tests/accounts/test_admin_step_up.py::test_activate_requires_step_up_but_token_revoke_stays_session_only`). The endpoint refuses (`409`) an un-enrolled account, so an admin cannot pre-activate a seat into bypassing the gate (`tests/accounts/test_activation.py::test_activation_requires_a_completed_enrollment`); a credentials reset re-enters pending-confirmation too (`::test_reenrollment_after_reset_lands_in_pending_confirmation`). **Completion notification (leg b):** on enrollment the registered address receives "an account was enrolled for you — if this wasn't you, contact your admin" (`::test_enrollment_completion_notifies_the_enrolled_address`); it rides the same channel the interception may control, so it supplements, never replaces, the admin gate. Single-use links and 24 h expiry (both black-box tested, names above) bound the interception **window**. `notifications.email.fallback_to_portal` (default `true`) lets the admin bypass the channel entirely and hand links over out-of-band — see [IDENT-3](IDENT-3-notification-channel-interception.md). |
| **Operator configuration** | Distribute enrollment links over end-to-end-secure channels — with `fallback_to_portal: true`, hand them over in person or via E2E messaging rather than email. **Actually confirm out-of-band before activating (#128):** the pending-confirmation gate is only as strong as the admin's diligence in verifying with the human before flipping the seat live — activating on the strength of the completion notice alone (which rides the possibly-compromised channel) forfeits the channel-independence that makes the gate ①. Regenerate immediately if an Approver reports a missing or dead link — regeneration kills the outstanding link, so the report-and-reissue loop is a genuine remediation. Enable SMTP TLS. |

**Delta.** Introduced: enrollment links exist only because the proxy exists — in the
baseline direct-publish world, maintainers enroll on PyPI under PyPI's own account
machinery. Both baseline ratings N/A.

**Scope.** IDENT-2 is the highest-severity payload of the link-lifecycle family it shares with
[VOTE-2](VOTE-2-captured-credential-replay.md) and [IDENT-4](IDENT-4-phishable-approver-authentication.md):
all three ride the invariant of a bearer token traveling a channel the proxy cannot secure
end-to-end ([IDENT-3](IDENT-3-notification-channel-interception.md) owns the channel itself). What
sets IDENT-2 apart is that there is no legitimate credential-holder to race or to notice in the
moment — the identity does not exist yet, so the bootstrap secret has no second factor
behind it. The admin who mints these links is the adjacent trust anchor: an attacker who
controls the admin does not need to intercept anything ([IDENT-1](IDENT-1-admin-account-compromise.md)).

**Why bucket ①, per-leg.** The threat splits into a *detection* leg and a *prevention*
leg, and [#128](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/128) moved the
detection leg — now the headline — to ①. Admin-gated activation is an **in-app,
channel-independent** control: the intercepted seat is enrolled but cannot cast a counting
vote until an admin confirms out-of-band and activates, executably demonstrated by
`test_unactivated_seat_cannot_vote_until_admin_activates`. That is a realized proxy defense,
not operator advice, so it sets the headline bucket at ①. **The minority prevention leg
stays ③:** the link reaching *only* the intended human is operator-enforced channel security
by nature — bootstrapping cannot authenticate its recipient, because authentication is what
is being bootstrapped. The single-use and expiry legs remain ①-grade but only bound the
window. So: detection ① (in-app, tested), prevention ③ (operator territory, unchanged).

**Ratings.** Likelihood residual `medium` is a justified downward deviation from the L1
default (high): the window is tight (single-use, 24 h, admin-initiated, recipient expecting
the mail), but mailbox compromise is common enough that `low` would be dishonest.
Severity residual `high`, not critical: the outcome is durable, quiet, legitimate quorum
standing — the worst of the link-lifecycle family — but one seat still cannot move a
publish; m-of-n holds, and critical stays reserved for durable publish-at-will
([HOST-1](HOST-1-proxy-host-compromise.md)'s rung). This is the same containment that makes
[CORE-1](CORE-1-single-approver-account-compromise.md) the flagship improvement.

**ATT&CK mapping.** T1586.002 — *Compromise Accounts: Email Accounts* — is a Resource
Development technique: an adversary compromises a third party's email account to **operate
from it** (send mail as a trusted sender, receive replies, register for services), staged
before the intrusion proper. **Weak fit, tagged with a caveat:** the interception here is the
adversary *reading a delivered secret out of* the recipient's compromised mailbox, which
ATT&CK models most precisely as T1114 *Email Collection* — a Collection technique. T1586.002
is retained as the nearest technique for the mailbox-takeover **precondition** that makes the
interception realistic (TLS makes on-wire capture the rare case, and it has no distinct
Enterprise technique); the collection step itself is the prose remainder. The link's
*delivery channel* is [IDENT-3](IDENT-3-notification-channel-interception.md)'s surface (T1114); what
captured authentication material is worth afterward is [VOTE-2](VOTE-2-captured-credential-replay.md)'s.
