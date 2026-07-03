---
id: T9
title: "Enrollment Link Interception"
stride: ["Spoofing", "Elevation of Privilege"]
attack: [T1586.002]
capability: [L1]
delta: introduced
likelihood_baseline: N/A
likelihood_residual: medium
severity_baseline: N/A
severity_residual: high
bucket: 3
related: [T8, T10, T13, T16]
---

# T9 — Enrollment Link Interception

| | |
|---|---|
| **Category** | Spoofing, Elevation of Privilege |
| **Capability** | L1 — a network or mailbox attacker with access to the delivery path (realistically: a compromised email account); no proxy standing required. |
| **What the attacker gains** | A whole Approver identity, from birth. Enrollment is where the identity is created: the admin provisions the account, the proxy delivers a single-use link, and whoever opens it first sets the password, TOTP secret, and Ed25519 keypair. Intercepting the link before the legitimate Approver uses it is not credential theft — it is identity **pre-emption**: the attacker holds a legitimate quorum seat with genuine keys, and the real Approver just finds a dead link. |
| **What they cannot do** | Reuse a consumed link: `tests/accounts/test_enrollment.py::test_used_link_cannot_be_replayed`. Use an expired link — default 24 h, `auth.enrollment_link_expiry_hours` (`src/msig_proxy/core/config.py`): `tests/accounts/test_enrollment.py::test_expired_link_is_rejected`. Survive a regeneration — the admin reissuing a link invalidates the old one: `tests/accounts/test_admin_portal.py::test_regenerate_link_lets_a_pending_user_enroll`. Publish alone — one stolen seat is one vote of m; reaching a publish means capturing **m separate enrollment links** (or combining with [T12](T12-approval-request-fatigue.md)-style coercion of the remaining seats). |
| **Current defenses** | Single-use links and 24 h expiry (both black-box tested, names above) bound the interception **window** — they do nothing against interception *inside* the window, which is the threat itself. Admin-initiated provisioning means the real Approver is expecting the mail, so pre-emption tends to surface as "my link doesn't work." `notifications.email.fallback_to_portal` (default `true`) lets the admin bypass the channel entirely and hand links over out-of-band — see [T16](T16-notification-channel-interception.md). |
| **Operator configuration** | Distribute enrollment links over end-to-end-secure channels — with `fallback_to_portal: true`, hand them over in person or via E2E messaging rather than email. Confirm enrollment completion with the Approver out-of-band (the manual version of [#128](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/128)). Regenerate immediately if an Approver reports a missing or dead link. Enable SMTP TLS. |

**Delta.** Introduced: enrollment links exist only because the proxy exists — in the
baseline direct-publish world, maintainers enroll on PyPI under PyPI's own account
machinery. Both baseline ratings N/A.

**Scope.** T9 is the highest-severity payload of the link-lifecycle family it shares with
[T8](T08-captured-credential-replay.md) and [T10](T10-phishable-approver-authentication.md):
all three ride the invariant of a bearer token traveling a channel the proxy cannot secure
end-to-end ([T16](T16-notification-channel-interception.md) owns the channel itself). What
sets T9 apart is that there is no legitimate credential-holder to race or to notice in the
moment — the identity does not exist yet, so the bootstrap secret has no second factor
behind it. The admin who mints these links is the adjacent trust anchor: an attacker who
controls the admin does not need to intercept anything ([T13](T13-admin-account-compromise.md)).

**Why bucket ③.** The headline defense — the link reaches only the intended human — is
operator-enforced channel security by nature: bootstrapping cannot authenticate its
recipient, because authentication is what is being bootstrapped. The tested single-use and
expiry legs are ①-grade but only bound the window; the prevention story lives in the
operator row. Per-leg: [#128](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/128)
promotes the *detection* leg ③ → ①; prevention remains operator territory.

**Ratings.** Likelihood residual `medium` is a justified downward deviation from the L1
default (high): the window is tight (single-use, 24 h, admin-initiated, recipient expecting
the mail), but mailbox compromise is common enough that `low` would be dishonest.
Severity residual `high`, not critical: the outcome is durable, quiet, legitimate quorum
standing — the worst of the link-lifecycle family — but one seat still cannot move a
publish; m-of-n holds, and critical stays reserved for durable publish-at-will
([T4](T04-proxy-host-compromise.md)'s rung). This is the same containment that makes
[T1](T01-single-approver-account-compromise.md) the flagship improvement.

**ATT&CK mapping.** T1586.002 — *Compromise Accounts: Email Accounts* — is a Resource
Development technique: an adversary compromises a third party's email account to **operate
from it** (send mail as a trusted sender, receive replies, register for services), staged
before the intrusion proper. **Weak fit, tagged with a caveat:** the interception here is the
adversary *reading a delivered secret out of* the recipient's compromised mailbox, which
ATT&CK models most precisely as T1114 *Email Collection* — a Collection technique. T1586.002
is retained as the nearest technique for the mailbox-takeover **precondition** that makes the
interception realistic (TLS makes on-wire capture the rare case, and it has no distinct
Enterprise technique); the collection step itself is the prose remainder. The link's
*delivery channel* is [T16](T16-notification-channel-interception.md)'s surface (T1114); what
captured authentication material is worth afterward is [T8](T08-captured-credential-replay.md)'s.

## Planned defenses

- **Out-of-band enrollment confirmation** — [#128](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/128) — gate account activation on confirming (out-of-band, or via completion notification) that the intended human enrolled. Converts silent takeover into a race the attacker loses loudly: the real Approver reports "I never enrolled" before the stolen seat ever votes. Promotes the detection leg ③ → ① once implemented and tested.
