---
id: VOTE-3
title: "Browser-Borne Approval Coercion"
stride: ["Elevation of Privilege"]
attack: []
capability: [L1]
delta: introduced
likelihood_baseline: N/A
likelihood_residual: low
severity_baseline: N/A
severity_residual: high
bucket: 1
related: [IDENT-4, VOTE-4, VOTE-1]
---

# VOTE-3 — Browser-Borne Approval Coercion

| | |
|---|---|
| **Category** | Elevation of Privilege |
| **Capability** | L1 — a web attacker who can get an Approver to visit a page they control (or view content they can shape). No credential, no foothold. |
| **What the attacker gains** | A vote shaped through the Approver's own browser. Two instances of the invariant: (a) **CSRF** — a malicious page forges an approve POST to `/approve/{id}` from the Approver's browser; (b) **UI-redress / clickjacking** — the attacker frames or overlays the *real* approve page and disguises what the Approver is clicking, so a genuine password + TOTP ceremony produces a vote whose meaning the victim misread. |
| **What they cannot do** | Cast any vote without the Approver's live credentials. Approver sessions are stateless: every `POST /approve/{id}` carries username + password + TOTP in the form body (`src/msig_proxy/approvals/approve.py`), and the approval flow sets **no cookie** — so a cross-site forged request arrives credential-less and is rejected with 401. Demonstrated black-box by `tests/approvals/test_approve.py::test_a_vote_requires_fresh_reauthentication` (bad credentials → 401, zero votes recorded, request still pending). |
| **Current defenses** | The architecture itself: classic CSRF rides an *ambient* credential the browser attaches automatically, and the approval flow has none to ride — per-vote re-authentication is the design (`docs/web-proxy.md` §Approver Authentication Flow). Where ambient credentials *do* exist (the Requester/admin Proxy Session), the cookie is issued `HttpOnly + Secure + SameSite=Strict` (`src/msig_proxy/auth/login.py`), so browsers refuse to attach it to cross-site requests — see [VOTE-1](VOTE-1-proxy-session-hijacking.md) for that surface. |
| **Operator configuration** | Until [#127](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/127) lands, anti-framing is operator territory: serve the proxy behind a reverse proxy that adds `X-Frame-Options: DENY` / `Content-Security-Policy: frame-ancestors 'none'`, and deploy it on its own dedicated domain. |

**Delta.** Introduced: the approve/deny form exists only because the proxy exists — the
baseline direct-publish world has no approval UI for a browser to coerce.

**Scope.** CSRF is the primary instance, not the extent: the invariant is *browser-borne
coercion of the approval action* — any attack that rides the Approver's own browser to
produce or reshape a vote. Clickjacking/UI-redress is the second instance, and the one the
architecture does not kill: an attacker cannot forge a vote, but can still try to disguise
a genuine one. That residual is small — the victim must complete a full username +
password + TOTP ceremony inside the attacker's framing, during a live approval window —
but it is the leg the anti-framing headers ([#127](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/127))
exist to close.

**Why bucket ①.** The core claim — a forged cross-site vote is impossible because there is
no ambient credential — is executably demonstrated:
`tests/approvals/test_approve.py::test_a_vote_requires_fresh_reauthentication` posts a vote
with wrong credentials and asserts 401 with nothing recorded. Per-leg: the UI-redress leg
is ③ (operator anti-framing) today; [#127](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/127)
promotes it ③ → ① (header presence is black-box assertable).

**Ratings.** Likelihood residual `low` is a justified downward deviation from the L1
default (high): the cheap, scalable form of this attack — classic CSRF — is architecturally
foreclosed, and what remains is targeted UI-redress requiring the victim to knowingly
perform a full authentication ceremony under the attacker's framing. That is bespoke social
engineering, not a commodity attack. Severity residual `high`: a coerced vote is a
*genuine* signed approval — an authorization-integrity hit — but one vote is not a publish
(m-of-n leaves at least one barrier), and the vote is signed, attributed, and auditable
after the fact.

**ATT&CK mapping.** Empty by considered verdict ([DOS-4](DOS-4-approver-withholding.md)
precedent): ATT&CK Enterprise has no CSRF or clickjacking technique — both live in
CAPEC/OWASP taxonomies (CAPEC-62, CAPEC-103). Near-misses rejected: T1189 *Drive-by
Compromise* is browser **exploitation** (code execution via a visited page), not request
forgery; T1185 *Browser Session Hijacking* requires malware already running in the victim's
browser; T1204 *User Execution* describes the lure's delivery, not this technique. Forcing
any of these would poison the [#111](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/111)
ATT&CK coverage table.

## Planned defenses

- **In-app anti-framing headers** (`X-Frame-Options: DENY`, CSP `frame-ancestors 'none'`) —
  [#127](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/127) — promotes the
  UI-redress leg ③ → ① (one middleware plus a header-assertion test); the CSRF leg is ①
  already.
