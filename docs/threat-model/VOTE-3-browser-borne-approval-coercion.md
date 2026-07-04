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
tests:
  - tests/approvals/test_approve.py::test_a_vote_requires_fresh_reauthentication
  - tests/approvals/test_approve.py::test_approve_page_forbids_framing
---

# VOTE-3 — Browser-Borne Approval Coercion

| | |
|---|---|
| **Category** | Elevation of Privilege |
| **Capability** | L1 — a web attacker who can get an Approver to visit a page they control (or view content they can shape). No credential, no foothold. |
| **What the attacker gains** | A vote shaped through the Approver's own browser. Two instances of the invariant: (a) **CSRF** — a malicious page forges an approve POST to `/approve/{id}` from the Approver's browser; (b) **UI-redress / clickjacking** — the attacker frames or overlays the *real* approve page and disguises what the Approver is clicking, so a genuine password + TOTP ceremony produces a vote whose meaning the victim misread. |
| **What they cannot do** | Cast any vote without the Approver's live credentials. Approver sessions are stateless: every `POST /approve/{id}` carries username + password + TOTP in the form body (`src/msig_proxy/approvals/approve.py`), and the approval flow sets **no cookie** — so a cross-site forged request arrives credential-less and is rejected with 401. Demonstrated black-box by `tests/approvals/test_approve.py::test_a_vote_requires_fresh_reauthentication` (bad credentials → 401, zero votes recorded, request still pending). |
| **Current defenses** | Two legs, both closed in-app. **CSRF:** the architecture itself — classic CSRF rides an *ambient* credential the browser attaches automatically, and the approval flow has none to ride (per-vote re-authentication is the design, `docs/web-proxy.md` §Approver Authentication Flow). Where ambient credentials *do* exist (the Requester/admin Proxy Session), the cookie is issued `HttpOnly + Secure + SameSite=Strict` (`src/msig_proxy/auth/login.py`), so browsers refuse to attach it cross-site — see [VOTE-1](VOTE-1-proxy-session-hijacking.md). **UI-redress:** the app serves anti-framing headers on every response — `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'` — from a middleware in the composition root (`src/msig_proxy/app.py`), so a browser refuses to frame the approve page and the clickjacking overlay cannot render. Demonstrated black-box by `tests/approvals/test_approve.py::test_approve_page_forbids_framing` (both headers asserted on the approve-page response). |
| **Operator configuration** | Defense-in-depth only, no longer load-bearing: deploy the proxy on its own dedicated domain (also credited to [VOTE-1](VOTE-1-proxy-session-hijacking.md)). A reverse proxy may echo the anti-framing headers, but the app now sets them itself. |

**Delta.** Introduced: the approve/deny form exists only because the proxy exists — the
baseline direct-publish world has no approval UI for a browser to coerce.

**Scope.** CSRF is the primary instance, not the extent: the invariant is *browser-borne
coercion of the approval action* — any attack that rides the Approver's own browser to
produce or reshape a vote. Clickjacking/UI-redress is the second instance, and the one the
architecture does not kill by itself: an attacker cannot forge a vote, but can still try to
disguise a genuine one. That residual is small — the victim must complete a full username +
password + TOTP ceremony inside the attacker's framing, during a live approval window — and
the anti-framing headers ([#127](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/127))
now close it: a compliant browser refuses to frame the approve page at all.

**Why bucket ①.** The core claim — a forged cross-site vote is impossible because there is
no ambient credential — is executably demonstrated:
`tests/approvals/test_approve.py::test_a_vote_requires_fresh_reauthentication` posts a vote
with wrong credentials and asserts 401 with nothing recorded. Per-leg: the UI-redress leg is
now ① too — [#127](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/127) shipped
the in-app anti-framing headers, and `test_approve_page_forbids_framing` asserts both
`X-Frame-Options: DENY` and CSP `frame-ancestors 'none'` on the approve-page response. (It was
③ operator-anti-framing before; the promotion ③ → ① is why the leg is no longer a residual.)

**Ratings.** Likelihood residual `low` is a justified downward deviation from the L1
default (high): the cheap, scalable form of this attack — classic CSRF — is architecturally
foreclosed, and the UI-redress leg is now blocked in-app for any compliant browser by the
[#127](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/127) anti-framing
headers. What is left is the narrow sliver those headers cannot reach — a victim on a
non-conforming/legacy client, coaxed through a full authentication ceremony — which is
bespoke social engineering, not a commodity attack. Severity residual `high`: a coerced vote is a
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
