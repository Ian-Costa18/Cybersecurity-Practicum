---
id: IDENT-3
title: "Notification-Channel Interception"
stride: ["Information Disclosure", "Spoofing"]
attack: [T1114]
capability: [L1]
delta: inherited
likelihood_baseline: medium
likelihood_residual: medium
severity_baseline: critical
severity_residual: high
bucket: N/A
related: [VOTE-2, IDENT-2, IDENT-4, INFO-1, CORE-1]
tests:
  - tests/accounts/test_admin_portal.py::test_admin_portal_surfaces_pending_approval_links
  - tests/accounts/test_admin_portal.py::test_approval_links_hidden_when_fallback_disabled
  - tests/accounts/test_admin_portal.py::test_link_is_recoverable_when_smtp_is_down
---

# IDENT-3 — Notification-Channel Interception

| | |
|---|---|
| **Category** | Information Disclosure, Spoofing |
| **Capability** | L1 — a network or mailbox attacker on the notification delivery path; no proxy standing required. |
| **What the attacker gains** | The proxy funnels security-relevant material through an out-of-band notification channel it cannot authenticate end-to-end — SMTP in the MVP. Ranked by what transits it: (1) **enrollment links** — the one genuine bootstrap secret; interception here is [IDENT-2](IDENT-2-enrollment-link-interception.md); (2) **approval links** — not secrets (per-vote authentication gates the vote), so interception yields targeting intelligence, not authority; (3) **notification content** — request metadata (package names, requesters, timing) readable by any mailbox observer, the channel-side twin of [INFO-1](INFO-1-information-disclosure-via-quorum-status-approver-visibility.md)'s page-side disclosure. The reverse direction — *injecting* into the channel with mail that impersonates the proxy — is exactly [IDENT-4](IDENT-4-phishable-approver-authentication.md)'s lure. |
| **What they cannot do** | Gain approval authority from an intercepted approval link — casting a vote still requires the full password + TOTP ceremony ([VOTE-2](VOTE-2-captured-credential-replay.md)'s tested mechanics). Force the proxy to use the channel at all for link delivery: `notifications.email.fallback_to_portal` (default `true`, `src/msig_proxy/core/config.py`) surfaces links in the admin portal for out-of-band handoff instead — tested: `tests/accounts/test_admin_portal.py::test_admin_portal_surfaces_pending_approval_links`, `::test_approval_links_hidden_when_fallback_disabled`, `::test_link_is_recoverable_when_smtp_is_down`. |
| **Current defenses** | The channel carries as little authority as the design can manage: approval links are deliberately worthless without authentication, leaving the enrollment link as the only secret in transit — and the portal fallback (tested, above) can take even that off the channel. Channel security itself (TLS, sender authentication) is configuration, not code. |
| **Operator configuration** | Configure SMTP with STARTTLS or SMTPS (`tls: true`); never unencrypted SMTP. Use a reputable provider with SPF, DKIM, and DMARC records on the sender domain — this authenticates the proxy's mail to recipients and starves [IDENT-4](IDENT-4-phishable-approver-authentication.md)'s lure. In high-security deployments, keep `fallback_to_portal: true` and distribute enrollment links out-of-band rather than emailing them. |

**Delta.** Inherited — reclassified from `introduced` in the 2026-07-03 catalog audit,
because the original rationale ("the notification stream exists only because the proxy
exists") was the surface-counting form the net-cancellation rule bans. Re-derive it from
the baseline twin: PyPI emails password-reset links whose interception yields full account
takeover, over the same TLS + SPF/DKIM/DMARC email channel, to the same standard. The
mechanism is identical, so the interception threat cancels: **likelihood medium = medium**
(mailbox compromise is the realistic path in both worlds — the inherited cross-check).
Severity differs (**baseline critical** — a reset link is the whole account and the account
is a unilateral publish — vs residual high, one seat of m), which is permitted for
inherited entries: the payload containment is [CORE-1](CORE-1-single-approver-account-compromise.md)'s
quorum story, credited once there, not a property of this channel. And the proxy-specific
escape hatch — `fallback_to_portal` can take the enrollment secret off the channel
entirely, an option the baseline lacks — does **not** break the cancellation either: it
reduces what the channel *carries*, not the interception surface itself, and by-option
mitigations live in the Operator row, not the delta. What would break it is the proxy
running the channel *below* the baseline standard (say, plain SMTP by default) — it
doesn't.

**Scope.** Retitled from "SMTP Channel Attack" (2026-07-02): SMTP is the MVP instance, not
the invariant. The invariant is the **out-of-band notification channel the proxy cannot
authenticate end-to-end** — and it survives every planned backend, which is why
[#20](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/20) appears below as a
re-inheritance, not a mitigation. Within the link-lifecycle family, IDENT-3 owns the channel;
its two exploits are [IDENT-2](IDENT-2-enrollment-link-interception.md) (intercept the bootstrap
secret) and [IDENT-4](IDENT-4-phishable-approver-authentication.md) (inject the lure); what any
captured material is worth afterward is [VOTE-2](VOTE-2-captured-credential-replay.md)'s.

**Why bucket N/A.** Inherited threats carry no defense-claim bucket: everything that
secures the channel is baseline email hygiene the operator would owe PyPI's channel too —
transport encryption, provider choice, SPF/DKIM/DMARC DNS records. The one proxy-specific
mechanism, the portal fallback, stays cited in `tests:` as evidence the escape hatch exists
in code; whether it is used is deployment policy, so it lives in the Operator row. (The old
body listed DMARC/DKIM/SPF as a planned defense — they are DNS configuration, not future
code, so they live in the operator row now.)

**Ratings.** Likelihood `medium = medium` — the inherited invariant. Residual `medium` is a
justified downward deviation from the L1 default (high), rated deliberately together with
[IDENT-2](IDENT-2-enrollment-link-interception.md), its worst payload: TLS-by-default
deployment makes on-wire capture rare, so the realistic path is mailbox compromise —
common, but not ambient. The baseline rates `medium` by the identical logic on PyPI's reset
channel — same transport, same realistic path. Severity `baseline critical`: an intercepted
PyPI reset link is the whole account, and the account is a unilateral publish. Severity
residual `high` follows the worst payload: the channel carries the enrollment bootstrap
secret, and its worst interception *is* IDENT-2's outcome (a durable quorum seat — one seat
of m, hence high, not critical). Content-only interception would rate medium on the
[INFO-1](INFO-1-information-disclosure-via-quorum-status-approver-visibility.md) rung.

**ATT&CK mapping.** T1114 — *Email Collection*: the adversary collects email from a
compromised mailbox or in transit — the realistic interception path for everything this
channel carries. The injection direction's techniques (T1566.002 *Spearphishing Link*,
T1557 *Adversary-in-the-Middle*) are owned by
[IDENT-4](IDENT-4-phishable-approver-authentication.md) and deliberately not double-tagged here;
the mailbox-takeover route to the same material is tagged on
[IDENT-2](IDENT-2-enrollment-link-interception.md) as T1586.002.

## Planned defenses

- **Multi-backend notifications via Apprise** — [#20](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/20) — listed honestly: it does not fix this threat, it **re-inherits it per channel**. Every backend added (Slack, SMS, push, webhooks) must bring its own interception story — transport security, sender authenticity, and who else can read the destination. **No bucket change** — it re-inherits the threat rather than mitigating it; ③ stands.
