---
id: T16
title: "Notification-Channel Interception"
stride: ["Information Disclosure", "Spoofing"]
attack: [T1114]
capability: [L1]
delta: introduced
likelihood_baseline: N/A
likelihood_residual: medium
severity_baseline: N/A
severity_residual: high
bucket: 3
related: [T8, T9, T10, T22]
---

# T16 — Notification-Channel Interception

| | |
|---|---|
| **Category** | Information Disclosure, Spoofing |
| **Capability** | L1 — a network or mailbox attacker on the notification delivery path; no proxy standing required. |
| **What the attacker gains** | The proxy funnels security-relevant material through an out-of-band notification channel it cannot authenticate end-to-end — SMTP in the MVP. Ranked by what transits it: (1) **enrollment links** — the one genuine bootstrap secret; interception here is [T9](T09-enrollment-link-interception.md); (2) **approval links** — not secrets (per-vote authentication gates the vote), so interception yields targeting intelligence, not authority; (3) **notification content** — request metadata (package names, requesters, timing) readable by any mailbox observer, the channel-side twin of [T22](T22-information-disclosure-via-quorum-status-approver-visibility.md)'s page-side disclosure. The reverse direction — *injecting* into the channel with mail that impersonates the proxy — is exactly [T10](T10-phishable-approver-authentication.md)'s lure. |
| **What they cannot do** | Gain approval authority from an intercepted approval link — casting a vote still requires the full password + TOTP ceremony ([T8](T08-captured-credential-replay.md)'s tested mechanics). Force the proxy to use the channel at all for link delivery: `notifications.email.fallback_to_portal` (default `true`, `src/msig_proxy/core/config.py`) surfaces links in the admin portal for out-of-band handoff instead — tested: `tests/accounts/test_admin_portal.py::test_admin_portal_surfaces_pending_approval_links`, `::test_approval_links_hidden_when_fallback_disabled`, `::test_link_is_recoverable_when_smtp_is_down`. |
| **Current defenses** | The channel carries as little authority as the design can manage: approval links are deliberately worthless without authentication, leaving the enrollment link as the only secret in transit — and the portal fallback (tested, above) can take even that off the channel. Channel security itself (TLS, sender authentication) is configuration, not code. |
| **Operator configuration** | Configure SMTP with STARTTLS or SMTPS (`tls: true`); never unencrypted SMTP. Use a reputable provider with SPF, DKIM, and DMARC records on the sender domain — this authenticates the proxy's mail to recipients and starves [T10](T10-phishable-approver-authentication.md)'s lure. In high-security deployments, keep `fallback_to_portal: true` and distribute enrollment links out-of-band rather than emailing them. |

**Delta.** Introduced: the notification stream exists only because the proxy exists — the
baseline direct-publish world has no proxy sending anyone links. Both baseline ratings N/A.

**Scope.** Retitled from "SMTP Channel Attack" (2026-07-02): SMTP is the MVP instance, not
the invariant. The invariant is the **out-of-band notification channel the proxy cannot
authenticate end-to-end** — and it survives every planned backend, which is why
[#20](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/20) appears above as a
re-inheritance, not a mitigation. Within the link-lifecycle family, T16 owns the channel;
its two exploits are [T9](T09-enrollment-link-interception.md) (intercept the bootstrap
secret) and [T10](T10-phishable-approver-authentication.md) (inject the lure); what any
captured material is worth afterward is [T8](T08-captured-credential-replay.md)'s.

**Why bucket ③.** Everything that secures the channel itself is operator-enforced by
nature: transport encryption, provider choice, SPF/DKIM/DMARC DNS records, and the policy
decision to use the portal fallback. The tested fallback legs prove the escape hatch
exists in code; whether it is used is deployment policy. (The old body listed DMARC/DKIM/SPF
as a planned defense — they are DNS configuration, not future code, so they live in the
operator row now.)

**Ratings.** Likelihood residual `medium` is a justified downward deviation from the L1
default (high), rated deliberately together with [T9](T09-enrollment-link-interception.md),
its worst payload: TLS-by-default deployment makes on-wire capture rare, so the realistic
path is mailbox compromise — common, but not ambient. Severity residual `high` follows the
worst payload too: the channel carries the enrollment bootstrap secret, and its worst
interception *is* T9's outcome (a durable quorum seat — one seat of m, hence high, not
critical). Content-only interception would rate medium on the
[T22](T22-information-disclosure-via-quorum-status-approver-visibility.md) rung.

**ATT&CK mapping.** T1114 — *Email Collection*: the adversary collects email from a
compromised mailbox or in transit — the realistic interception path for everything this
channel carries. The injection direction's techniques (T1566.002 *Spearphishing Link*,
T1557 *Adversary-in-the-Middle*) are owned by
[T10](T10-phishable-approver-authentication.md) and deliberately not double-tagged here;
the mailbox-takeover route to the same material is tagged on
[T9](T09-enrollment-link-interception.md) as T1586.002.

## Planned defenses

- **Multi-backend notifications via Apprise** — [#20](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/20) — listed honestly: it does not fix this threat, it **re-inherits it per channel**. Every backend added (Slack, SMS, push, webhooks) must bring its own interception story — transport security, sender authenticity, and who else can read the destination. **No bucket change** — it re-inherits the threat rather than mitigating it; ③ stands.
