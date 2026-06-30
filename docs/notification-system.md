# Notification System

This document specifies how the proxy notifies people about things that happen in the system — a new approval request awaiting their vote, the outcome of a request they submitted, an enrollment link for a new account.

The notification system is a **best-effort** notifier reacting to events emitted elsewhere. It owns no events and no state machine of its own. It draws on two event sources, decides who should be told, renders a message, and delivers it. If delivery fails, nothing upstream is affected.

See [CONTEXT.md](../CONTEXT.md) for glossary terms (User, Requester, Approver, Approval Request, Service Grant, Action, Approval Link). The decoupling principle is recorded in [ADR 0005](adr/0005-decoupled-notification-system.md).

## What it is, and what it is not

| It is | It is not |
|---|---|
| A reactive notifier for lifecycle and account events | A source of events or truth about request state |
| A delivery layer (SMTP email in MVP) | A step the approval flow waits on |
| Best-effort — a dropped notification is recoverable | Critical — it can never block, delay, or roll back an approval |

This is the enforceable form of [ADR 0005](adr/0005-decoupled-notification-system.md): the lifecycle advances and emits *blind*; the notification system reacts after the fact. A failed or delayed notification can never corrupt state. Contrast with the **audit** and **handoff/executor** consumers, which are *critical* (a missed event there is a system fault) — see [request-lifecycle.md § Consumers and reliability classes](request-lifecycle.md).

## Event sources

The notification system draws on **two catalogs**, each owned by the document that produces the events:

1. **Request-lifecycle events** — `request.*`, `action.*`, `grant.*`. Source of truth: [request-lifecycle.md § Event catalog](request-lifecycle.md). These are routed by **subscribing to the event bus**.
2. **Account events** — `account.*`. Source of truth: [account-management.md § Account Events](account-management.md). In the MVP these notifications are delivered by **direct best-effort calls** from the `accounts` slice at the emit site — still best-effort, still never blocking, so the [ADR 0005](adr/0005-decoupled-notification-system.md) guarantee holds — while the `account.*` events themselves are emitted on the bus, where the **audit** subscriber records them. Routing account notifications through the bus subscriber as well is a natural future consolidation.

The notification system **does not redefine** either catalog. It maps events to recipients and messages. If a catalog grows, the notification system gains a candidate event to route; it does not own the addition.

## Recipients

Notifications go to **Users**. A given event resolves to one of:

- **The affected User** — for account events, the subject of the event (the user being enrolled, reset, deactivated, deleted).
- **The Requester** — the User who created the Approval Request, for outcome notifications about their own request.
- **The Approvers** — the snapshotted approver set of an Approval Request (the exact set fixed at creation; see [request-lifecycle.md](request-lifecycle.md)), for the notification that a request needs their vote.
- **The Endorsing Approvers** — the approvers who cast an *approve* vote on the request (see [CONTEXT.md](../CONTEXT.md)), notified of its terminal outcome. By approving, they put their name on the request, so they are told how it ended — distinct from the eligible/snapshot set above and from an approver who denied.

### The approver/requester asymmetry

Approvers and requesters are notified for opposite reasons, and this drives the defaults:

- **Approvers are never "sitting and waiting."** They do not know a request exists until told. The `request.created` email *is* the mechanism that pulls them to the approve/deny page. They therefore **always** receive `request.created`, for both service types, and this is never suppressed.
- **A requester may already be watching.** A forward-auth requester waits in the browser and sees the result live; a one-time requester has walked away and needs to be told asynchronously. Requester notifications are therefore the place where service type matters (see defaults below).

This asymmetry — approvers get the `request.created` pull, requesters get outcomes — holds for the *eligible set*. But an approver who actually votes to approve becomes an **Endorsing Approver** and *additionally* receives the request's terminal outcome, the same terminal outcomes the requester receives. They have put their name on the request, so accountability dictates they learn how it ended. This is best-effort like every notification and never blocks the lifecycle.

## Default subscriptions (MVP)

In MVP these defaults are **fixed and hardcoded**. There is no per-user configuration and no settings page — see [Future](#future-enhancements). The defaults below are the complete behavior of the MVP notification system.

A blank recipient means **no notification by default** for that event. Most such events are internal execution mechanics (the quorum-progress UI and the audit trail consume them; users do not need an email per retry).

### Request-lifecycle events

| Event | Default recipient | Message |
|---|---|---|
| `request.created` | **All approvers** (snapshot set) | Approval Link + service name + request summary; "a request needs your vote" |
| `request.vote_recorded` | *(none)* | Internal tally; shown in the UI, not emailed |
| `request.approved` | **Requester** | "Your request was approved." For one-time, execution now begins |
| `request.denied` | **Requester** + **Endorsing Approvers** | "Your request was denied by an approver." |
| `request.cancelled` | *(none)* | Requester withdrew it themselves; nobody else needs telling |
| `request.timed_out` *(future)* | **Requester** | Arrives with the approval-timeout feature |
| `action.queued` | *(none)* | Execution mechanics |
| `action.started` | *(none)* | Execution mechanics |
| `action.retrying` | *(none)* | Execution mechanics; transient retry |
| `action.succeeded` | **Requester** + **Endorsing Approvers** | "Your request completed successfully." (e.g., the package published) |
| `action.failed` | **Requester** + **Endorsing Approvers** | "Your request was approved, but execution failed: \<reason\>." |
| `action.aborted` | *(none)* | Requester withdrew it themselves before execution |
| `grant.activated` | **Requester** + **Endorsing Approvers** | "Access granted." (forward-auth; see note) |
| `grant.expired` | *(none)* | Expiry is expected and silent; requester re-requests if still needed |

**Endorsing Approvers on terminal outcomes.** Where a row lists **Endorsing Approvers** alongside the Requester, the recipients are *only* the approvers who cast an approve vote on that request — not the full snapshot set, and not approvers who denied. They are added on the terminal-outcome events (`request.denied`, `action.succeeded`, `action.failed`, `grant.activated`) because, having endorsed the request, they are accountable for how it ended. For `request.denied` this means an approver who approved is still told when a *later* denial overrode the approval they had given.

**Two outcome axes.** `request.approved` settles the *approval* axis only. For a one-time service the *execution* outcome (`action.succeeded` / `action.failed`) is decided later by the external service — so a requester whose request was `approved` may still receive a later `action.failed`. The messages must not conflate the two: `approved` ≠ "it's live." This mirrors the two-aggregate model in [request-lifecycle.md](request-lifecycle.md).

**`grant.activated` for forward-auth.** The requester is typically in the browser and sees access granted live, so this email is somewhat redundant. It is kept on by default for parity (a confirmation never hurts) and because suppressing it correctly requires knowing whether the requester has an active session — an optimization deferred to [Future](#future-enhancements).

### Account events

The recipient is always the **affected User**. Source: [account-management.md § Account Events](account-management.md).

| Event | Default recipient | Message |
|---|---|---|
| `account.enrollment_issued` | Affected User | Enrollment link (`/enroll/{token}`) to set password + TOTP |
| `account.credentials_reset` | Affected User | Fresh enrollment link (a reset is a re-enrollment) |
| `account.deactivated` | Affected User | "Your account has been deactivated; contact your admin." No link |
| `account.deleted` | Affected User | "Your account has been deleted; contact your admin." No link |

`account.deactivated` / `account.deleted` notify the affected user for transparency. The tip-off risk to a compromised account is low: deactivation/deletion has already cut off that account's access, so the message grants the attacker nothing.

## Delivery

### SMTP email (MVP)

The single delivery backend in MVP is **SMTP email**. When a subscribed event fires, the proxy renders the message and emails the recipient at their registered address (`users.email`; see [account-management.md](account-management.md)).

### Portal fallback

If email delivery fails — or email is disabled entirely via `notifications.email.enabled: false` — the proxy does **not** fail hard. For notifications that carry an actionable link (Approval Links, enrollment links), the link is displayed in the **Admin Portal** so an operator can copy and hand-distribute it manually (`fallback_to_portal: true`). This is **operator-mediated** and the degraded-mode path, not the primary one — the User Portal grants no self-service "view fallback link" capability.

**Reachability anchors to the Approval Request record, not to the notification.** An Approval Link's reachability derives from the **critically-written Approval Request** (the snapshot approver set and link are persisted with the request — a guaranteed write), *not* from this best-effort notification-side rendering. The operator can therefore always recover the link from the request even if the notification itself was never delivered. One caveat: a displayed fallback Approval Link still **dies on `account.deactivated`** — an approver's in-flight approval links are invalidated on deactivation (see [account-management.md](account-management.md)), so a recovered link for a since-deactivated approver will no longer authenticate.

Informational notifications with no link (`account.deactivated`, `account.deleted`, plain outcome messages) have nothing to fall back to; a failed send for these is simply logged and dropped, consistent with best-effort delivery.

### Best-effort guarantee

Delivery is attempted **after** the emitting transition has already committed. A delivery failure is logged and never propagates back to the lifecycle. There is no MVP retry queue for notifications (distinct from the *Action* executor's retry, which is a lifecycle concern, not a notification concern). At-least-once delivery with a retry/outbox is a possible future hardening, but is not required for correctness because no system invariant depends on a notification arriving.

## Configuration

Notification delivery is configured under the `notifications.email` block. The authoritative field reference is [config.md § notifications](config.md); summarized here:

```yaml
notifications:
  email:
    enabled: true
    smtp_host: smtp.example.com
    smtp_port: 587
    smtp_user: proxy@example.com
    smtp_password: $ENV{SMTP_PASSWORD}
    from_address: "Auth Proxy <proxy@example.com>"
    tls: true
    fallback_to_portal: true
```

- `enabled: false` turns off email entirely; all link-bearing notifications then rely on the portal fallback.
- `smtp_password` is referenced via environment-variable substitution (`$ENV{...}`) and never stored in plaintext in the config file.
- `fallback_to_portal: true` is recommended so a misconfigured SMTP server degrades gracefully instead of blocking operators.

There is no per-event or per-user notification configuration in MVP; the default subscription matrix above is the entire behavior.

## Future enhancements

These are explicitly **out of MVP scope** and recorded so the seams are visible:

- **Per-user subscription settings page.** A settings page where users opt in/out of events over the default matrix — e.g., an approver opts in to outcome notifications for requests they voted on; a one-time requester opts down to terminal outcomes only. The mechanism is per-user subscription; the MVP exposes only the fixed defaults. See [request-lifecycle.md](request-lifecycle.md), which marks subscriptions as fixed in MVP.
- **Apprise multi-backend delivery.** Integrate [Apprise](https://github.com/caronc/apprise) to deliver via Slack, Discord, Telegram, webhooks, SMS, push, etc., in addition to or instead of SMTP — one library: register each destination with `apobj.add(url)`, then send with `apobj.notify(body=..., title=...)`, configured per operator. Low effort once the SMTP path exists. See [#20](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/20).
- **Active-session suppression.** Suppress requester notifications (notably `grant.activated`) when the requester has an active browser session and is already watching the result live. Depends on the proxy being able to detect an active connection at emission time.
- **Reminders.** Re-notify approvers about a still-pending request after an interval ("pending since 2 hours ago"). Pairs naturally with the approval-timeout feature. See [#31](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/31) and [use-cases/02-shared-account-management.md](use-cases/02-shared-account-management.md).
- **Admin notifications.** Notify admins of security-relevant events — request floods / approval-fatigue bursts (subscribing `request.created` for [threat-model.md T12](threat-model.md) anomaly detection), repeated `action.failed`, etc. No admin-facing notifications exist in MVP.
- **At-least-once delivery.** A retry/outbox for notifications, if best-effort proves insufficient operationally.
