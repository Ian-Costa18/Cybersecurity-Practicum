# Decoupled Notification System

## Status
Accepted

## Context

The proxy must notify approvers when an approval request is pending. Different organizations may have different notification preferences (email, Slack, Discord, webhook, SMS, etc.). The notification system must be:

1. **Simple to integrate:** Operators can plug in their preferred backend
2. **Decoupled from approval logic:** Notification failures should not block approval flow
3. **Flexible:** Support multiple backends without code changes
4. **MVP-feasible:** For MVP, a minimal implementation is acceptable

## Considered Options

### Option A: Built-in Email Notifications
- Proxy sends emails directly
- **Advantage:** Simple, self-contained
- **Disadvantage:** Limited to email; requires SMTP config; tight coupling; operators cannot easily switch to Slack/Discord

### Option B: Tight Integration with One Service (e.g., Slack)
- Proxy sends Slack messages directly
- **Advantage:** Popular, immediate feedback
- **Disadvantage:** Ties proxy to one platform; other operators need different versions

### Option C: Decoupled Notification + Approval Link Pattern
- Proxy generates an approval link (e.g., `https://proxy.example.com/approve/{approval_id}`) and delivers it out-of-band; the approval flow never calls a notification backend directly
- For MVP, the proxy delivers the link via SMTP email, with manual distribution from the admin portal as a fallback when email is disabled or fails
- Delivery is decoupled from approval logic, so additional backends (via Apprise) can be added later without touching the approval flow
- **Advantage:** Flexible, not tied to any backend; simple approval logic; operators control notification channel
- **Disadvantage:** Operator must configure SMTP for automatic delivery; richer backends (Slack, Discord) are a post-MVP addition

## Decision

**Chosen: Decoupled Notification + Approval Link Pattern (Option C)**

### Approval Link Model

Each approval request is assigned a unique ID. When the request is created, the proxy generates an approval link:

```
https://proxy.example.com/approve/{approval_id}
```

This link is:
- **Not secret:** Anyone with the link can click it, but they still must authenticate as an approver to actually approve.
- **Durable:** The link works as long as the approval request is pending (no expiration for MVP).
- **Auditable:** The approval_id is recorded in logs and the database, linking notifications to approvals.

Approvers click the link, authenticate with their credentials (password + 2FA), and see the approval details (service name, requester, hash if applicable). They click "approve" or "deny."

### Notification Delivery

The proxy delivers notifications via SMTP email. When an approval request is created, the proxy emails each approver their Approval Link directly.

If email delivery fails (or is disabled via `notifications.email.enabled: false`), the proxy displays the Approval Link in the admin portal, so operators can distribute it manually (`fallback_to_portal: true`).

**Future:** Integrate Apprise to support additional backends (Slack, Discord, Telegram, webhooks, SMS, etc.). Apprise is a Python library that supports 100+ notification backends with a single API call (`apprise.notify(title, body, url)`). Adding Apprise does not require changes to the approval flow.

### Notification as a Best-Effort Consumer of Lifecycle Events

"Decoupled" is made precise by the [request lifecycle](../request-lifecycle.md): each lifecycle transition emits an event, and consumers *subscribe* to those events rather than being called inline by the approval flow. Consumers fall into two **reliability classes**:

- **Critical / guaranteed** — a missed event is a system fault, processed atomically with (or reliably after) the transition. The **audit trail** and the **handoff/executor** (which creates the Post-Approval Object) are critical: an approved request that never produced its Post-Approval Object is a silently lost operation.
- **Best-effort** — a missed event is recoverable and does not corrupt state. The **notification system** is best-effort by design: the lifecycle has already advanced before delivery is attempted, so a failed or delayed notification can never block or roll back an approval.

This is the enforceable form of the decoupling requirement: notifications are a best-effort subscriber to an event stream, never a step the approval flow waits on. Notification subscriptions are configurable per user (a Requester chooses which events route to them); the default subscriptions are defined in the notification-system specification, not here.

## Rationale

1. **Decoupling reduces complexity:** Notification delivery is a separate concern from approval logic. The proxy does not need to know about email servers, Slack tokens, webhooks, etc.

2. **Flexibility for operators:** Different organizations have different communication channels. Some use Slack, others email, others webhook to internal systems. Decoupling lets each operator choose.

3. **Apprise integration is low-effort:** Apprise is a single Python library. Once integrated, operators can choose their backend with a config line (e.g., `APPRISE_URL=slack://...` or `APPRISE_URL=mailto://...`).

4. **MVP-feasible:** SMTP email is the one delivery backend implemented for MVP — it is universally available and needs no third-party service tokens. The admin-portal fallback covers misconfigured or disabled email without blocking approvals. Because delivery is decoupled, adding Apprise backends later is a small addition that does not touch the approval flow.

5. **No approval-link expiration (for MVP):** Distributed approvers may take a long time to reach quorum. Expiring approval links would add friction. For MVP, links do not expire (or have a very long lifetime, e.g., 30 days). If replay attacks become a concern, expiration can be added.

## Implications

- Each approval request has a unique ID and an associated approval link.
- Notification delivery is orthogonal to the approval system.
- The proxy delivers notifications via SMTP email; the admin portal provides a fallback if email is disabled or fails.
- Future versions can integrate Apprise for additional delivery backends.
- No notification backends are called from the approval flow; notification failures do not block approvals.

## Trade-offs Accepted

- **Portal fallback for failed delivery:** If SMTP is misconfigured or disabled, operators must manually copy and distribute approval links from the admin portal. Not ideal UX, but acceptable as a degraded-mode fallback.
- **No link expiration:** Increases replay/reuse risk slightly, but acceptable for MVP since the threat model is "single approver compromised," not "attacker guesses old approval links."
