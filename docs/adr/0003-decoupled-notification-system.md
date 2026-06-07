# ADR 0003: Decoupled Notification System

## Status
Accepted

## Context

The proxy must notify approvers when an approval request is pending. Different organizations may have different notification preferences (email, Slack, Discord, webhook, SMS, etc.). The notification system must be:

1. **Simple to integrate:** Operators can plug in their preferred backend
2. **Decoupled from approval logic:** Notification failures should not block approval flow
3. **Flexible:** Support multiple backends without code changes
4. **MVP-feasible:** For MVP, a minimal implementation is acceptable

## Options Considered

### Option A: Built-in Email Notifications
- Proxy sends emails directly
- **Advantage:** Simple, self-contained
- **Disadvantage:** Limited to email; requires SMTP config; tight coupling; operators cannot easily switch to Slack/Discord

### Option B: Tight Integration with One Service (e.g., Slack)
- Proxy sends Slack messages directly
- **Advantage:** Popular, immediate feedback
- **Disadvantage:** Ties proxy to one platform; other operators need different versions

### Option C: Decoupled Notification + Approval Link Pattern
- Proxy generates an approval link (e.g., `https://proxy.example.com/approve/{approval_id}`)
- Notification delivery is decoupled: operators use Apprise (or equivalent) to send the link via their chosen backend
- For MVP, notification delivery is not implemented; approvers can manually copy the link from the proxy UI or logs
- **Advantage:** Flexible, not tied to any backend; simple approval logic; operators control notification channel
- **Disadvantage:** Requires operator to set up notification delivery (not automatic for MVP)

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

For MVP, the proxy does not automatically send notifications. Instead:

1. **Option 1 (Simplest):** The proxy displays the approval link in the UI or logs. Operators manually copy and distribute the link (e.g., paste into a Slack channel).

2. **Option 2 (Future):** Integrate Apprise to generate notifications. Apprise is a Python library that supports 100+ notification backends (email, Slack, Discord, Telegram, webhook, etc.) with a single API. A single function call (`apprise.notify(title, body, url)`) sends the link to the configured channels.

For MVP, **Option 1 (manual distribution) is sufficient**. The hook for notification is in place; implementation can be added without breaking the approval flow.

## Rationale

1. **Decoupling reduces complexity:** Notification delivery is a separate concern from approval logic. The proxy does not need to know about email servers, Slack tokens, webhooks, etc.

2. **Flexibility for operators:** Different organizations have different communication channels. Some use Slack, others email, others webhook to internal systems. Decoupling lets each operator choose.

3. **Apprise integration is low-effort:** Apprise is a single Python library. Once integrated, operators can choose their backend with a config line (e.g., `APPRISE_URL=slack://...` or `APPRISE_URL=mailto://...`).

4. **MVP-feasible:** For MVP, manual distribution (copy link, paste to Slack) is acceptable. It's not automatic, but it works and requires zero notification code. Once the approval flow is solid, Apprise integration is a small addition.

5. **No approval-link expiration (for MVP):** Distributed approvers may take a long time to reach quorum. Expiring approval links would add friction. For MVP, links do not expire (or have a very long lifetime, e.g., 30 days). If replay attacks become a concern, expiration can be added.

## Implications

- Each approval request has a unique ID and an associated approval link.
- Notification delivery is orthogonal to the approval system.
- For MVP, operators manually send approval links to approvers.
- Future versions can integrate Apprise for automatic delivery.
- No notification backends are called from the approval flow; notification failures do not block approvals.

## Trade-offs Accepted

- **Manual distribution for MVP:** Not ideal UX, but acceptable for a practicum project. Operators get their workflow right, then add notification automation.
- **No link expiration:** Increases replay/reuse risk slightly, but acceptable for MVP since the threat model is "single approver compromised," not "attacker guesses old approval links."
