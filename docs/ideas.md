# Future Ideas (Out of Scope for MVP)

This document captures features and improvements discussed but not committed to the MVP. They are stored here to prevent scope creep while preserving the design vision.

## Multi-Backend Notification (Apprise)

**Current state:** MVP delivers notifications via SMTP email only. Enrollment links and approval request links are emailed to approvers automatically.

**Idea:** Integrate Apprise to send notifications via additional backends — Slack, Discord, webhook, SMS, push notification, etc. — in addition to or instead of email.

**Rationale:** SMTP covers the common case. Apprise adds flexibility for teams that prefer Slack over email or want redundant delivery channels. Low effort once the SMTP path exists (~50 lines of code).

## Live Approver Visibility / Quorum Status

**Current state:** Approvers are notified of a request but have no visibility into whether other approvers have already approved or denied.

**Idea:** When an approver clicks their link, show them the current approval state (e.g., "2-of-3 approvals received; waiting for Charlie"). Allow them to withdraw their approval if needed.

**Rationale:** Improves UX for quorum-based workflows; prevents duplicate/redundant approvals. Can be added as a UI enhancement to the approval page.

## Screen-Share Auditing

**Current state:** Approvers approve a request (e.g., publish to PyPI) but cannot see what the requester is doing with the granted access.

**Idea:** After approval is granted, approvers optionally join a live screen-share session to observe the requester's actions. Record the session as a video audit log for later review.

**Rationale:** Adds accountability and real-time oversight. Particularly valuable for sensitive operations (large production releases, data access). Implementation requires WebRTC/screen-share library and video storage.

**Estimated complexity:** High; orthogonal to core approval flow.

## Traefik / Reverse-Proxy Integrations

**Current state:** MVP supports forward-auth pattern but is not formally integrated as a Traefik plugin or middleware.

**Idea:** Create a Traefik middleware plugin that makes deployment via Traefik seamless (e.g., add `traefik.http.middlewares.multi-auth.url=http://proxy:8080` to app config).

**Rationale:** Improves deployment experience for users of Traefik. Currently, the forward-auth pattern works, but the setup is manual.

**Estimated complexity:** Medium; mostly documentation and middleware boilerplate.

## Per-User Credential Wrapping

**Current state:** For MVP, the proxy holds publishing credentials (e.g., PyPI token) in memory, unencrypted. A compromised proxy can read them.

**Idea:** Store a copy of publishing credentials encrypted with each approver's own credentials. To publish, the system asks the quorum of approvers to decrypt their copy of the credentials. Only after m-of-m decryptions can the credentials be used.

**Rationale:** Prevents a compromised proxy from reading credentials without compromising m approvers simultaneously. Adds threshold encryption on top of credential-backed approval.

**Estimated complexity:** Medium; introduces threshold decryption logic.

## Formal Verification

**Current state:** Approval protocol is specified in CONTEXT.md and ADRs but not formally verified.

**Idea:** Model the approval protocol in Tamarin or ProVerif and formally verify replay-resistance, authentication, and secrecy properties.

**Rationale:** High confidence in security claims; publishable result. Aligns with the literature review's recommendation for formal verification of authentication protocols.

**Estimated complexity:** High; requires learning Tamarin/ProVerif syntax and modeling the approval flow.

## Fine-Grained Authorization (Per-User Thresholds)

**Current state:** Approvers for a service are uniform; any approver can approve any request for that service.

**Idea:** Allow per-user or per-request-type approval rules (e.g., "Alice can approve PyPI publishes alone; Bob requires 2-of-3 for the same action").

**Rationale:** Supports delegation and role-based workflows. Adds flexibility but also complexity.

**Estimated complexity:** Medium; requires ACL extension.

## Approval History & Audit Logging

**Current state:** Approvals are recorded in the database but audit logging is not emphasized.

**Idea:** Comprehensive audit log with: requester, service, approvers, approval timestamps, approval hashes, published artifacts, any denials. UI to query and filter audit logs.

**Rationale:** Compliance requirement for many organizations. Proves "who approved what and when."

**Estimated complexity:** Medium; mostly database queries and UI.

## Integration with External Secret Managers

**Current state:** Proxy holds publishing credentials in memory.

**Idea:** Integrate with HashiCorp Vault, AWS Secrets Manager, or similar to fetch credentials at publish time rather than storing them in the proxy.

**Rationale:** Improves security posture; credentials are never in the proxy's memory. Requires operator to set up and maintain external secret manager.

**Estimated complexity:** Medium; integration code + operator overhead.

## Approval Timeouts & Reminders

**Current state:** Approval requests have no expiration. Approvers are notified once and then it is their responsibility to check the proxy periodically.

**Idea:** Set a timeout (e.g., 24 hours) for approval requests. If quorum is not reached by the deadline, the request is automatically denied. Optionally send reminders to approvers at fixed intervals (e.g., "Charlie still hasn't approved; reminder sent").

**Rationale:** Prevents approval requests from languishing indefinitely. Improves coordination overhead for distributed teams.

**Estimated complexity:** Low; background job + notification retry logic.

## Rate Limiting & Abuse Prevention

**Current state:** No rate limiting on approval requests.

**Idea:** Limit the number of approval requests per requester per time window. Detect and alert on unusual patterns (e.g., "Alice suddenly approving 10x the usual requests").

**Rationale:** Prevents DoS attacks or abuse (a compromised requester account flooding the system).

**Estimated complexity:** Low to medium; depends on sophistication of detection.

## Approval Content Preview

**Current state:** The approve/deny page shows the approver the basic details of the request (HTTP request metadata, or a download link for a package artifact).

**Idea:** Show approvers a rich preview of what they are approving. For package publishing, this could be an in-browser file browser showing the package contents and source code. For HTTP requests, a formatted diff or structured view of the payload.

**Rationale:** Approvers cannot make an informed decision if they cannot see what they are approving. A file browser for packages would let reviewers catch malicious code before it is published. Significant implementation effort; well beyond MVP scope.

**Estimated complexity:** High; requires server-side package extraction, syntax highlighting, and file-tree UI.

## Peer-Approved Credential Recovery

**Current state:** Credential recovery is admin-only. An approver who loses their password or TOTP contacts an admin, who verifies their identity out-of-band and issues a new enrollment link via the authentication portal.

**Idea:** Use the approval mechanism itself to gate credential recovery. An approver submits a recovery request; m-of-n other approvers must approve it before a new enrollment link is issued.

**Rationale:** Removes the admin as a single recovery trust point and aligns with the multi-sig philosophy of the system.

**Concerns:**

- **Social engineering surface:** Approvers have no cryptographic basis for verifying the requester's identity. They are clicking "approve" on a claim ("I am Alice and I lost my credentials"), not on a verifiable artifact. This is easier to abuse than a standard approval. The current admin model is arguably stronger — admins verify identity out-of-band (phone, in person) before acting.
- **Circular dependency risk:** If enough approvers simultaneously lose credentials, nobody can approve recovery requests. With a tight quorum (e.g., 3-of-5) and two people locked out, the system could deadlock.
- **Possible mitigation:** Require admin approval *plus* a configurable number of co-approver attestations — keeps a human identity check in the loop while distributing the trust.

**Estimated complexity:** Medium for the mechanism; high for reasoning about the security model correctly.

## SSO / External Identity Provider Integration

**Current state:** Approver accounts are managed locally by the proxy (bcrypt password + TOTP).

**Idea:** Delegate identity to an external OIDC/SAML provider (GitHub, Google, Okta, etc.). Approvers authenticate via their existing organizational identity; the proxy just enforces quorum on top.

**Rationale:** Reduces credential management burden for organizations with existing SSO. Adds OAuth/OIDC complexity; not needed for MVP.

**Estimated complexity:** Medium; OAuth2/OIDC client integration.

---

## Summary

The MVP is a solid, tightly scoped system for credential-backed multi-approval with hash binding and per-service configuration. All items above are valuable additions but are deferred to preserve focus on shipping a working, evaluated core.
