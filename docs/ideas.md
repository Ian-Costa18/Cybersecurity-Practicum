# Future Ideas (Out of Scope for MVP)

This document captures features and improvements discussed but not committed to the MVP. They are stored here to prevent scope creep while preserving the design vision.

## Multi-Backend Notification (Apprise)

**Current state:** MVP delivers notifications via SMTP email only. Enrollment links and approval request links are emailed to approvers automatically.

**Idea:** Integrate Apprise to send notifications via additional backends — Slack, Discord, webhook, SMS, push notification, etc. — in addition to or instead of email.

**Rationale:** SMTP covers the common case. Apprise adds flexibility for teams that prefer Slack over email or want redundant delivery channels. Low effort once the SMTP path exists (~50 lines of code). See the matching forward-reference in [notification-system.md § Future enhancements](notification-system.md).

## Live Approver Visibility / Quorum Status

**Current state:** Approvers are notified of a request but have no visibility into whether other approvers have already approved or denied.

**Idea:** When an approver clicks their link, show them the current approval state, including the identities of other approvers who have or have not yet acted (e.g., "2-of-3 approvals received; waiting for Charlie"). (Changing or withdrawing one's own vote while a request is `pending` is already part of the MVP via the append-only vote model; this idea is about surfacing live approver identities/status.)

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

**Idea:** Set a timeout (e.g., 24 hours) for approval requests. If quorum is not reached by the deadline, the request is automatically denied. Optionally send reminders to approvers at fixed intervals (e.g., "Charlie still hasn't approved; reminder sent"). This is the feature that introduces the `timed_out` terminal state reserved in [request-lifecycle.md](request-lifecycle.md).

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

## Approver-Governed Service Grant Revocation

**Current state:** A Service Grant ends only when its time window expires (see [request-lifecycle.md](request-lifecycle.md)). There is no way to cut off an active grant early, and — deliberately — no admin "revoke" button, to avoid concentrating unilateral power in an admin.

**Idea:** Let the *approvers* revoke an active Service Grant the same way they granted it — through a vote. While a grant is `active`, an approver could re-initiate a vote (or withdraw their prior approval) to terminate access early. Revocation stays governed by the same m-of-n trust that created the grant, rather than handing a single admin the power to revoke.

**Rationale:** Preserves the multi-sig philosophy: the people who can grant access are the people who can take it away, and no single actor (including an admin) can unilaterally revoke. Gives a real "emergency cutoff" lever for a grant that turns out to be a mistake or a compromise, without waiting out the expiry window.

**Concerns:** Complex — requires a revocation vote lifecycle layered on an already-active grant, and rules for what a partial revocation quorum means. Note this is distinct from withdrawing a vote on a still-`pending` request (already in the MVP via the append-only vote model); here the grant is already `active`, so a new vote lifecycle is needed to unwind it.

**Estimated complexity:** Medium to high; a second vote lifecycle bound to an active grant.

## Use-Count-Limited Service Grants

**Current state:** A Service Grant is time-windowed only — it expires when `expires_at` passes, regardless of how many times it was used (see [request-lifecycle.md](request-lifecycle.md)).

**Idea:** Allow a Service Grant to be bounded by a use count in addition to (or instead of) a time window — e.g., "good for 3 accesses, or 8 hours, whichever comes first." The grant transitions to `expired` when either bound is hit.

**Rationale:** Some operations should be one-shot or few-shot regardless of the time window. A use count limits exposure more tightly than time alone for sensitive, discrete accesses.

**Estimated complexity:** Low to medium; adds a per-grant counter decremented on each access and an extra expiry condition.

## In-Memory Private-Key Erasure (Secure Wipe / Out-of-Process Signing)

**Current state:** `sign_with_password` ([crypto.py](../src/msig_proxy/crypto.py)) decrypts the Ed25519 private key transiently, signs, and lets the plaintext key fall out of scope when the call returns. This is *confinement*, not *erasure* — invariant 3 (`docs/cryptography.md`) holds in the sense that the key never escapes the call into a caller or a stored record, but the bytes are not zeroed and linger in memory until garbage-collected and the allocator reuses the page.

**Idea:** Actually wipe the key material after signing so it cannot be recovered from process memory.

**Why the obvious version (zero a `bytearray`) does not work:** By the time Python can zero a buffer it controls, the secret already exists in copies it cannot reach: `AESGCM.decrypt` returns an immutable `bytes`; `Ed25519PrivateKey.from_private_bytes(...)` copies the scalar into an OpenSSL `EVP_PKEY` that `cryptography` exposes no API to cleanse; and `sign()` makes its own internal temporaries. Zeroing one buffer clears one of several copies. Add GC object movement and the chance of pages reaching swap / hibernation / a core dump, and pure-Python "secure wipe" advertises a guarantee it cannot deliver.

**What would actually work (architectural, not a `bytearray` trick):**

- **Out-of-process signer.** Do decrypt→sign inside a short-lived child process that is killed immediately after, bounding the key's lifetime to that process's memory.
- **`mlock`'d buffers** to keep the plaintext key (and `enc_key`) out of swap, paired with an OpenSSL-level `OPENSSL_cleanse` on the internal copy (needs library cooperation the Python binding does not currently expose).
- **HSM / KMS signing**, so the raw private key never enters the proxy's address space at all — the strongest option, and a natural companion to [Per-User Credential Wrapping](#per-user-credential-wrapping) and [Integration with External Secret Managers](#integration-with-external-secret-managers).

**Rationale:** Defends against an attacker who can read the proxy's process memory *after* signing (core dump, memory over-read, swap forensics, cold-boot). Note this only matters once the larger conceded exposure is closed: `docs/mvp.md` already accepts "Credentials in memory unencrypted" (the PyPI token and shared-account credentials sit in plaintext in the same address space), so hardening the Ed25519 key alone is inconsistent effort until that limitation is addressed too. The property the MVP actually relies on — the key is encrypted **at rest** under a password-derived key, so a database thief without the password cannot forge — is unaffected either way.

**Estimated complexity:** Medium for an out-of-process signer; high (and most valuable) for HSM/KMS-backed signing.

---

## Summary

The MVP is a solid, tightly scoped system for credential-backed multi-approval with hash binding and per-service configuration. All items above are valuable additions but are deferred to preserve focus on shipping a working, evaluated core.
