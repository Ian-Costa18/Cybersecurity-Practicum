# Requesters are authenticated, not signing

## Status
Accepted

Approval decisions are cryptographically signed by Approvers (each Approver's Ed25519 key, decrypted transiently from their password — see [ADR 0002](0002-asymmetric-key-approval-signing.md)). Requesters, by contrast, are only **authenticated** — by password + TOTP for forward-auth, or by an API token for one-time uploads — and sign nothing.

We considered having Requesters sign their submissions for non-repudiation, including a scheme where each API token wraps a per-token signing key. We rejected it. The only buildable (proxy-side) version produces a signature gated by a secret the proxy handles on every call (the password, or worse a long-lived bearer token), so it is forgeable by a compromised proxy and adds nothing an honest proxy's authenticated record does not already give. And the fact it would attest — *submitter identity* — gates no security decision: artifact integrity is pinned by hash binding, and authorization by the Approvers' signatures over that hash. The genuinely strong version (client-held keys, where the key never reaches the proxy) re-introduces exactly the key-management burden [ADR 0001](0001-credential-backed-approval.md) and [ADR 0002](0002-asymmetric-key-approval-signing.md) deliberately avoided, and breaks the zero-tooling-change Twine flow that is the PyPI use case.

## Consequences

- Requester identity in the audit trail is **proxy-asserted, not cryptographically non-repudiable**. Accepted: a compromised proxy could misattribute a submission, but cannot get it published without quorum approving the hash-bound artifact.
- The integrity of *what* is approved and published rests on hash binding plus Approver signatures over that hash — never on a Requester signature.
- The API token therefore only needs to identify the Requester; it never needs to unlock key material, which is what keeps the non-interactive (Twine) upload path possible.
