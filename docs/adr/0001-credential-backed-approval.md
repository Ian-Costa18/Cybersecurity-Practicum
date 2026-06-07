# ADR 0001: Credential-Backed Approval Model

## Status
Accepted

## Date
2026-06-07

## Context

The project needs to gate access to protected resources by requiring multiple distinct people to approve before access is granted. Two main cryptographic models were considered:

### Option A: Threshold Signatures (FROST, GG20, DKLS)
- Each approver holds a cryptographic private key
- To approve, they generate a cryptographic signature/share locally
- Shares combine to form a valid threshold signature (e.g., 3-of-5 shares)
- The approver's key never leaves their hands
- **Advantage:** Strongest security model; approvers never trust the proxy with their key
- **Disadvantage:** Requires approvers to manage additional cryptographic secrets (keys, key backups, key storage); complex UX

### Option B: Credential-Backed Approval
- Approvers do not hold additional keys; they authenticate with standard credentials (password + 2FA)
- When an approver approves, the system records the approval cryptographically tied to their authentication event
- If the proxy is compromised *after* approval, the attacker cannot forge retroactive approvals
- **Advantage:** Simple UX (just authenticate and click approve); no key management burden; supports distributed, async approvers
- **Disadvantage:** Weaker than threshold signatures (requires trusting the proxy to honestly record approvals)

## Decision

**Chosen: Credential-Backed Approval (Option B)**

## Rationale

1. **No key management burden:** Approvers are not necessarily tech-savvy. Asking them to manage cryptographic keys would add friction and risk (lost keys, accidental disclosure). The constraint is explicit: approvers should only need credentials they already know (password + 2FA).

2. **Distributed, async approvers:** The threat model assumes approvers are spread globally and may take time to reach quorum. Threshold signatures add network round trips and synchronization overhead; credential-backed approval naturally supports fire-and-forget approval (approver clicks link, authenticates, approves, done).

3. **Simpler to implement and audit:** Threshold signature schemes (FROST, GG20) are complex cryptographic protocols with known implementation risks (GG18 bugs, Alpha-Rays attacks). Using audited libraries is safer, but still adds complexity. Credential-backed approval is simpler to reason about and implement correctly.

4. **Adequate threat model:** The adversary we're defending against is a *single compromised approver* (or a compromised proxy). Requiring m-of-n approvers to cooperate defends against single-identity compromise. Threshold signatures don't solve the multi-identity compromise case either; they just shift the attack from "compromise one approver's password" to "compromise one approver's key" — not a meaningful improvement given the constraint that approvers should not manage keys.

5. **Flexible upgrade path:** If stronger guarantees are needed later, per-user credential wrapping (encrypting publishing secrets with each approver's credentials) can be layered on top without redesigning the approval flow.

## Implications

- Approvers authenticate with password + 2FA (or equivalent).
- The system records approvals cryptographically signed with a per-approver Ed25519 private key, making them tamper-evident and non-repudiable. See [ADR 0002](0002-asymmetric-key-approval-signing.md) for the signing mechanism decision.
- Each approver's private key is stored encrypted at rest (encrypted under a key derived from their password). The public key is stored in plaintext and used for audit verification without requiring the approver's password.
- Quorum is enforced at the proxy level: once m-of-n approvers have authenticated and explicitly approved, the system proceeds.
- For publishing use cases (PyPI), approvals are hash-bound to prevent MITM attacks between upload and publication.

## Trade-offs Accepted

- **Weaker than threshold signatures:** The proxy must be trusted to honestly record approvals. A compromised proxy *before* approval can approve anything; a compromised proxy *after* approval cannot forge approvals retroactively (they are cryptographically tied to past auth events). This is acceptable for the stated use case (preventing single-maintainer supply-chain attacks).
- **Credential expiry risk:** If an approver's password is compromised after they approve, an attacker cannot retroactively revoke the approval (it is already recorded). This is acceptable because the approval is time-limited in effect (the approved action is executed soon after quorum is reached).
