# Snapshot the Approver Set and Threshold at Request Creation

## Status
Accepted

## Context

The set of eligible Approvers and the Quorum threshold for a Service are defined in the per-service configuration (ADR 0004). That configuration can change while an Approval Request is still `pending`: an admin might add or remove an approver, change the threshold (e.g., 2-of-3 → 3-of-4), or deactivate an approver's account.

This raises a question for any in-flight `pending` request: is it evaluated against the configuration **as it was when the request was created**, or against the **current** configuration, which may have changed mid-vote?

Concrete scenarios on a 2-of-3 service:
- Bob has already approved; an admin removes Charlie before quorum.
- An admin raises the threshold to 3-of-3 while a request with 2 approvals is about to reach quorum.
- An admin adds Dave; is Dave now eligible to vote on the existing pending request?

## Decision

**The eligible approver set and the Quorum threshold are snapshotted at Approval Request creation. A `pending` request is evaluated against that snapshot and is immune to later configuration changes.**

Already-cast votes remain valid even if the voting approver is later removed from the Service configuration. Configuration changes are forward-looking only: they affect requests created *after* the change, never requests already in flight.

## Rationale

1. **Auditability / determinism.** The request carries a fixed, signed statement of exactly what it required ("2-of-{Alice, Bob, Charlie}"). A rule that mutates mid-vote is unauditable — you could not later prove what threshold a given approval actually satisfied.

2. **Security — prevents a mid-flight weakening attack.** If configuration changes applied to live requests, a compromised admin could lower the threshold or swap in a colluding approver *while a malicious request is pending* and push it through with fewer legitimate approvals than the policy demanded at creation. Snapshotting denies this; it is consistent with the system's core premise that no single actor (including an admin) should be able to unilaterally force an approval.

3. **Cast votes reflect real decisions.** A recorded approval is a genuine authenticated decision tied to the approver's identity ([ADR 0001](0001-credential-backed-approval.md), [ADR 0002](0002-asymmetric-key-approval-signing.md)). Removing that approver from future configuration does not retroactively unmake a vote they actually cast.

## Implications

- A configuration change does not affect in-flight requests; operators must let `pending` requests drain (or have them cancelled/remade) for a new policy to fully apply.
- If the snapshot becomes **unreachable** — e.g., a snapshot approver's account is deactivated before voting, dropping the eligible pool below the threshold — the request simply stays `pending`. In the MVP (no `timed_out` state) the Requester's recourse is to `cancel` it and create a fresh request against the current configuration. Requests are cheap to remake.
- The Approval Request must persist its snapshot (approver set + threshold) at creation, not look it up live at vote time.

## Trade-offs Accepted

- **Config changes are not retroactive.** An operator who tightens policy cannot have it apply to already-open requests; they must wait for them to drain or cancel them. This is the correct trade for a security product — policy changes on a live vote are exactly the attack we are denying — and it is cheap to work around because requests can always be remade.
- **Possible stuck `pending` requests.** Until the approval-timeout feature exists (see [ideas.md](../ideas.md)), an unreachable snapshot leaves a request open until cancelled. Accepted as an MVP limitation; cancellation is the escape hatch.
