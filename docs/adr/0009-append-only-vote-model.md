# Append-only, supersedable vote model

## Status
Accepted

An Approver may change their decision on an Approval Request while it is `pending` — flip `approve`↔`deny`, or `withdraw` an approval back to neutral. Rather than mutating a stored vote, every decision is recorded as a new **signed Vote that supersedes** the Approver's previous one; the full sequence is retained permanently, and quorum and the single-denial rule are computed from each Approver's latest (**effective**) Vote. See [request-lifecycle.md § Votes](../request-lifecycle.md#votes-append-only-and-supersedable) for the mechanics.

We chose this over the original "one decision per approver, duplicates rejected" rule (formerly threat-model VOTE-2). Mutating or deleting a vote would corrupt the tamper-evident audit trail; forbidding any change would leave an Approver who has second thoughts with no recourse before the request finalizes. Append-only supersession keeps both properties: **non-repudiation** (every decision, including a reversal, is signed and never erased) and **flexibility** (the effective vote can change until the request leaves `pending`).

## Consequences

- The replay/duplicate defense (VOTE-2) is reframed: an *identical* repeated vote is still a no-op, but a *changed* decision from the same authenticated Approver is an accepted supersession, not a rejected duplicate. Only the authenticated Approver can supersede their own Vote.
- Votes freeze at any terminal state. A change of heart after `approved` is expressed on the Post-Approval Object (Service Grant revocation / Action abort), not by altering a Vote.
- "Endorsing Approver" is defined by *effective* vote at the moment of outcome, so a withdrawn or flipped approval correctly drops the Approver from the endorsing set and its notifications.
- Enables the self-service vote-management capability in the User Portal (review and change your own votes on still-`pending` requests).
