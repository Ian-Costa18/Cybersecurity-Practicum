# ADR 0007: Two-Aggregate Request Model (Approval Request Hands Off to a Post-Approval Object)

## Status
Accepted

## Context

A request in the proxy has two distinct phases: the **approval** phase (an m-of-n vote among Approvers) and the **post-approval** phase (what happens once quorum is reached). The two phases are genuinely different in shape depending on the service type:

- **forward-auth** (e.g., shared account access): after quorum, the Requester receives *ongoing interactive access* for a bounded window. There is no external operation to execute.
- **one-time** (e.g., PyPI publish): after quorum, the proxy *executes an operation* against an external service, which can succeed, fail transiently (retry), or fail permanently.

The question is how to model the object(s) that carry a request through these phases. This is the foundational data-model decision the entire [request lifecycle](../request-lifecycle.md) is built on.

## Options Considered

### Option A: One aggregate flows through everything
A single "Request" object carries a `type` and moves `pending → approved → [post-approval states] → terminal`. Service Grant and execution are *phases* of one object.

- **Advantage:** One ID, one timeline; "what's the status of my request?" is a single lookup.
- **Disadvantage:** The object means different things at different times — a "Request" that is now a live access session is a semantic stretch. The two post-approval phases are heterogeneous (a grant has *expiry/revocation*; an execution has *retries/failure*), so one state enum becomes a fat union where half the states are illegal for any given instance.

### Option B: Two aggregates — Approval Request hands off to a Post-Approval Object
The Approval Request owns only the *approval core* (`pending → approved/denied/timed_out/cancelled`). On `approved` it spawns a **Post-Approval Object** — a Service Grant (forward-auth) or an Action (one-time) — each with its own lifecycle. The two are bidirectionally linked.

- **Advantage:** Each aggregate is cohesive with one clean lifecycle. The approval core is identical across service types. Retry lives on the Action; expiry/revocation lives on the Service Grant. Matches the existing glossary, which already says a Service Grant is "issued after an Approval Request is fulfilled."
- **Disadvantage:** Two IDs to correlate; requires an explicit link between the objects.

## Decision

**Chosen: Option B — two aggregates with a handoff at `approved`.**

The **Approval Request** is the approval-core aggregate; its entire life is the vote, ending in a terminal state (`approved`, `denied`, `timed_out`, or `cancelled`). On `approved` it hands off to a **Post-Approval Object**: a **Service Grant** for forward-auth or an **Action** for one-time. The model is open to additional Post-Approval Object types later.

The two aggregates are **bidirectionally linked**: each carries its own unique ID and references the other (the post-approval object stores the `approval_request_id`; the Approval Request stores a forward pointer written at handoff). See [request-lifecycle.md](../request-lifecycle.md) for the full state machines.

## Rationale

1. **Two outcome axes, two owners.** "Was it approved?" and "did it execute successfully?" are decided by different actors at different times (Approvers vote; the external service accepts or rejects). Collapsing them hides that a `failed` PyPI publish was actually *approved* — which matters for the audit trail and for what the Requester is told. Separate aggregates keep the axes independent.

2. **Cohesion.** Retry/abort semantics belong to the Action; expiry belongs to the Service Grant; neither pollutes the approval core. The approval core stays identical regardless of what it hands off to.

3. **The glossary already committed to it.** `CONTEXT.md` defined the Service Grant as "issued after an Approval Request is fulfilled" — two-object language — before this decision was formalized.

4. **Audit integrity.** The bidirectional link lets an auditor walk forward from an approval to what it caused, and backward from an executed Action (or granted access) to the exact vote that authorized it.

## Implications

- An `approved` Approval Request is **terminal on the approval axis** but spawns work; reaching `approved` concludes the *vote*, not the *record* (the forward link is added at handoff).
- The handoff (creating the Post-Approval Object) is a **critical/guaranteed** step — an `approved` request must always produce its linked Post-Approval Object, or the operation is silently lost (see the consumer reliability classes in [request-lifecycle.md](../request-lifecycle.md)).
- Adding a new post-approval behavior means adding a new Post-Approval Object type, not changing the approval core.

## Trade-offs Accepted

- **Two IDs to correlate.** Answering "what happened to my request end-to-end?" spans two linked objects rather than one row. Accepted because the bidirectional link makes the traversal deterministic, and the alternative (one fat aggregate) makes every other operation messier.
