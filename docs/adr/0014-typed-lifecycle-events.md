# Typed Lifecycle Events

## Status
Accepted

## Context

[ADR 0005](0005-decoupled-notification-system.md) established *how* the lifecycle and its consumers are decoupled: the lifecycle emits **blind**, consumers **subscribe**, and they fall into two **reliability classes** (critical audit, best-effort notifications). This ADR does not revisit any of that — it records only the **representation** of an event.

Lifecycle events were *stringly-typed*: a single `Event(name: str, payload: dict[str, Any])`, a flat block of `REQUEST_APPROVED = "request.approved"` name constants, dicts assembled by hand at each emit site (`{"approval_request_id": str(request.id), ...}`) and re-parsed at the consumer (`uuid.UUID(payload.get("approval_request_id"))`). Both the discriminator (the name string) and the payload shape were unchecked: a misspelled name or a missing key surfaced only at runtime, and the notification subscriber carried a `_load_request` that re-validated an id the emitter had just stringified.

## Considered Options

### Option A: keep `name` + `dict` payload
- **Advantage:** zero change; trivially serializable for audit.
- **Disadvantage:** the discriminator and payload are both unchecked; every emit stringifies ids and every consumer re-parses them; a typo is a runtime bug.

### Option B: typed event dataclasses, **designed** hierarchy
Frozen dataclasses with typed fields, plus an up-front category tree (a `RequestEvent` / `AccountEvent` / `GrantEvent` spine).
- **Advantage:** typed discriminator and fields.
- **Disadvantage:** category nodes no consumer branches on are taxonomy for its own sake — they widen the interface every matcher must learn for no leverage, and events get sliced along several orthogonal axes (subject aggregate, audience, reliability class) that single inheritance cannot all encode.

### Option C: typed event dataclasses, **discovered** hierarchy *(chosen)*
Frozen dataclasses with typed fields; a single shallow base with **flat** children, and an intermediate node promoted **only when a real consumer dispatches on it**.

## Decision

**Chosen: Option C.** `core/events.py` exposes a frozen `Event` base and a flat set of frozen-dataclass children with typed fields. The **discriminator is the concrete type** — subscribers `match` on it; nothing compares strings on the emit/consume path. Each event still carries a stable catalog label as a `ClassVar[str] name`, used **only** for the audit trail's `event_name` column (not for dispatch).

Concrete events (subject aggregate in parentheses):

| Event class | `name` | Fields |
|---|---|---|
| `RequestCreated` (request) | `request.created` | `approval_request_id: UUID`, `service_name: str`, `requester_id: UUID` |
| `RequestApproved` (request) | `request.approved` | `approval_request_id`, `service_name`, `requester_id` |
| `RequestDenied` (request) | `request.denied` | `approval_request_id`, `service_name`, `requester_id` |
| `RequestCancelled` (request) | `request.cancelled` | `approval_request_id` |
| `ActionSucceeded` (action) | `action.succeeded` | `approval_request_id` |
| `ActionFailed` (action) | `action.failed` | `approval_request_id`, `reason: str \| None` |
| `GrantActivated` (grant) | `grant.activated` | `grant_id: UUID`, `approval_request_id`, `expires_at: datetime` |
| `GrantExpired` (grant) | `grant.expired` | `grant_id` |
| `ArtifactDestroyed` (artifact) | `artifact.destroyed` | `approval_request_id`, `action_id: str \| None`, `terminal_state: str` |
| `EnrollmentIssued` (account) | `account.enrollment_issued` | `user_id: UUID`, `email: str` |
| `CredentialsReset` (account) | `account.credentials_reset` | `user_id`, `email` |
| `AccountDeactivated` (account) | `account.deactivated` | `user_id`, `email` |
| `AccountDeleted` (account) | `account.deleted` | `user_id`, `email` |

**The hierarchy is flat: no intermediate node exists.** Applying the deletion test (a category node earns its place only if deleting it forces a consumer to enumerate its concrete children by hand), none qualifies:

- **Audit** handles every event uniformly — `event.name` for the column, `dataclasses.asdict(event)` for the payload — so it dispatches on the `Event` base, never on a category.
- **Notifications** branches on six **concrete** types. A `RequestScopedEvent` node would *not* serve it: that node would also include `RequestCancelled` and `ArtifactDestroyed` (both carry `approval_request_id`), which notifications does **not** handle — so the subscriber would still enumerate its six concrete types.

The subject aggregate (request / action / grant / artifact / account) is therefore documentation grouping, **not** an inheritance spine; the cross-cutting axes (audience, reliability class) are expressed as per-consumer membership, never on the event.

**No behavior lives on an event.** There is no `notify()` / `render()` / `audit()` method — the lifecycle emits blind ([ADR 0005](0005-decoupled-notification-system.md)); "what to do" belongs per-consumer (audit, notifications, the polling waiting room). The event is typed **data**.

Events remain centralized in `core/events.py`. [ADR 0012](0012-vertical-slice-package-layout.md) permits a slice to define its own event type; the MVP set is small and shared by multiple slices, so centralizing is simpler. A future slice-local event is compatible — it would subclass the same `Event` base.

### The notification matrix (former candidate, deferred)

Once events are typed, the notification `if/elif` becomes a `match`. Folding the four terminal-outcome arms (`RequestDenied`, `ActionSucceeded`, `ActionFailed`, `GrantActivated`) into one audience-parameterised table was **considered and rejected**: their subjects interpolate different request fields (`service_name` vs `package_name`/`package_version`) and `ActionFailed` splices a dynamic `reason`, so a table would need escape hatches for most of its rows. They stay as honest `match` branches.

## Rationale

1. **The type system replaces a class of runtime bugs.** A misspelled discriminator or a missing payload key is now a construction error, not a silent runtime miss. The notification subscriber's `_load_request` dict-reparse is gone — the id is a typed `UUID` field, so the only remaining miss is "valid id, no such row," which stays logged-and-swallowed.
2. **Discovered beats designed for hierarchy.** Encoding category nodes no consumer branches on would widen every matcher's surface for no leverage, and the orthogonal axes (aggregate / audience / reliability) cannot all be a single inheritance spine. Starting flat and promoting on demand keeps the interface minimal.
3. **Behavior off the event keeps the seam blind.** Putting `notify()`/`render()` on the event would recouple the emitting slice to the notification system that [ADR 0005](0005-decoupled-notification-system.md) decoupled, and there are three consumers, so "what to do" is irreducibly per-consumer.
4. **Audit serialization stays generic.** `event.name` + `dataclasses.asdict` reproduces the prior `event_name` + JSON-payload shape (ids stringify via `default=str`), so the audit trail format is unchanged and events still carry only identifiers, never secrets.

## Implications

- `core/events.py` no longer exposes `Event(name, payload)` or the `*_NAME` constants; emit sites construct typed events (`bus.emit(events.RequestApproved(...))`) with no manual `str(id)` / dict assembly.
- The audit subscriber serializes any event generically; the notification subscriber `match`es on type and reads typed fields.
- Tests assert through the subscribers and on event **types/fields**, not on payload-dict shape.
- This is independent of the session-lending seam ([#102](0005-decoupled-notification-system.md) era refactor): both touch `core/events.py` and the emit sites, so whichever lands second rebases; there is no ordering dependency.

## Trade-offs Accepted

- **More classes for the same data.** Thirteen dataclasses replace one `Event` + a constant block. The payoff is a checked discriminator and checked fields; the cost is a larger (but flat and mechanical) module.
- **A `ClassVar name` straddles two worlds.** The catalog string survives as a serialization label for the audit column even though dispatch no longer uses it. Keeping it preserves the audit trail format and the documented catalog names; the alternative (deriving `event_name` from the class name) would have changed every existing audit row's label.
