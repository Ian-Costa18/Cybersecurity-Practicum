# Request Lifecycle

This document defines the **state machine** that every request flows through, from creation to a terminal outcome. It is the source of truth for request states and transitions. Other systems — notifications, the audit trail, the approval-timeout feature, and the threat model — **subscribe to** the transitions defined here rather than redefining them.

See [CONTEXT.md](../CONTEXT.md) for the glossary terms used below (Approval Request, Service Grant, Action, Post-Approval Object, Quorum).

> **On naming:** "Request Lifecycle" is the name of the end-to-end *journey* a Requester's request takes across two aggregates. It is **not** a new aggregate — there is no capital-R "Request" object. The approval-core aggregate is the **Approval Request**; the post-approval aggregates are the **Service Grant** and the **Action**. This doc traces a request as it moves through them.

## Model: two aggregates, one handoff

A request is modeled as **two linked aggregates**, not one object that flows through everything (see [ADR 0007](adr/0007-two-aggregate-request-model.md) for this decision, and [ADR 0005](adr/0005-decoupled-notification-system.md) for the decoupling principle it builds on):

1. **Approval Request** — owns the *approval core*. Its entire life is the m-of-n vote. It reaches a terminal state and does no post-approval work itself.
2. **Post-Approval Object** — what an `approved` Approval Request hands off to. One of:
   - **Service Grant** (forward-auth): grants the Requester interactive access to the Service.
   - **Action** (one-time): executes an operation against an external service (e.g., publish to PyPI).
   - The model is open to additional Post-Approval Object types later.

The two aggregates are **bidirectionally linked**: each carries its own unique ID and references the other. An auditor can walk forward from an approval to what it caused, and backward from an executed Action (or granted access) to the exact vote that authorized it. Reaching a terminal approval state concludes the *vote*, not the *record* — the spawned Post-Approval Object's ID is **allocated by the executor at handoff**, which also writes the forward link back onto the Approval Request then. The ID is recovered from the persisted Approval Request afterward; it is **not** carried in the `request.approved` event (see [Handoff / executor](#consumers-and-reliability-classes)).

```text
                         ┌─────────────────────┐
                         │   Approval Request   │   (approval core)
                         │   pending → approved │
                         └──────────┬───────────┘
                                    │ approved  (handoff)
                   ┌────────────────┴────────────────┐
                   ▼                                  ▼
          ┌─────────────────┐               ┌─────────────────┐
          │  Service Grant   │               │     Action       │
          │  (forward-auth)  │               │   (one-time)     │
          └─────────────────┘               └─────────────────┘
```

## Approval core: the Approval Request lifecycle

This is the shared trunk both service types run through. It is identical regardless of which Post-Approval Object the request will hand off to.

| State | Meaning | Terminal? |
|---|---|---|
| `pending` | Created, waiting for votes. Partial quorum stays here. | No |
| `approved` | Quorum reached. Hands off to a Post-Approval Object. | Yes (approval axis settled) |
| `denied` | A single denial closed the request. | Yes |
| `timed_out` | Deadline passed without reaching quorum. *(future — see below)* | Yes |
| `cancelled` | The Requester withdrew the request before approval. | Yes |

```text
                  ┌──────────────────────────► denied      (single denial)
                  │
                  ├──────────────────────────► timed_out   (future)
   pending ───────┤
                  ├──────────────────────────► cancelled   (requester withdraws)
                  │
                  └──────────────────────────► approved ──► (handoff to Post-Approval Object)
```

### Transition rules

- **`pending → approved`** when the number of distinct approvers whose Effective Vote is `approve` reaches the Service's configured Quorum (see [Votes](#votes-append-only-and-supersedable) below).
- **`pending → denied`** on the **first effective `deny`** (including a flip from a prior `approve`; see [Votes](#votes-append-only-and-supersedable) below). A single denial immediately and permanently closes the request; there is no "quorum of denials." **Deny dominates a same-instant approve:** if the m-th `approve` and a `deny` would commit concurrently, the `deny` wins and the request closes `denied` — guaranteed by serializing vote application per Approval Request (see [Vote application is atomic and serialized](#design-notes) below). This is a deliberate MVP choice and is the root of the retry-amplification concern in [threat model T12](threat-model/00-overview.md) — an attacker can drive a denial → re-request loop. A future "m-of-n denials" model is a plausible mitigation.
- **`pending → timed_out`** when an approval deadline passes without quorum. **Not implemented in MVP** — approval requests currently have no expiration. This state arrives with the approval-timeout feature (see [#30](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/30)).
- **`pending → cancelled`** when the Requester withdraws. Reachable **only** from `pending`. Once a request is `approved`, the vote is recorded and signed and cannot be un-approved (doing so would corrupt the audit trail). A Requester who no longer wants an already-approved result expresses that on the Post-Approval Object instead — **Service Grant revocation** or **Action abort** — not as a cancellation of the Approval Request.

### Design notes

- **Partial quorum is a counter, not a state.** "1 of 3 approvals received" is data the Approve/Deny page displays (see [mvp.md](mvp.md)); it is not a lifecycle state. Nothing downstream behaves differently at 1 vote vs 2 — only crossing the quorum threshold fires a transition. Promoting partial counts to states would explode the machine for no behavioral gain.
- **`approved` is terminal on the approval axis but spawns work.** It is the precise point where the approval outcome is settled and the execution/grant outcome has not yet started. The two axes (approval outcome vs. execution outcome) live on different objects by design.
- **The approver set and threshold are snapshotted at creation.** A `pending` Approval Request is evaluated against the exact set of eligible approvers and the Quorum threshold **as they were when the request was created** — it is immune to later changes to the Service's configuration. This matters for three reasons:
  1. **Auditability / determinism.** The request carries a fixed, signed statement of what it required; a rule that mutates mid-vote is unauditable.
  2. **Security.** Live config changes would let a compromised admin weaken policy (lower the threshold, swap in a colluding approver) *while a malicious request is pending* and push it through. Snapshotting denies this — policy changes are forward-looking, never retroactive on a live vote.
  3. **Cast votes stay valid.** A vote already recorded against an approver's authenticated identity is not unmade if that approver is later removed from the Service config.

  **Consequence:** a config change does not affect in-flight requests. If quorum against the snapshot becomes unreachable (e.g., a snapshot approver's account is deactivated before voting), the request simply stays `pending`; in MVP (no `timed_out`) the Requester's recourse is to `cancel` it and create a fresh request against the current config. Requests are cheap to remake, so config changes should very seldom need to reach back into already-created requests.

- **Vote application is atomic and serialized per Approval Request.** Recording a Vote, recomputing effective votes, evaluating quorum/deny, performing any resulting terminal transition, and emitting that transition's events all happen in **one serialized transaction per Approval Request** (a row lock / `SELECT … FOR UPDATE` on the Approval Request). Two consequences: (1) **deny dominates a same-instant approve** — a concurrent m-th `approve` and `deny` are ordered, and the deny closes the request `denied`; (2) a Vote can never commit without its transition and events committing atomically, so a request cannot be stranded at `pending` with quorum-sufficient votes already cast (there is no `timed_out` rescue in MVP). The same lock serializes a `cancel` against a concurrent final `approve`: whichever commits first wins, and once `approved` the request can no longer be cancelled.

### Votes: append-only and supersedable

The `pending → approved` and `pending → denied` transitions are driven by **Votes** (see [CONTEXT.md](../CONTEXT.md)). The vote record is **append-only**: an Approver may cast a Vote and later change it *while the request is `pending`*, but a change never overwrites the prior record — it appends a new signed Vote that **supersedes** the earlier one. The full sequence is retained for audit; nothing is mutated or deleted.

- **Effective Vote.** Each Approver has at most one *effective* Vote at any moment: their most recent Vote while the request is `pending`. Quorum and the single-denial rule are computed **only** from effective votes, never from the full history.
- **Three decisions.** A Vote is `approve`, `deny`, or `withdraw`. A `withdraw` supersedes a prior `approve` (or `deny`) and returns the Approver to *no* effective approve/deny — it retracts an endorsement without blocking the request.
- **Quorum** is reached when the count of distinct Approvers whose effective Vote is `approve` reaches the Service's snapshotted threshold.
- **Single denial** closes the request on the **first effective `deny`** — including a flip from a prior `approve`. The deny rule itself is unchanged; it simply reads the effective Vote.
- **Freeze at terminal.** Votes may only be cast or changed while the request is `pending`. Once the request is `approved`, `denied`, `cancelled`, or `timed_out`, the vote set is frozen — the handoff (or closure) has already happened, and an `approved` request's signed votes are part of the permanent record. A change of heart after approval is expressed on the Post-Approval Object (Service Grant revocation / Action abort), not by altering a Vote.

Each Vote — including a supersession or a withdrawal — is independently signed and emits `request.vote_recorded`. This reframes the old "duplicate decisions are rejected" rule (see [threat model](threat-model/00-overview.md) T8): an *identical* repeat is still a no-op, but a *changed* decision from the same Approver is an accepted supersession, not a rejected duplicate. Only the authenticated Approver can supersede their own Vote.

## Post-approval lifecycles

### Service Grant lifecycle (forward-auth)

A **Service Grant** is created when an Approval Request reaches `approved` for a forward-auth Service. Unlike an Action (which performs an operation and ends), a Service Grant *persists* — it represents ongoing access for a bounded window, during which the User can reach the Service without triggering a new Approval Request.

| State | Meaning | Terminal? |
|---|---|---|
| `active` | Access is live. Created at handoff. The User can reach the Service. | No |
| `expired` | The grant's time window elapsed; access ends. | Yes |

```text
   (handoff: Approval Request → approved)
                  │
                  ▼
               active ──────────────────────► expired   (expires_at passes)
```

#### Transition rules

- **`(handoff) -> active`** when the Approval Request reaches `approved`. The grant records `expires_at` and is scoped to one User + one Service.
- **`active -> expired`** when `expires_at` passes. Expiry is governed by `expires_at` — or, when `grant_expiry_hours = 0`, by the end of the Requester's Proxy Session (see [config.md](config.md) and [web-proxy.md](web-proxy.md)). It is **evaluated lazily at `/auth`**: no scheduler watches the clock in the MVP, so a grant whose window has elapsed stays `active` in the store until the next `/auth` observes it expired and denies access (see [architecture.md](architecture.md)). Apart from this lazy expiry there is no other way an MVP Service Grant ends (see the no-revocation note below).

#### Design notes

- **Time-windowed only.** A single `expires_at` timestamp drives expiry. Use-count limiting is deferred (see [#37](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/37)).
- **No revocation in MVP.** There is deliberately no `revoked` state. Admin revocation is excluded to avoid concentrating unilateral power in an admin; requester self-revoke was dropped as unmotivated (a grant simply expiring is harmless). The valuable form — **approver-governed** emergency cutoff of an active grant — is a future idea (see [#36](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/36)), not approximated by a weaker MVP mechanism.
- **Consequence accepted:** there is no way to end an `active` grant before its window expires except coarse account-level action (deactivating the User or ending their Proxy Session). Grant lifetimes should be kept short to bound this exposure.
- **No `suspended` state.** Suspend/resume (temporarily freezing access without ending the grant) is out of scope for MVP.

### Action lifecycle (one-time)

> **Post-MVP — not yet implemented (see [#83](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/83)).** The persisted Action aggregate described below — the `queued → running → succeeded/failed/aborted` state machine, the `attempts` / `max_attempts` retry budget, the automatic transient-vs-permanent retry policy, the idempotent / lost-response reconciliation, and the `action.queued` / `action.started` / `action.retrying` / `action.aborted` events — is **deferred to post-MVP**. In the current MVP a one-time approval executes its action (`publish-to-pypi`) **synchronously as a single attempt** at handoff: no persisted Action row, no retry, no abort; only the `action.succeeded` / `action.failed` outcome is signalled. This section specifies the target design for when that work is picked up.

An **Action** is created when an Approval Request reaches `approved` for a one-time Service. It owns the *execution outcome* axis — distinct from the *approval outcome* axis owned by the Approval Request. An Action being `approved` upstream does **not** mean the operation succeeded; `succeeded` and `failed` are decided here, by the external service, after the vote concluded.

| State | Meaning | Terminal? |
|---|---|---|
| `queued` | Created at handoff, or re-enqueued after a transient failure. Waiting for the executor. | No |
| `running` | The executor is actively performing the operation; an external call is in flight. | No |
| `succeeded` | The external service accepted the operation. | Yes |
| `failed` | Retries exhausted, or a permanent rejection that retrying cannot fix. | Yes |
| `aborted` | The Requester withdrew the Action before execution began. | Yes |

```text
   (handoff: Approval Request → approved)
                  │
                  ▼
   ┌─────────► queued ──────────────► aborted   (requester withdraws, pre-execution)
   │             │
   │             ▼
   │          running ──────────────► succeeded
   │             │
   │  transient  │  permanent reject
   │  (attempts  │  OR attempts exhausted
   │   remain)   ▼
   └──────────  failed
   (re-enqueue, attempts++)
```

#### Transition rules

- **`(handoff) → queued`** when the Approval Request reaches `approved`. The Action carries the `action_hash` fixed at request time, so the executor runs exactly the payload the approvers voted on.
- **`queued → running`** when the executor picks up the Action.
- **`queued → aborted`** when the Requester withdraws. Reachable **only** from `queued`, before execution begins. Once `running`, there is no abort — an external side effect may already be in flight (e.g., a PyPI upload partially applied). This is the Action-side analogue of the Approval Request's "`cancelled` only from `pending`" rule: you can withdraw work that has not started, not work already in motion.
- **`running → succeeded`** when the external service accepts the operation.
- **`running → queued`** on a **transient** failure (network error, timeout, 5xx) when `attempts < max_attempts`. Increments the `attempts` counter. This re-enqueue *is* the retry — there is no separate `retrying` state.
- **`running → failed`** when either (a) the failure is a **permanent rejection** that retrying cannot fix (e.g., PyPI "version already exists", a 4xx), or (b) a transient failure occurs with `attempts >= max_attempts`. Exception: a "version already exists" that *this* Action authored (a lost-response retry) is reconciled to `succeeded`, not `failed` — see the reconciliation note below.

#### Design notes

- **Retry is automatic and bounded (hybrid policy).** Transient failures auto-retry up to `max_attempts`; permanent rejections skip retries and go straight to terminal `failed`. The executor classifies each failure as transient vs. permanent (typically: retry on network errors and 5xx, give up on 4xx). This avoids burning the retry budget on structurally unfixable errors.
- **`attempts` is a count, not a timer.** The machine has no timing state. `attempts` is an integer incremented on each `running → queued` bounce; `attempts >= max_attempts` is the condition that diverts to terminal `failed`.
- **`running` means "an external call is in flight right now."** The retry-wait period lives in `queued`, not `running`, deliberately. This keeps a clean invariant for crash recovery and idempotency: if the system died while an Action was `running`, a side effect may have been partially applied and must be reconciled before retrying. A `queued` Action (even with `attempts > 0`) has no call in flight.
- **Handoff is idempotent.** The transactional outbox that delivers `request.approved` guarantees *at-least-once*, so a relay retry after a crash can redeliver it. A uniqueness constraint on `approval_request_id` for the spawned Post-Approval Object makes a redelivered event a **no-op** — a second delivery cannot create a second Action (or a second Service Grant), so it cannot cause a double publish. This is what keeps the Security ① oracle ("the PyPI mock is never invoked", [mvp-prd.md](mvp-prd.md#L89)) intact under redelivery.
- **Publish is reconciled, not blindly retried, after a lost response.** If a publish succeeds at PyPI but its HTTP response is lost, the retry hits PyPI's `version already exists` 400 ([line 152](#action-lifecycle-one-time)). Because PyPI versions are immutable, that version was created by *this* Action — so the Executor reconciles "version already exists, attributable to this Action" to **`succeeded`**, not `failed`, distinguishing it from a genuine collision authored elsewhere (which remains a permanent `failed`). Sources: [PyPI version immutability — warehouse #6872](https://github.com/pypi/warehouse/issues/6872).
- **The held artifact is destroyed at a terminal outcome — on every path.** A one-time Service stages the uploaded artifact at request creation; it must not outlive the request. Destruction is owned explicitly: on the **approved** path the **Executor** deletes the held artifact when the Action reaches `succeeded`, `failed`, or `aborted`; on the **non-handoff** terminals (`denied`, `cancelled`, and future `timed_out`), the Approval Request's terminal-transition handler deletes it, since no Executor handoff fires. Each deletion emits `artifact.destroyed`. Forward-auth Services stage no artifact and are unaffected.

## Events

Each lifecycle transition emits an **event**. The lifecycle emits *blind* — it does not know or care who is listening (the decoupling principle from [ADR 0005](adr/0005-decoupled-notification-system.md)). Consumers subscribe to the catalog; emission and delivery are separate concerns.

> **Note:** This catalog is the reference; the authoritative list is the code. The events **implemented today** are **typed frozen dataclasses** in `core/events.py` ([ADR 0014](adr/0014-typed-lifecycle-events.md)) — the discriminator is the concrete type, not the name string, and the `<object>.<event>` string survives only as the dataclass's catalog label (the audit trail's `event_name`). The typed set is the `request.*`, `action.succeeded`/`action.failed`, `grant.*`, `artifact.destroyed`, and `account.*` events (catalogued with their fields in [ADR 0014](adr/0014-typed-lifecycle-events.md)); the remaining rows below describe the intended model and have no dataclass yet.

### Event catalog

Events are named `<object>.<event>`; an implemented event's dataclass is the PascalCase of that name (e.g. `request.created` → `RequestCreated`). Most correspond to a state transition; two do not (`request.vote_recorded` is a per-vote event with no state change; `action.retrying` is the `running → queued` retry loop, not a new state).

| Event | Fires when | Key payload |
|---|---|---|
| `request.created` | An Approval Request is created (`→ pending`) | `approval_request_id`, `service_name`, `requester_id` (the code-authoritative payload). The snapshotted approver set + threshold, `action_hash`, and Approval Link are **not** in the event — they are recovered from the persisted Approval Request, which the critical write guarantees (consumers resolve them by `approval_request_id`) |
| `request.vote_recorded` | An approver casts or changes a vote — `approve`, `deny`, or `withdraw` (no state change) | `approval_request_id`, approver identity, decision, signature, running tally (over effective votes) |
| `request.approved` | Quorum reached (`pending → approved`) | `approval_request_id`, `service_name`, `requester_id` (the code-authoritative payload). The spawned Post-Approval Object's ID is **not** in the event — it is recovered from the persisted Approval Request after the handoff (the forward-auth `service_grant_id` forward pointer; the one-time MVP publishes synchronously with no persisted Action, see [Action lifecycle](#action-lifecycle-one-time)). The event is emitted on the `pending → approved` transition, just before the type-specific handoff runs |
| `request.denied` | First denial (`pending → denied`) | `approval_request_id`, denying approver |
| `request.cancelled` | Requester withdraws (`pending → cancelled`) | `approval_request_id` |
| `request.timed_out` | Deadline passes (`pending → timed_out`) *(future)* | `approval_request_id` |
| `action.queued` | Action created at handoff, or re-enqueued for retry (`→ queued`) | `action_id`, `approval_request_id`, `attempts` |
| `action.started` | Executor picks up the Action (`queued → running`) | `action_id`, `attempts` |
| `action.succeeded` | External service accepts (`running → succeeded`) | `action_id`, result reference |
| `action.failed` | Terminal failure (`running → failed`) | `action_id`, failure classification, last error |
| `action.retrying` | Transient failure, will retry (`running → queued`) | `action_id`, `attempts`, error |
| `action.aborted` | Requester withdraws pre-execution (`queued → aborted`) | `action_id` |
| `grant.activated` | Service Grant issued at handoff (`→ active`) | `grant_id`, `approval_request_id`, `expires_at` |
| `grant.expired` | Time window elapses (`active → expired`) | `grant_id` |
| `artifact.destroyed` | Held artifact deleted at a terminal outcome (any path) | `approval_request_id`, `action_id` (if any), terminal state |

### Consumers and reliability classes

Consumers fall into two classes by how a missed event is treated. This is the precise, enforceable form of [ADR 0005](adr/0005-decoupled-notification-system.md)'s rule that *notification failures must not block approvals*:

**Critical / guaranteed — a missed event is a system fault.** Implemented so the event is processed atomically with (or reliably after) the transition, e.g., a transactional outbox.

- **Audit** — subscribes to *every* event, unconditionally and non-configurably. Records approver identity, signature, and timestamps (see [CONTEXT.md](../CONTEXT.md) and [mvp.md](mvp.md)).
- **Handoff / executor** — runs on `request.approved`. The executor **allocates the Post-Approval Object's ID at handoff**: it creates the object (spawns the Action / issues the Service Grant), then writes the forward link back onto the Approval Request, completing the bidirectional link. The ID is recovered from the persisted Approval Request, **not** carried in the `request.approved` event payload. A redelivered `request.approved` is a **no-op** — a uniqueness constraint on `approval_request_id` for the spawned object means a second delivery cannot create a second Action / Grant. If the handoff never runs, an approved request never produces its Post-Approval Object — a silently lost operation — so this step must not be best-effort. *(MVP note: post-approval work runs synchronously in-band on the closing vote's transition rather than off a transactional outbox; the durable at-least-once outbox is part of the post-MVP Action work, [#83](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/83).)*

**Best-effort — a missed event is recoverable and does not corrupt state.** The lifecycle has already advanced; failure here is tolerable by design.

- **Notification system** — subscribes to the catalog and delivers messages to users. In MVP, subscriptions are **fixed defaults** (hardcoded, no per-user configuration); a per-user settings page that lets users opt in/out of events is a future enhancement. **Default subscriptions are defined in the notification-system spec, not here** — this doc defines the catalog only. Notification failures never affect the lifecycle.
- **Quorum-progress UI** — consumes `request.vote_recorded` plus the closing events (`request.approved` / `denied` / `cancelled`) to render live status (e.g., "2 of 3 received"). A stale UI is harmless.

The catalog is open to additional consumers without changing the lifecycle — for example, **T12 anomaly detection** (see [threat model](threat-model/00-overview.md)) would subscribe to `request.created` to detect request floods / approval-fatigue bursts.
