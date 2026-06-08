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

The two aggregates are **bidirectionally linked**: each carries its own unique ID and references the other. An auditor can walk forward from an approval to what it caused, and backward from an executed Action (or granted access) to the exact vote that authorized it. Reaching a terminal approval state concludes the *vote*, not the *record* — the forward link to the spawned Post-Approval Object is written at handoff.

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
- **`pending → denied`** on the **first effective `deny`** (including a flip from a prior `approve`; see [Votes](#votes-append-only-and-supersedable) below). A single denial immediately and permanently closes the request; there is no "quorum of denials." This is a deliberate MVP choice and is the root of the retry-amplification concern in [threat-model.md T12](threat-model.md) — an attacker can drive a denial → re-request loop. A future "m-of-n denials" model is a plausible mitigation.
- **`pending → timed_out`** when an approval deadline passes without quorum. **Not implemented in MVP** — approval requests currently have no expiration. This state arrives with the approval-timeout feature (see [ideas.md](ideas.md)).
- **`pending → cancelled`** when the Requester withdraws. Reachable **only** from `pending`. Once a request is `approved`, the vote is recorded and signed and cannot be un-approved (doing so would corrupt the audit trail). A Requester who no longer wants an already-approved result expresses that on the Post-Approval Object instead — **Service Grant revocation** or **Action abort** — not as a cancellation of the Approval Request.

### Design notes

- **Partial quorum is a counter, not a state.** "1 of 3 approvals received" is data the Approve/Deny page displays (see [mvp.md](mvp.md)); it is not a lifecycle state. Nothing downstream behaves differently at 1 vote vs 2 — only crossing the quorum threshold fires a transition. Promoting partial counts to states would explode the machine for no behavioral gain.
- **`approved` is terminal on the approval axis but spawns work.** It is the precise point where the approval outcome is settled and the execution/grant outcome has not yet started. The two axes (approval outcome vs. execution outcome) live on different objects by design.
- **The approver set and threshold are snapshotted at creation.** A `pending` Approval Request is evaluated against the exact set of eligible approvers and the Quorum threshold **as they were when the request was created** — it is immune to later changes to the Service's configuration. This matters for three reasons:
  1. **Auditability / determinism.** The request carries a fixed, signed statement of what it required; a rule that mutates mid-vote is unauditable.
  2. **Security.** Live config changes would let a compromised admin weaken policy (lower the threshold, swap in a colluding approver) *while a malicious request is pending* and push it through. Snapshotting denies this — policy changes are forward-looking, never retroactive on a live vote.
  3. **Cast votes stay valid.** A vote already recorded against an approver's authenticated identity is not unmade if that approver is later removed from the Service config.

  **Consequence:** a config change does not affect in-flight requests. If quorum against the snapshot becomes unreachable (e.g., a snapshot approver's account is deactivated before voting), the request simply stays `pending`; in MVP (no `timed_out`) the Requester's recourse is to `cancel` it and create a fresh request against the current config. Requests are cheap to remake, so config changes should very seldom need to reach back into already-created requests.

### Votes: append-only and supersedable

The `pending → approved` and `pending → denied` transitions are driven by **Votes** (see [CONTEXT.md](../CONTEXT.md)). The vote record is **append-only**: an Approver may cast a Vote and later change it *while the request is `pending`*, but a change never overwrites the prior record — it appends a new signed Vote that **supersedes** the earlier one. The full sequence is retained for audit; nothing is mutated or deleted.

- **Effective Vote.** Each Approver has at most one *effective* Vote at any moment: their most recent Vote while the request is `pending`. Quorum and the single-denial rule are computed **only** from effective votes, never from the full history.
- **Three decisions.** A Vote is `approve`, `deny`, or `withdraw`. A `withdraw` supersedes a prior `approve` (or `deny`) and returns the Approver to *no* effective approve/deny — it retracts an endorsement without blocking the request.
- **Quorum** is reached when the count of distinct Approvers whose effective Vote is `approve` reaches the Service's snapshotted threshold.
- **Single denial** closes the request on the **first effective `deny`** — including a flip from a prior `approve`. The deny rule itself is unchanged; it simply reads the effective Vote.
- **Freeze at terminal.** Votes may only be cast or changed while the request is `pending`. Once the request is `approved`, `denied`, `cancelled`, or `timed_out`, the vote set is frozen — the handoff (or closure) has already happened, and an `approved` request's signed votes are part of the permanent record. A change of heart after approval is expressed on the Post-Approval Object (Service Grant revocation / Action abort), not by altering a Vote.

Each Vote — including a supersession or a withdrawal — is independently signed and emits `request.vote_recorded`. This reframes the old "duplicate decisions are rejected" rule (see [threat-model.md](threat-model.md) T8): an *identical* repeat is still a no-op, but a *changed* decision from the same Approver is an accepted supersession, not a rejected duplicate. Only the authenticated Approver can supersede their own Vote.

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
- **`active -> expired`** when `expires_at` passes. This is the **only** way an MVP Service Grant ends.

#### Design notes

- **Time-windowed only.** A single `expires_at` timestamp drives expiry. Use-count limiting is deferred (see [ideas.md](ideas.md)).
- **No revocation in MVP.** There is deliberately no `revoked` state. Admin revocation is excluded to avoid concentrating unilateral power in an admin; requester self-revoke was dropped as unmotivated (a grant simply expiring is harmless). The valuable form — **approver-governed** emergency cutoff of an active grant — is a future idea (see [ideas.md](ideas.md)), not approximated by a weaker MVP mechanism.
- **Consequence accepted:** there is no way to end an `active` grant before its window expires except coarse account-level action (deactivating the User or ending their Proxy Session). Grant lifetimes should be kept short to bound this exposure.
- **No `suspended` state.** Suspend/resume (temporarily freezing access without ending the grant) is out of scope for MVP.

### Action lifecycle (one-time)

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
- **`running → failed`** when either (a) the failure is a **permanent rejection** that retrying cannot fix (e.g., PyPI "version already exists", a 4xx), or (b) a transient failure occurs with `attempts >= max_attempts`.

#### Design notes

- **Retry is automatic and bounded (hybrid policy).** Transient failures auto-retry up to `max_attempts`; permanent rejections skip retries and go straight to terminal `failed`. The executor classifies each failure as transient vs. permanent (typically: retry on network errors and 5xx, give up on 4xx). This avoids burning the retry budget on structurally unfixable errors.
- **`attempts` is a count, not a timer.** The machine has no timing state. `attempts` is an integer incremented on each `running → queued` bounce; `attempts >= max_attempts` is the condition that diverts to terminal `failed`.
- **`running` means "an external call is in flight right now."** The retry-wait period lives in `queued`, not `running`, deliberately. This keeps a clean invariant for crash recovery and idempotency: if the system died while an Action was `running`, a side effect may have been partially applied and must be reconciled before retrying. A `queued` Action (even with `attempts > 0`) has no call in flight.

## Events

Each lifecycle transition emits an **event**. The lifecycle emits *blind* — it does not know or care who is listening (the decoupling principle from [ADR 0005](adr/0005-decoupled-notification-system.md)). Consumers subscribe to the catalog; emission and delivery are separate concerns.

> **Note:** This catalog is enumerated here because no implementation exists yet. Once the code exists, the authoritative event list is derivable from it, and this section becomes a reference rather than a source of truth.

### Event catalog

Events are named `<object>.<event>`. Most correspond to a state transition; two do not (`request.vote_recorded` is a per-vote event with no state change; `action.retrying` is the `running → queued` retry loop, not a new state).

| Event | Fires when | Key payload |
|---|---|---|
| `request.created` | An Approval Request is created (`→ pending`) | `approval_request_id`, requester, service, snapshotted approver set + threshold, `action_hash` (if any), Approval Link |
| `request.vote_recorded` | An approver casts or changes a vote — `approve`, `deny`, or `withdraw` (no state change) | `approval_request_id`, approver identity, decision, signature, running tally (over effective votes) |
| `request.approved` | Quorum reached (`pending → approved`) | `approval_request_id`, final tally, spawned Post-Approval Object ID |
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

### Consumers and reliability classes

Consumers fall into two classes by how a missed event is treated. This is the precise, enforceable form of [ADR 0005](adr/0005-decoupled-notification-system.md)'s rule that *notification failures must not block approvals*:

**Critical / guaranteed — a missed event is a system fault.** Implemented so the event is processed atomically with (or reliably after) the transition, e.g., a transactional outbox.

- **Audit** — subscribes to *every* event, unconditionally and non-configurably. Records approver identity, signature, and timestamps (see [CONTEXT.md](../CONTEXT.md) and [mvp.md](mvp.md)).
- **Handoff / executor** — subscribes to `request.approved`; creates the Post-Approval Object (spawns the Action / issues the Service Grant) and writes the bidirectional link. If this is dropped, an approved request never produces its Post-Approval Object — a silently lost operation. It must not be best-effort.

**Best-effort — a missed event is recoverable and does not corrupt state.** The lifecycle has already advanced; failure here is tolerable by design.

- **Notification system** — subscribes to the catalog and delivers messages to users. In MVP, subscriptions are **fixed defaults** (hardcoded, no per-user configuration); a per-user settings page that lets users opt in/out of events is a future enhancement. **Default subscriptions are defined in the notification-system spec, not here** — this doc defines the catalog only. Notification failures never affect the lifecycle.
- **Quorum-progress UI** — consumes `request.vote_recorded` plus the closing events (`request.approved` / `denied` / `cancelled`) to render live status (e.g., "2 of 3 received"). A stale UI is harmless.

The catalog is open to additional consumers without changing the lifecycle — for example, **T12 anomaly detection** (see [threat-model.md](threat-model.md)) would subscribe to `request.created` to detect request floods / approval-fatigue bursts.
