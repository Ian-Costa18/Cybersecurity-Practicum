# Vertical-Slice Package Layout (Lifecycle Slices + Service-Type Verticals)

## Status
Accepted

## Context

The application code lives in a single flat package, `src/msig_proxy/` — ~25 modules side by side, with no structural boundary between the HTTP surface and the logic beneath it. Two problems followed from that flatness (both captured in [#67](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/67)):

1. **Routers and logic are interleaved with nothing separating them.** The would-be "domain" modules are shot through with the web framework: `auth.authenticate_requester` is a FastAPI `Depends`-wired function, and `deps.py` is entirely dependency-injection glue. So they are *adapters*, not framework-free logic — you cannot exercise the approval rules without standing up the app.
2. **Service-type behavior is smeared across the package.** The one-time vs forward-auth divergence shows up in `intake.py` (two creation functions), `post_approval.py` (two handlers), `executor.py` (publish primitives *and* grant primitives in one file), and the held-artifact lifecycle is split between `intake.py` (staged at creation) and `executor.py`/`post_approval.py` (destroyed at terminal). No single place owns "what one-time does."

The decision is how to restructure the package so that (a) it reads by feature/flow rather than as a flat module pile, (b) a dependency *rule* — not just a folder — keeps the logic framework-free, and (c) the per-service-type divergence is localized.

## Considered Options

### Option A: Layered — `web/` over a framework-free `domain/`

All routers move to a top-level `web/` package; everything else becomes `domain/`. The dependency rule is "domain must not import the web framework," pointing `web → domain`.

- **Advantage:** One obvious rule, one obvious place for the HTTP surface.
- **Disadvantage:** A `web/` folder *does not* enforce the rule on its own (#67) — the property comes from the import discipline, which a layout can't guarantee. Worse, it splits every feature across two trees: reading "how does approval work" means hopping between `web/approve.py` and `domain/votes.py`. This fights the flow-cohesion the team values.

### Option B: Vertical slices by lifecycle stage, with service-type verticals for the divergent tail

Top-level folders are the lifecycle stages a request moves through (`auth → accounts → approvals → service_types`), and **each slice holds its own web edge and its own logic**. The two service types are grouped under one `service_types/` slice, each owning its whole-lifecycle type-specific behavior.

- **Advantage:** A feature reads top-to-bottom in one folder. The front of the app (type-agnostic flow) organizes by stage; the back (type-divergent behavior) organizes by service type — mirroring exactly where the domain forks ([ADR 0007](0007-two-aggregate-request-model.md)).
- **Disadvantage:** A *mixed* taxonomy (stage in front, type in back) is one more thing a reader must be told. The dependency rule still has to be stated and held — it lives *within* each slice (only the web-edge files import the framework) rather than at one big `web/` boundary.

## Decision

**Chosen: Option B — vertical slices by lifecycle stage, with a single `service_types/` slice for the divergent tail.**

Top-level slices: `auth/`, `accounts/`, `approvals/`, `service_types/`, `notifications/`, plus framework-free `core/` and the `app.py`/`deps.py` composition glue. The `service_types/` slice contains `one_time/` and `forward_auth/`, each owning that type's behavior across the *entire* request lifetime (intake, staging, terminal handling, consumption), and a type-blind `dispatch.py`. The full map and the per-slice responsibilities live in [source-layout.md](../source-layout.md), which is the living document this ADR authorizes.

Two rules are part of the decision, not incidental:

1. **The dependency rule (the actual invariant).** Within a slice, only the **web-edge** files import the web framework (`APIRouter`, `Depends`, `Form`, `Request`, `Response`, `HTTPException`). Every other file is **framework-free**: it takes a `Session`/`AppConfig`/plain args and returns plain values or raises domain errors. Dependencies flow `web-edge → framework-free logic → core`, never the reverse. The folders are merely where this rule is *visible*; the rule is the design.

2. **Service Handler rename.** The per-service-type terminal behavior, formerly the **Post-Approval Handler**, is renamed the **Service Handler** to reflect that its slice now owns the type's whole lifetime, not only the post-approval moment. Its *dispatched interface* stays narrow — the terminal hooks (`on_approved` / `on_denied` / `on_cancelled`) both types genuinely share — because terminal handling is the **only** point reached without knowing the service type (see Rationale). The glossary in [CONTEXT.md](../../CONTEXT.md) is updated in the same change.

## Rationale

1. **Converge-then-diverge mirrors the data model.** [ADR 0007](0007-two-aggregate-request-model.md) already established that the two service types share the *entire* approval core and diverge only at the post-approval handoff. Organizing the front of the app by lifecycle stage (convergent) and the back by service type (divergent) puts the folder seam exactly where the domain seam already is.

2. **The dependency rule is the real fix #67 named.** The issue was explicit that the first step is "purging FastAPI `Depends` out of the domain modules," not moving routers. Carrying the rule *into* each slice — web-edge imports the framework, logic does not — is what makes the approval rules testable without the app and demolishes the `Depends`-in-domain problem at its source.

3. **Terminal handling is the only type-blind reach point.** `finalize` is called from the generic voting/cancellation path with an `ApprovalRequest` whose type it doesn't know, so a dispatcher plus per-type handler is required to recover the type at runtime. Intake has no such problem: each type has its own inbound trigger (the upload endpoint for one-time, the access route for forward-auth), so the router already knows the type and calls directly. This is why the Service Handler's dispatched interface is the *narrow* terminal contract and intake/staging/consumption are sibling files in the slice rather than methods on the handler — folding them in would produce a fat interface where each type no-ops the other's methods.

4. **Self-contained verticals over DRY.** Each service type owns its creation end-to-end; the only genuinely shared, must-not-drift creation logic is the eligible-approver + quorum snapshot (ADR 0008), which lives in `approvals/` because `approvals` both *writes* that rule (snapshot at creation) and *reads* it (the Tally). The residual duplication is a few lines of `ApprovalRequest(...)` construction across the two `intake.py` files — accepted in exchange for each type reading top-to-bottom in one folder.

## Implications

- **`executor.py` and `post_approval.py` dissolve.** Their primitives move into the type they belong to: one-time gets `publish.py` + `artifact.py`, forward-auth gets `grant.py` + `resolve.py`; the type-blind dispatcher (`ServiceHandler` ABC + registry + `finalize`) becomes `service_types/dispatch.py`.
- **The held artifact lives entirely in `one_time/`.** Forward-auth stages nothing (`ForwardAuthHandler.on_denied` is already a no-op), so staging *and* destruction belong to `one_time/`, not a shared layer.
- **The `login.py` smudge is removed.** `POST /login` returns to authenticate-and-redirect only; the forward-auth access-request creation and its `request.created` emit move to a guarded `forward_auth/access.py` route. `auth/` then imports nothing from `service_types/`.
- **Per-route login gating is explicit.** The session/admin guards (`current_session_user`, `require_session_user`, `require_admin`) live in `auth/guards.py`; any slice's web edge opts a route into login by declaring the guard, and public routes omit it.
- **The migration is incremental** (tracked in [#67](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/67)); until it completes, [source-layout.md](../source-layout.md) is the target the moves converge toward.
- The "Post-Approval Handler" term is retired from the glossary; downstream prose that still uses it (e.g. `request-lifecycle.md`, `notification-system.md`) is corrected as the corresponding code moves.

## Trade-offs Accepted

- **Mixed taxonomy.** The front of the app is organized by lifecycle stage and the back by service type. A reader has to be told this once — which is precisely what this ADR and [source-layout.md](../source-layout.md) do. Accepted because it tracks the domain's own converge/diverge seam rather than imposing a single uniform axis that would fit one half badly.
- **A little duplication over a shared spine.** The `ApprovalRequest(...)` constructor call appears in both `intake.py` files; a required-field change touches two files. Accepted for vertical cohesion; the security-relevant shared logic (the snapshot) is *not* duplicated.
- **Slices do not own their schema.** A single shared `core/models.py` keeps the ORM and its cross-slice foreign keys in one place; the cost is that each slice's persistent types live outside the slice. Accepted because the relational coupling is intrinsic — pretending each row belongs to one slice fights SQLAlchemy — and per-slice *domain* types are better pursued via typed states ([#56](https://github.com/Ian-Costa18/Cybersecurity-Practicum/issues/56)) than by splitting the schema.
- **One cross-cutting reader.** The User Portal (`accounts/portal.py`) lists a User's requests, approvals, and tokens, so it reads across `approvals` and `service_types`. It is permitted this as a *read-only* presentation aggregator rather than being split across the slices it surfaces.
