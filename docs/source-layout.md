# Source Layout

The structural map of `src/msig_proxy/`: the slices, what each owns, and the one dependency rule that makes the structure mean something. Read this **before any structural work** (adding a module, moving logic, wiring a new route).

> **You MUST update this file in the same change** whenever you add, move, rename, or remove a slice or a slice's responsibility, or alter the dependency rule. A layout map that lags the code is worse than none.

This map is **structural, not a file inventory** — it names slices and responsibilities, not every file. For file/symbol-level discovery (where a symbol is defined, who calls it), use the sverklo index (`sverklo_overview` / `sverklo_search`), not this document.

The decision and rationale behind this layout are frozen in [ADR 0012](adr/0012-vertical-slice-package-layout.md). Domain terms (Service Handler, Approval Request, Service Grant, Action) are defined in [CONTEXT.md](../CONTEXT.md).

## The dependency rule (the actual invariant)

A slice is not just a folder — it is a folder plus this rule:

- **Within a slice, only the web-edge files import the web framework** — `APIRouter`, `Depends`, `Form`, `Request`, `Response`, `HTTPException`. These are tagged `[web]` below.
- **Every other file is framework-free** (`[pure]`): it takes a `Session` / `AppConfig` / plain arguments and returns plain values or raises domain errors. No FastAPI symbol appears in it.
- **Dependencies flow one way:** `web-edge → framework-free logic → core`. Never the reverse; `core/` imports no slice, and `approvals/` does not import `service_types/`.

`[pure]` means *free of the inbound web framework*, not free of all I/O — an outbound adapter (e.g. the PyPI HTTP POST, SMTP send) is still `[pure]` because it is not FastAPI.

Example: in `auth/`, the login route and the session/admin guards are web-edge; credential verification and Proxy Session handling are framework-free — so the auth rules can be exercised without standing up the app. Apply the same split in every slice.

## The slices

Each slice holds its own web edge and its own logic. The line is one per slice — what it *owns*, not which files it contains (ask sverklo for files).

```
src/msig_proxy/
  app.py / deps.py     composition root (mount routers, wire subscribers) + shared FastAPI providers

  core/                shared, owned by no slice: models · db · config · events (the seam) · crypto

  auth/                prove who you are, and enforce it per route — login/logout, the session
                       and admin guards, credential + Proxy Session logic

  accounts/            identity & account management — Admin Portal, enrollment, signing-key
                       lifecycle, seeding, and the read-only User Portal (the cross-cutting reader)

  approvals/           vote an Approval Request to a terminal outcome (type-agnostic) — the /approve
                       routes, the waiting room + SSE, the Tally, and the eligibility+quorum snapshot

  service_types/       everything that DIVERGES by service type, across the whole request lifetime
    dispatch.py        the type-blind seam: ServiceHandler contract + registry + finalize
    one_time/          submit-then-publish (e.g. PyPI): inbound upload, intake + artifact staging,
                       hash re-verification + publish, artifact destruction, its Service Handler
    forward_auth/      interactive backend access: the /auth gate, the post-login access trigger,
                       intake, grant issue + resolve, its Service Handler

  notifications/       best-effort event subscriber (ADR 0005): consume lifecycle events, render + deliver
```

## Rules of the layout

- **Front by stage, back by type.** `auth → accounts → approvals` is the convergent, type-agnostic flow. `service_types/` is the divergent tail, organized by service type because that is where the domain forks ([ADR 0007](adr/0007-two-aggregate-request-model.md)). This mixed taxonomy is deliberate.
- **A service type owns its whole lifetime.** `one_time/` and `forward_auth/` each own intake, terminal handling, and (for forward-auth) consumption. The held artifact lives entirely in `one_time/` — forward-auth stages nothing.
- **The Service Handler's dispatched interface is narrow.** Only the terminal hooks (`on_approved` / `on_denied` / `on_cancelled`) are dispatched, because terminal handling is the only point reached without knowing the type. Intake and consumption are sibling files, not handler methods.
- **The snapshot lives in `approvals/`.** It is written at creation but owned by `approvals` because `approvals` also reads it (the Tally). The service-type intakes import `approvals.snapshot`; `approvals` imports nothing from `service_types`.
- **The User Portal (in `accounts/`) is the one sanctioned cross-cutting reader** — read-only, surfacing a User's requests/approvals/tokens from other slices.
