# Technology Stack Selection

## Status
Accepted

## Context

Until now, exactly one technology was fixed: **Python** ([architecture.md](../architecture.md) states "No technologies are chosen yet. Python is the only fixed decision"). The architecture deliberately named each component by its *responsibility* (Proxy, Store, Executor, Notifier, Audit) so that a concrete technology could "drop in at the seam" when implementation began. [ADR 0003](0003-cryptographic-primitive-selection.md) locked the cryptographic *primitives* (Ed25519, PBKDF2-HMAC-SHA-256, AES-256-GCM, bcrypt, SHA-256) but not the libraries that implement them. [ADR 0006](0006-build-proxy-from-scratch.md) committed to building the proxy from scratch in Python rather than extending an existing IdP.

Implementation is now beginning (the *thinnest-thesis-first* build sequence in [mvp.md](../mvp.md)). This ADR records the stack chosen for that build and, for each choice, why it was preferred over its realistic counterparts. It records decisions at the *consequential* level — choices that are hard to reverse or that a future reader would question. The exhaustive package list and version pins live in `pyproject.toml`, which is the right home for that detail; this ADR is not a dependency manifest.

## Decision

| Concern | Choice | Beat out |
|---|---|---|
| Web framework / server | **FastAPI on Uvicorn** (ASGI, async) | Flask (sync/WSGI), Django, plain Starlette |
| Human-facing UI | **htmx + Jinja2** (server-rendered HTML fragments) | React/Vue SPA, Alpine/vanilla-only |
| Browser-consumed JSON API | **Deferred to post-MVP** (`/api/v1/*`) | Building it in the MVP |
| Database engine | **SQLite** for MVP | PostgreSQL (deferred to production) |
| Database access | **SQLAlchemy 2.0** (explicit style) + **Alembic** | Raw SQL, ORM-magic / SQLModel |
| Cryptography | **`cryptography`** + **`bcrypt`** | PyNaCl, passlib |
| TOTP | **`pyotp`** | — |
| Sessions | **Server-side opaque token** (stdlib `secrets` + `hmac`) | JWT / stateless signed cookie |
| Validation & config | **Pydantic + pydantic-settings** | Untyped dicts, manual validation |
| Outbound HTTP | **`httpx`** | `requests` |
| Mail send / mail test | **`aiosmtplib`** / **`aiosmtpd`** | stdlib `smtplib` |
| Dependency management | **uv** | pip + venv, Poetry, PDM |
| Lint / format | **ruff** (incl. `S` security rules) | black + flake8 + isort + bandit |
| Type checking | **ty** | mypy, Pyright |

## Rationale

### Web framework: FastAPI on Uvicorn (async ASGI)

The deciding factor is the **waiting-room Server-Sent Events stream** ([web-proxy.md](../web-proxy.md)). A Requester holds an SSE connection open for the entire time quorum is being gathered — potentially minutes to hours. On a synchronous WSGI stack each open connection pins a worker for its whole lifetime, so a handful of waiting Requesters exhausts the worker pool; on async ASGI, many idle-but-open connections cost almost nothing.

- **Over Flask** — sync/WSGI; SSE is worker-bound. Loses on the central UX feature.
- **Over Django** — Django's headline value is its batteries, chiefly its auth system, but [ADR 0006](0006-build-proxy-from-scratch.md) commits to building auth from scratch precisely because the crypto model needs the plaintext password at approval time. Django's auth would fight that, its async ORM story is second-class, and it is heavy for a small closed-team proxy.
- **Over plain Starlette** (FastAPI's own foundation) — FastAPI's dependency-injection maps almost one-to-one onto the four distinct auth modes in [web-proxy.md](../web-proxy.md) (Proxy Session, `is_admin`, API token, per-request fresh approval re-auth), keeping each guard clean and independently testable. Worth the small additional weight over bare Starlette.

### Human UI: htmx + Jinja2; JSON API deferred

The system has two surfaces: a **machine integration surface** (`/auth`, `/pypi/legacy/`, the SSE stream) that is inherently protocol/API, and a **human surface** (login, enroll, approve/deny, portals) where the rendering approach is a genuine choice.

For the human surface, htmx delivers dynamic, server-driven pages (submit form, refresh a list, swap a row) **without a Node/npm build pipeline**. Avoiding that pipeline is especially apt here: the project's *thesis is supply-chain attacks via package ecosystems*, so adding npm's dependency surface to the proxy would be self-undermining. htmx is a single vendored `.js` file — not a pip or npm dependency — so it adds nothing to either dependency tree.

- **Over a React/Vue SPA** — a second toolchain, a bundler, and npm supply-chain surface, for a UI that is mostly forms and lists. Not justified.
- **Over Alpine/vanilla only** — htmx is the better fit for server round-trips; Alpine remains available for purely-local UI state if needed. Same zero-build-step posture.

The security-critical pages (login, enroll, approve/deny) stay server-rendered regardless, minimizing client-side attack surface on exactly the pages that matter most. A browser-consumed JSON API (`/api/v1/*`) for external integrators is **out of MVP scope**; when built it will be a surface *separate* from the htmx HTML-fragment endpoints rather than content-negotiated onto them.

### Database: SQLite now, SQLAlchemy + Alembic, Postgres seam later

SQLite satisfies the spec's two hard constraints — the database is **never mocked** in tests ([mvp.md](../mvp.md)) and is a **single logical Store** ([architecture.md](../architecture.md)) — while being zero-ops and single-file. The system is explicitly low-throughput (< 100 logins/day, [ADR 0003](0003-cryptographic-primitive-selection.md)). [architecture.md](../architecture.md) already names PostgreSQL as the *future* production target, so the only requirement is a clean access seam for that later swap.

For access, **SQLAlchemy 2.0 used in an explicit style** (no lazy-loaded relationships; `select()`-based statements) with **Alembic** migrations:

- **Over raw SQL** — parameterized SQLAlchemy removes a whole class of injection risk by default and provides the Postgres-portability seam for free; raw SQL trades that for boilerplate and a larger footgun surface in a *security* codebase.
- **Over a magic ORM / SQLModel** — the vote and audit records are Ed25519-signed over canonical JSON ([mvp.md](../mvp.md)) and the vote model is append-only / supersede-don't-overwrite ([ADR 0009](0009-append-only-vote-model.md)). Both want *explicit, predictable* persistence; an ORM's identity map, lazy loads, and implicit flushes are exactly the wrong behavior near records whose bytes were just signed. Explicit SQLAlchemy keeps the two layers (persistence vs. validation/serialization) distinct on purpose — the reason SQLModel (which fuses them) was rejected.

DB calls run **synchronously in a threadpool** rather than via the async ORM stack: the SSE connections wait on an in-process event/queue, not a held DB connection, so end-to-end async DB is not needed to scale the waiting room, and this avoids async-SQLAlchemy's sharp edges.

### Cryptography: `cryptography` + `bcrypt`

[ADR 0003](0003-cryptographic-primitive-selection.md) fixed the primitives; this is the library to implement them. The single most security-load-bearing dependency in the project.

- **`cryptography` over PyNaCl** — `cryptography` (OpenSSL-backed, the most-audited Python crypto library, constant-time) covers four of the five primitives in one dependency: Ed25519, AES-256-GCM, PBKDF2-HMAC-SHA-256, SHA-256. PyNaCl does Ed25519 well but offers Argon2/scrypt instead of PBKDF2 and does not cleanly cover AES-256-GCM, forcing a two-crypto-library mix to satisfy primitives [ADR 0003](0003-cryptographic-primitive-selection.md) already rejected the alternatives for.
- **`bcrypt` (standalone) over passlib** — passlib is effectively in maintenance limbo with known friction against modern bcrypt releases. The standalone `bcrypt` package (same maintainers as `cryptography`) is used directly; there is exactly one password scheme, so passlib's multi-scheme abstraction buys nothing and would hide the 72-byte truncation behavior ([ADR 0003](0003-cryptographic-primitive-selection.md)) that must stay explicit.

Neither is in the Python standard library: the stdlib has no asymmetric crypto and no AES at all, so `cryptography` is mandatory for Ed25519 and AES-256-GCM regardless.

### Sessions: server-side opaque token, not JWT

[mvp.md](../mvp.md) is explicit: "server-side session record **(not a stateless signed cookie)**." The cookie carries only an opaque, high-entropy session id (stdlib `secrets`), validated against a server-side record; the id is HMAC-signed with the app secret (stdlib `hmac`) for tamper-evidence. No signing framework is needed for a token that is looked up server-side anyway.

- **Over JWT** — JWTs are valid until expiry and cannot be revoked without a server-side denylist, which reintroduces the very state JWT exists to avoid. The spec *requires* instant revocation: deactivating a user must revoke their Proxy Sessions immediately ([mvp.md](../mvp.md)). JWT also carries a well-documented footgun history (`alg=none`, RS256/HS256 confusion) that a security project should be seen avoiding.

### Validation & config: Pydantic + pydantic-settings

Pydantic rides in as a FastAPI dependency regardless; the decision is to author models with it **at the I/O boundary only**. Highest value is **config**: parsing the per-service YAML + `$ENV{VAR}` config ([config.md](../config.md)) into typed models means malformed config (missing `quorum`, bad service `type`, quorum exceeding the approver count) fails loudly **at startup**, not at request time. `pydantic-settings` handles the env/settings side. Pydantic also enforces constraints on untrusted request input (TOTP shape, email format, username charset) — boundary validation is itself a defense.

Pydantic is deliberately **kept out of two places**: it is not the persistence/domain model (SQLAlchemy owns that), and it is **never used for the canonical-JSON serialization of signed records** — `model_dump_json()` makes no canonical-form guarantee (key order, whitespace, number formatting), so signing over it would be a latent verification bug. The signed-record path uses an explicit canonical serializer.

### Outbound I/O: httpx, aiosmtplib, aiosmtpd

- **`httpx` over `requests`** — httpx supports async (matching the ASGI stack), and has first-class test mocking (`MockTransport` / `respx`), which is required because PyPI is the *one* boundary the test suite mocks ([mvp.md](../mvp.md)). `requests` has no async story and weaker test ergonomics.
- **`aiosmtplib`** sends mail asynchronously, fitting the event-driven Notifier/Executor seam ([architecture.md](../architecture.md)) without tying up the threadpool. **`aiosmtpd`** provides the *real in-process SMTP server* the spec mandates for tests ([mvp.md](../mvp.md)) — the one boundary deliberately *not* mocked.

### Tooling: uv, ruff, ty (Astral ecosystem)

The Astral toolchain is chosen across the board for speed and a cohesive single-vendor developer loop: **uv** (dependency management, over pip+venv/Poetry/PDM), **ruff** (lint + format in one fast binary, replacing black + flake8 + isort + bandit — and its `S`/flake8-bandit rules add security linting directly relevant to this project), and **ty** (type checking, over mypy/Pyright). `ty` is pre-1.0; this is an accepted trade-off (see below).

## Implications

- The proxy runs as one or more ASGI processes under Uvicorn; the architecture's "one process or several" deferral ([architecture.md](../architecture.md)) remains open and is unaffected by this choice.
- `python-multipart` is a required runtime dependency (FastAPI form and file-upload parsing — needed for `POST /pypi/legacy/` and htmx form posts).
- The full, version-pinned dependency list lives in `pyproject.toml`, split into runtime and dev groups; test and quality tooling (pytest, pytest-asyncio, respx, aiosmtpd, pytest-cov, ruff, ty) are dev dependencies.
- The canonical-JSON signing constraint ([cryptography.md](../cryptography.md), [mvp.md](../mvp.md)) is now a cross-cutting implementation invariant binding two layers: neither SQLAlchemy nor Pydantic serialization may be used to produce the bytes that are Ed25519-signed.

## Trade-offs Accepted

- **FastAPI is API/JSON-first**, and a large part of the human surface is server-rendered HTML. FastAPI renders HTML fine via Jinja2 but it is not the framework's sweet spot; accepted because the async-SSE and dependency-injection benefits outweigh it.
- **SQLite is single-writer** and not a production datastore at scale; accepted for the MVP given low throughput, with PostgreSQL as the documented future swap behind the SQLAlchemy seam.
- **Sync DB in a threadpool** inside an async app is a hybrid posture; accepted to avoid async-ORM sharp edges, justified because no request path holds a long-lived DB connection.
- **`ty` is pre-1.0.** Type-checker behavior may change under us; accepted in exchange for ecosystem cohesion with uv and ruff, and revisitable if it proves unstable.
- **Two model layers** (SQLAlchemy for persistence, Pydantic for boundaries) require mapping between them rather than a single fused model; accepted deliberately to keep persistence and the signing path explicit (the reason SQLModel was rejected).
