# Container Deployment and Runtime Model

## Status
Accepted

## Context

[ADR 0011](0011-technology-stack.md) selected the stack (FastAPI/Uvicorn, SQLite, the Astral toolchain) but left how the proxy is **packaged and run** open, and [architecture.md](../architecture.md) deliberately deferred "one process or several" to build time. Implementation has reached the point where the system must be runnable turnkey — for the practicum demo and for any real deployment — so this ADR records the container/runtime model. It is the output of a `/grill-with-docs` design session and is the companion decision record to the operational reference in [deployment.md](../deployment.md); the per-file detail (exact base tags, compose service lists) lives there and in the artifacts themselves, not here.

This decision depends on **[#100 declarative user provisioning](../account-management.md#declarative-config-driven-provisioning)**: a turnkey `docker compose up` needs the first admin to exist without a human clicking an enrollment link, which is exactly what config-driven provisioning (Mode B) gives, run from the entrypoint.

## Decision

**One standalone image** (bring-your-own DB volume, SMTP, reverse proxy) plus a **thin `docker compose` dev/demo layer** over that same image.

| Area | Decision |
|---|---|
| Build | Multi-stage. Build stage `ghcr.io/astral-sh/uv:python3.14-bookworm-slim` runs `uv sync --frozen --no-dev` into `/app/.venv`; runtime stage `python:3.14-slim-bookworm` copies the venv in. **uv is absent from the runtime image.** |
| Distro | Debian `bookworm-slim` on both stages, so the glibc wheels for `cryptography`/`bcrypt` match build↔runtime. |
| User / state | **PUID/PGID entrypoint** (default 1000): start as root, `chown /data`, then `gosu`-drop to the unprivileged user. SQLite lives at the absolute `/data/msig_proxy.db`; artifacts are in-DB, so `/data` is the **only** writable state. Bind-mount-friendly with no host-side chown. |
| Process model | **Single Uvicorn process, single worker**, `--factory`, no `--reload`. This resolves architecture.md's "one process or several" deferral: **one process, one worker.** |
| Migrations | `alembic upgrade head` in the entrypoint, as the dropped user, before `exec uvicorn`. Idempotent; creates the DB on first boot. |
| Bootstrap | `msig-provision` (#100) runs in the entrypoint immediately after migrations, before the app serves. |
| Config delivery | Mount the `config/` directory read-only at `/config` (`config.yaml` + the credential-bearing `users.yaml`); never baked into the image. Commit `config/*.example.yaml`. Filesystem split: `/app` read-only code, `/config` read-only, `/data` read-write — supports a read-only root filesystem with a `tmpfs /tmp`. |
| Secrets | Env vars via a gitignored `.env` (+ committed `.env.example`) and `$ENV{VAR}` in config. `secret_key` stable across restarts. `.dockerignore` excludes `.env`. |
| Health / port | `EXPOSE 8080`, bind `0.0.0.0:8080`. `HEALTHCHECK` hits `/health/db` (readiness) via a stdlib `urllib` one-liner — no `curl` in the image; `/health` remains liveness. |
| Compose stacks | A shared base (`proxy` + `mailpit`) pulled in via compose `include`. **Publish stack** adds a `marimo` driver (stub notebook + TODO; real behavior deferred) and `pypiserver` (local publish target). **Forward-auth stack** adds `traefik` (a `forwardauth` middleware → `/auth`) and a `whoami` backend. **Mailpit stays ungated.** |

## Rationale

- **Multi-stage with uv only at build time** keeps the runtime image small and free of the build toolchain while still getting uv's fast, locked, reproducible installs. Copying the venv across two images is safe because the uv `python3.14-bookworm-slim` image *is* the official `python:3.14` image with uv added, so the interpreter path the venv references matches the runtime.
- **PUID/PGID + gosu over a baked `USER`.** A baked non-root UID forces the host to pre-`chown` any bind-mounted `/data` to that exact UID. Starting as root only long enough to align the user to the operator's PUID/PGID and `chown /data`, then dropping with gosu, makes a host bind mount Just Work — the standard pattern for self-hosted images. The process still serves unprivileged.
- **Single worker is a correctness decision, not just a sizing one.** SQLite is single-writer ([ADR 0011](0011-technology-stack.md)) and the lifecycle `EventBus` is **in-process and in-memory** ([ADR 0005](0005-decoupled-notification-system.md)): a second worker would be a second process with its own bus and a second writer to one SQLite file. The system is explicitly low-throughput (< 100 logins/day), so one worker is ample. This is the load-bearing risk the ADR exists to make non-silent (see below).
- **Migrations + provisioning in the entrypoint, not the app factory.** The factory is deliberately side-effect-free and writes nothing ([source-layout.md](../source-layout.md)); migrations and provisioning are bootstrap concerns. Running them in the entrypoint means container and local `uvicorn` bootstrap identically — the single path — without coupling app construction to a DB write.
- **Config as a read-only mount, secrets as env.** Keeping `config/` (including the credential-bearing `users.yaml`) out of the image and read-only at `/config` keeps credentials out of layers and supports a read-only root filesystem. `$ENV{VAR}` substitution ([config.md](../config.md)) keeps the remaining secrets out of the file.
- **Compose `include` for a shared base** avoids duplicating the `proxy`+`mailpit` definition across the publish and forward-auth stacks; each overlay is just its extra services. Mailpit is never gated because it is the channel for *reading* enrollment/approval links — gating it behind the very auth flow it bootstraps would be circular.

## Consequences

- architecture.md's "one process or several" deferral is now **resolved: one process, one worker.** That document and [ADR 0011](0011-technology-stack.md)'s implication note are updated to point here.
- The standalone image is deployable on its own (mount a config dir + a `/data` volume, point at any SMTP and reverse proxy); the compose stacks are dev/demo conveniences over the identical image.
- `pyx` is documented as a *production* `endpoint` option in [deployment.md](../deployment.md), not a local compose service.

## Trade-offs Accepted

- **Single worker caps horizontal scale on one node.** Accepted given the low-throughput target; revisiting it means moving off SQLite (the documented Postgres seam) **and** off the in-memory bus (a shared broker) together — neither is free, and the ADR records why the cap exists so a future "just add `--workers 4`" is recognized as the SQLite-corruption / split-bus footgun it would be.
- **Copying a venv between images** couples the two base images' Python layout; mitigated by both deriving from the same official `python:3.14-bookworm-slim`.
- **The marimo publish driver ships as a stub.** The compose publish stack opens a placeholder notebook; the real end-to-end driver is deferred to a separate issue so containerization is not blocked on it.
