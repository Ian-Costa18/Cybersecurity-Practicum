# Deployment

How to build, configure, and run the proxy in a container — both the **standalone image** and the **compose dev/demo stacks**. The decision record behind this model is [ADR 0013](adr/0013-container-deployment-and-runtime-model.md); the configuration field reference is [config.md](config.md), and the user/credential model is [account-management.md](account-management.md).

> **Single worker is load-bearing.** The image runs **one Uvicorn process with one worker**. SQLite is single-writer and the lifecycle event bus is in-memory, so a second worker would corrupt the database and split the bus. Do **not** add `--workers N`. To scale beyond one node you must first move off SQLite (the documented Postgres seam) *and* off the in-memory bus. See [ADR 0013](adr/0013-container-deployment-and-runtime-model.md).

## Filesystem layout

The container uses three directories with distinct permissions:

| Path | Mode | Holds |
|---|---|---|
| `/app` | read-only | the application code + its virtualenv (`/app/.venv`) |
| `/config` | read-only (mounted) | `config.yaml` and the credential-bearing `users.yaml` — never baked into the image |
| `/data` | read-write (volume) | `msig_proxy.db` (SQLite). Artifacts are stored in-DB, so this is the **only** writable state |

This split supports a read-only root filesystem (add a `tmpfs` at `/tmp`). On the host, the repo's `config/` directory holds the working files; `config/*.example.yaml` are committed references and the real `config/config.yaml` / `config/users.yaml` are git-ignored.

## Configuration & secrets

- **Config files:** copy the examples and edit:
  - `config/config.example.yaml` → `config/config.yaml`
  - `config/users.example.yaml` → `config/users.yaml`
- **Secrets:** supplied as environment variables via a git-ignored `.env` (copy `.env.example`), referenced from `config.yaml` with `$ENV{VAR}` substitution. `.dockerignore` keeps `.env` out of the image. Keep `server.secret_key` **stable across restarts** (a changed key invalidates every session cookie).
- **Deploy settings** (`MSIG_*`): the image defaults to container paths — `MSIG_CONFIG_FILE=/config/config.yaml`, `MSIG_USERS_FILE=/config/users.yaml`, `MSIG_DATABASE_URL=sqlite+pysqlite:////data/msig_proxy.db`.

## First-admin bootstrap

The entrypoint runs **`alembic upgrade head`** then **`msig-provision`** before the app serves, so the database and the declared users exist on first boot. There are two ways a user is created from `config/users.yaml` ([account-management.md](account-management.md#declarative-config-driven-provisioning)):

- **Mode A (identity-only)** — the default; the user is emailed a one-time enrollment link and sets their own password + TOTP. Needs working SMTP (Mailpit in the demos).
- **Mode B (pre-credentialed)** — the user is born enrolled from an **offline** bundle, no email required. This is how you create the **first admin** (and CI identities, and no-Mailpit demos).

Generate a Mode-B admin bundle offline and paste it into `config/users.yaml`:

```sh
docker run --rm msig-proxy:dev hash-credentials \
    --username admin --email admin@example.com --admin
```

It prompts for a password once, prints the `otpauth://` URI to scan into an authenticator app, and emits a paste-ready `users:` entry. Provisioning is **create-if-absent and additive only** — an existing username is never modified, so leaving the entry in place is a safe no-op on every boot.

## Standalone image

```sh
# Build
docker build -t msig-proxy:dev .

# Run: mount the config dir read-only and a data volume; supply secrets via --env-file.
docker run --rm \
    -p 8080:8080 \
    --env-file .env \
    -v "$(pwd)/config:/config:ro" \
    -v msig-data:/data \
    msig-proxy:dev
```

Bring your own SMTP server, reverse proxy, and (for one-time publishing) an upstream upload target. `PUID`/`PGID` (default `1000`) set the uid/gid the process drops to and that `/data` is chowned to, so a host bind mount works without any host-side `chown`.

### Health

- `GET /health` — **liveness** (process up).
- `GET /health/db` — **readiness** (the persistence seam round-trips a query). The image's `HEALTHCHECK` polls this with a stdlib `urllib` one-liner (no `curl` in the image).

## Compose dev/demo stacks

A shared base (`proxy` + `mailpit`) is pulled into each demo via compose `include`. **Mailpit is never placed behind the forward-auth gate** — it is how you *read* the enrollment/approval links (inbox UI at <http://localhost:8025>, SMTP on `1025`). For the demos set, in `config/config.yaml`:

```yaml
notifications:
  email:
    smtp_host: mailpit
    smtp_port: 1025
    tls: false
```

### Publish stack

```sh
docker compose -f compose.publish.yaml up
```

Adds **pypiserver** (a local PyPI-compatible upload target — point `services.<svc>.endpoint` at `http://pypiserver:8080` so a publish never touches real PyPI; browse it at <http://localhost:8081>) and a **marimo** driver notebook at <http://localhost:2718>. The marimo notebook is a **stub** today (a TODO placeholder); driving the full publish flow end to end is deferred to a separate issue.

> For **production** one-time publishing, set the service `endpoint` to your real upstream — e.g. PyPI's legacy upload URL (the default) or a [`pyx`](https://docs.astral.sh/uv/) index. `pyx` is a production endpoint option, not a local compose service.

### Forward-auth stack

```sh
docker compose -f compose.forward-auth.yaml up
```

Adds **Traefik** with a `forwardauth` middleware that delegates to the proxy's `/auth` gate, and a **whoami** backend reachable at <http://whoami.localhost> (Traefik dashboard at <http://localhost:8090>). Declare a matching `type: forward-auth` service in `config/config.yaml` (`endpoint: http://whoami:80`). An approved Service Grant lets the request through to whoami with the `Remote-*` identity headers injected.

## Pre-`up` checklist

1. `cp .env.example .env` and fill in `PROXY_SECRET_KEY` (≥ 16 chars) and any SMTP/PyPI secrets.
2. `cp config/config.example.yaml config/config.yaml` and edit (Mailpit SMTP for demos; your services).
3. `cp config/users.example.yaml config/users.yaml`; generate a Mode-B admin with `hash-credentials` and paste it in; declare your approvers (Mode A).
4. `docker compose -f compose.publish.yaml up` (or `compose.forward-auth.yaml`).
5. Read enrollment/approval links in Mailpit at <http://localhost:8025>.
