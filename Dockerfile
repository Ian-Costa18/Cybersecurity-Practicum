# syntax=docker/dockerfile:1
#
# Multi-stage build for the Multi-Signature Authentication Web Proxy (#101, ADR 0013).
# Build stage uses the uv image to resolve + install into /app/.venv; the runtime
# stage is plain slim Python with the venv copied in — uv is absent from the runtime.
# Both stages are Debian bookworm-slim so the glibc wheels for cryptography/bcrypt
# match between build and run.

# --- build: uv resolves the locked deps + installs the project into /app/.venv -----
# NOTE: pin this base by digest before production use, e.g.
#   ghcr.io/astral-sh/uv:python3.14-bookworm-slim@sha256:<digest>
FROM ghcr.io/astral-sh/uv:python3.14-bookworm-slim AS build

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv

WORKDIR /app

# Layer 1: dependencies only, keyed on the lock + manifest, so a source-only change
# does not re-resolve the whole dependency graph.
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-install-project

# Layer 2: the application itself (source, migrations, alembic config), then install
# the project into the same venv.
COPY src ./src
COPY migrations ./migrations
COPY alembic.ini ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

# --- runtime: slim Python, the venv + source copied in, no uv ----------------------
FROM python:3.14-slim-bookworm AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/app/.venv/bin:$PATH" \
    MSIG_CONFIG_FILE=/config/config.yaml \
    MSIG_USERS_FILE=/config/users.yaml \
    MSIG_DATABASE_URL=sqlite+pysqlite:////data/msig_proxy.db \
    PUID=1000 \
    PGID=1000

# gosu performs the root -> unprivileged privilege drop in the entrypoint; no curl is
# installed (the healthcheck uses stdlib urllib). Clean the apt lists in the same layer.
RUN apt-get update \
    && apt-get install -y --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 1000 app \
    && useradd -u 1000 -g 1000 -M -s /usr/sbin/nologin app

WORKDIR /app
COPY --from=build /app /app
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh && mkdir -p /data /config

# /data is the only writable state (SQLite lives here; artifacts are in-DB). /config
# is mounted read-only by the operator; /app holds read-only code. With a read-only
# root filesystem, mount a tmpfs at /tmp.
VOLUME ["/data"]
EXPOSE 8080

# Readiness probe (not liveness): proves the persistence seam round-trips. stdlib only.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health/db', timeout=3).status == 200 else 1)"

# The entrypoint drops privileges, runs migrations + provisioning, then execs the CMD.
# A single Uvicorn worker is load-bearing (SQLite single-writer + in-memory EventBus);
# see ADR 0013. --factory matches create_app's factory signature; no --reload.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["uvicorn", "msig_proxy.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
