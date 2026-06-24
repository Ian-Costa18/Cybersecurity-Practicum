#!/bin/sh
# Container entrypoint (#101, ADR 0013).
#
# Boot order, all before the app accepts a request:
#   1. (as root) align the bundled 'app' user/group to PUID/PGID, own /data, drop privs
#   2. (as the dropped user) alembic upgrade head   — idempotent; creates the DB first boot
#   3. (as the dropped user) msig-provision         — declarative create-if-absent users (#100)
#   4. exec the CMD (uvicorn)                        — single worker (see ADR 0013)
#
# The root -> unprivileged drop happens here (not via a baked USER) so the writable
# /data bind mount can be chowned to the operator's PUID/PGID at start, which is what
# lets a host bind mount work without any host-side chown.
set -eu

PUID="${PUID:-1000}"
PGID="${PGID:-1000}"

if [ "$(id -u)" = "0" ]; then
    # Align the bundled app user/group to the requested ids, then own the state dir.
    groupmod -o -g "$PGID" app
    usermod -o -u "$PUID" -g "$PGID" app
    mkdir -p /data
    chown -R "$PUID:$PGID" /data
    # Re-exec this script as the unprivileged user; the branch below then runs.
    exec gosu "$PUID:$PGID" "$0" "$@"
fi

echo "[entrypoint] applying database migrations (alembic upgrade head)"
alembic upgrade head

echo "[entrypoint] provisioning declared users (msig-provision)"
msig-provision

echo "[entrypoint] starting application: $*"
exec "$@"
