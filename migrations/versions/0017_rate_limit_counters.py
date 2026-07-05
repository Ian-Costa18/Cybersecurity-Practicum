"""per-(scope, key) rate-limit counters for the auth-endpoint throttle

Revision ID: 0017
Revises: 0016
Create Date: 2026-07-04

Issue #123 / threat-model IDENT-5: the credential endpoints (``POST /login``,
``POST /approve/{id}``, ``POST /pypi/legacy/``) gain an in-proxy per-IP throttle,
and this table is its ledger — one fixed-window attempt counter per
``(scope, key)`` (:class:`msig_proxy.core.models.RateLimitCounter`,
:mod:`msig_proxy.core.rate_limit`). ``scope`` is ``"auth"`` today; the
request-creation caps (#32) will add their own scope over the same table.

The unique index on ``(scope, key)`` is the atomic creation gate — the same
storage-layer race resolution as ``consumed_totps`` (0011): two first attempts
insert-race and exactly one wins.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0017"
down_revision: str | None = "0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "rate_limit_counters",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scope", sa.String(), nullable=False),
        sa.Column("key", sa.String(), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.Column("blocked_until", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "uq_rate_limit_counters_scope_key",
        "rate_limit_counters",
        ["scope", "key"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("uq_rate_limit_counters_scope_key", table_name="rate_limit_counters")
    op.drop_table("rate_limit_counters")
