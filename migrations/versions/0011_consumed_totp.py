"""record consumed TOTP time-steps for single-use enforcement

Revision ID: 0011
Revises: 0010
Create Date: 2026-06-21

Phase 2 #73: TOTP codes become single-use. RFC 6238 §5.2 requires the verifier to
reject a second use of an accepted OTP; without this a captured ``password + TOTP``
pair is replayable for the lifetime of the code (``docs/approver-authentication.md``
§TOTP Single-Use Enforcement, ``docs/threat-model.md`` T8). The new
``consumed_totps`` table is the burn ledger: each accepted code records the
``(user, 30s time-step)`` it matched, and any later submission for that same pair
is refused. Mirrors :class:`msig_proxy.core.models.ConsumedTotp`.

The **unique** index on ``(user_id, time_step)`` makes the check-and-record atomic
at the storage layer (the same single-use idiom as the enrollment-token gate): two
concurrent redemptions of one code race to insert the same row, exactly one wins.

No data backfill — same convention as 0008/0010: there is no production data in the
MVP, and the ledger starts empty.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "consumed_totps",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("time_step", sa.Integer(), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_consumed_totps_user_id", "consumed_totps", ["user_id"])
    # One redemption per (user, time-step) — the atomic single-use gate (RFC 6238
    # §5.2): a second insert for the same pair fails, so a code cannot burn twice.
    op.create_index(
        "uq_consumed_totps_user_step",
        "consumed_totps",
        ["user_id", "time_step"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("uq_consumed_totps_user_step", table_name="consumed_totps")
    op.drop_index("ix_consumed_totps_user_id", table_name="consumed_totps")
    op.drop_table("consumed_totps")
