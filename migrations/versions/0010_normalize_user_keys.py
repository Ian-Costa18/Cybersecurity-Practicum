"""normalize signing key pairs out of users into user_keys

Revision ID: 0010
Revises: 0009
Create Date: 2026-06-19

Phase 2 #53: the Ed25519 signing key pair leaves the ``users`` row for its own
``user_keys`` table so a User accumulates an active key plus the retired keys of
past resets/rotations, and a :class:`msig_proxy.core.models.Vote` stays verifiable
against the exact key that signed it (audit-safe key rotation prerequisite for
#34/#25). Mirrors :class:`msig_proxy.core.models.UserKey`.

The *active* key is derived (``revoked_at IS NULL``, a partial unique index makes
it at most one per user), so there is no ``users.current_key_id`` pointer. A CHECK
constraint pins the retired ⇔ public-only biconditional. ``Vote.key_id`` becomes
the ``UserKey`` id (a Uuid) instead of the old ``{user_id}:{version}`` string.

No data backfill — same convention as 0008's ``token_hash`` normalization: there
is no production data in the MVP, so any seeded/enrolled key is simply re-created
(re-run ``python -m msig_proxy.seed``, or re-enroll). The four ``users`` key
columns and the old string ``key_id`` values are dropped without migrating rows.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "user_keys",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("public_key", sa.LargeBinary(), nullable=False),
        sa.Column("encrypted_private_key", sa.LargeBinary(), nullable=True),
        sa.Column("key_salt", sa.LargeBinary(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        # Retired ⇔ public-only: a live key (null revoked_at) keeps its private half,
        # a retired key keeps neither — enforced at the storage layer (see UserKey).
        sa.CheckConstraint(
            "(revoked_at IS NULL AND encrypted_private_key IS NOT NULL AND key_salt IS NOT NULL)"
            " OR (revoked_at IS NOT NULL AND encrypted_private_key IS NULL AND key_salt IS NULL)",
            name="ck_user_keys_private_half_iff_active",
        ),
    )
    op.create_index("ix_user_keys_user_id", "user_keys", ["user_id"])
    # At most one active key per user — lets the active key be derived from
    # revoked_at rather than tracked by a users.current_key_id pointer.
    op.create_index(
        "uq_user_keys_active_per_user",
        "user_keys",
        ["user_id"],
        unique=True,
        sqlite_where=sa.text("revoked_at IS NULL"),
        postgresql_where=sa.text("revoked_at IS NULL"),
    )

    # SQLite can't ALTER/DROP COLUMN in place — batch rebuilds the table (see 0009).
    with op.batch_alter_table("users") as batch:
        batch.drop_column("key_version")
        batch.drop_column("key_salt")
        batch.drop_column("encrypted_private_key")
        batch.drop_column("public_key")

    # key_id now references UserKey.id (a Uuid), not the old "{user_id}:{version}" string.
    with op.batch_alter_table("votes") as batch:
        batch.alter_column(
            "key_id", existing_type=sa.String(), type_=sa.Uuid(), existing_nullable=False
        )


def downgrade() -> None:
    with op.batch_alter_table("votes") as batch:
        batch.alter_column(
            "key_id", existing_type=sa.Uuid(), type_=sa.String(), existing_nullable=False
        )

    # Restore the collapsed key columns in their pre-0010 (post-0009) shape: the
    # three blobs nullable, key_version a non-null integer (server_default for any
    # existing rows, matching how 0008 re-added dropped non-null columns).
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("public_key", sa.LargeBinary(), nullable=True))
        batch.add_column(sa.Column("encrypted_private_key", sa.LargeBinary(), nullable=True))
        batch.add_column(sa.Column("key_salt", sa.LargeBinary(), nullable=True))
        batch.add_column(sa.Column("key_version", sa.Integer(), nullable=False, server_default="1"))

    op.drop_index("uq_user_keys_active_per_user", table_name="user_keys")
    op.drop_index("ix_user_keys_user_id", table_name="user_keys")
    op.drop_table("user_keys")
