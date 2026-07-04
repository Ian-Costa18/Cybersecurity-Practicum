"""tamper-evident DB records: audit hash chain + frozen approver keys (#121)

Revision ID: 0015
Revises: 0014
Create Date: 2026-07-04

HOST-2 hardening (#121), two trust roots:

* **Audit hash chain** — ``audit_log`` gains ``prev_hash`` + ``entry_hash`` (the
  HMAC-SHA-256 chain link, keyed by an HKDF-derived audit key off
  ``server.secret_key``) plus ``actor_id`` (the acting admin on an admin-action row).
  The chain makes whole-row deletion/reorder detectable, not just per-record
  modification (``docs/cryptography.md`` §Audit Trail Integrity).
* **Frozen approver keys** — ``approval_request_approvers`` gains ``key_id`` +
  ``public_key``, freezing each eligible approver's active signing key at creation so
  the execution-time re-check verifies Votes against the anchored key, detecting a
  live-key substitution (ADR 0008, ``docs/threat-model/HOST-2-database-write-compromise.md``).

All new columns are nullable — the writer always populates them, so no backfill is
needed (same convention as the other Phase 2 migrations; the trail starts empty and
in-flight requests drain under the old, unfrozen rule).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("audit_log", sa.Column("actor_id", sa.Uuid(), nullable=True))
    op.add_column("audit_log", sa.Column("prev_hash", sa.LargeBinary(), nullable=True))
    op.add_column("audit_log", sa.Column("entry_hash", sa.LargeBinary(), nullable=True))
    op.add_column("approval_request_approvers", sa.Column("key_id", sa.Uuid(), nullable=True))
    op.add_column(
        "approval_request_approvers", sa.Column("public_key", sa.LargeBinary(), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("approval_request_approvers", "public_key")
    op.drop_column("approval_request_approvers", "key_id")
    op.drop_column("audit_log", "entry_hash")
    op.drop_column("audit_log", "prev_hash")
    op.drop_column("audit_log", "actor_id")
