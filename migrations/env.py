"""Alembic migration environment.

The migration URL is taken from the same :class:`~msig_proxy.config.Settings`
the application uses (``MSIG_DATABASE_URL``), so migrations and the running app
always target the same database. ``target_metadata`` is the project's
declarative metadata, ready for autogenerate once domain tables exist.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context

from msig_proxy.config import Settings
from msig_proxy.db import Base, create_db_engine

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _database_url() -> str:
    return Settings().database_url


def run_migrations_offline() -> None:
    """Emit SQL without a live DB connection."""
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live connection."""
    connectable = create_db_engine(_database_url())
    try:
        with connectable.connect() as connection:
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
                render_as_batch=True,  # SQLite needs batch mode for ALTER in later phases
            )
            with context.begin_transaction():
                context.run_migrations()
    finally:
        connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
