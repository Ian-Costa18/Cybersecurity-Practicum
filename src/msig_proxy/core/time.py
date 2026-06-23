"""Shared time primitives owned by no slice (see docs/source-layout.md).

A cross-slice helper used wherever a stored timestamp is compared against ``now``
for lazy expiry / validity. It sits in ``core`` (below every slice in the
dependency order), so auth, accounts, and the service-type slices may all import it
without violating the slice dependency rule.
"""

from __future__ import annotations

from datetime import UTC, datetime


def aware(value: datetime) -> datetime:
    """Treat a tz-naive timestamp (as SQLite returns) as UTC for comparison.

    A tz-aware value is returned unchanged; a tz-naive value is returned with UTC
    attached. This is the single home for the convention; every lazy-expiry site
    (sessions, enrollment, service grants) compares against ``datetime.now(UTC)``.
    """
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
