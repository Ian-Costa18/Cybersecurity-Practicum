"""Shared proxy-URL builders owned by no slice (see docs/source-layout.md).

The proxy mints absolute links (the Approval Link, the enrollment link) from the
configured ``server.base_url`` plus a path segment. Both the account/admin code and
the notifications code build these, so the construction lives in ``core`` (below both
in the dependency order) and the named builders are imported, never re-implemented.
"""

from __future__ import annotations

import uuid


def _join(base_url: str, path: str) -> str:
    """Join the configured base URL with a path segment, normalizing the slash."""
    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def approval_link(base_url: str, request_id: uuid.UUID) -> str:
    """The Approval Link for a request — ``{base_url}/approve/{request_id}`` (ADR 0005)."""
    return _join(base_url, f"approve/{request_id}")


def enrollment_link(base_url: str, token: str) -> str:
    """The single-use enrollment link for a token — ``{base_url}/enroll/{token}``."""
    return _join(base_url, f"enroll/{token}")
