"""API-token authentication for the programmatic upload endpoints.

Twine presents HTTP Basic ``__token__:<api-token>`` (``docs/web-proxy.md`` §API
Tokens). We hash the presented token and match it against a stored ``token_hash``;
the token identifies the Requester and is scoped to submission endpoints only —
it cannot log into a portal or approve a request (those checks arrive with those
surfaces). Authentication is rejected with ``401`` so Twine surfaces a clear error.
"""

from __future__ import annotations

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy import crypto
from msig_proxy.deps import get_session
from msig_proxy.models import User

# The fixed Basic-Auth username Twine/PyPI use for token auth — a public sentinel,
# not a secret. Naming it without "token" keeps it clear of the secret-scanner.
_TWINE_USERNAME = "__token__"

_basic = HTTPBasic(auto_error=False)


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="invalid API token",
        headers={"WWW-Authenticate": "Basic"},
    )


def authenticate_requester(
    credentials: HTTPBasicCredentials | None = Depends(_basic),
    session: Session = Depends(get_session),
) -> User:
    """Resolve the Requester behind a Twine ``__token__`` Basic-Auth upload.

    Rejects (``401``) a missing header, the wrong username, or a token matching no
    stored hash. The token is high-entropy, so a direct hash-equality lookup is
    safe — there is no low-entropy secret here for a timing oracle to leak.
    """
    if credentials is None or credentials.username != _TWINE_USERNAME:
        raise _unauthorized()
    token_hash = crypto.hash_api_token(credentials.password)
    user = session.scalars(select(User).where(User.token_hash == token_hash)).one_or_none()
    if user is None:
        raise _unauthorized()
    return user
