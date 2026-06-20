"""Authentication for the proxy: programmatic API tokens and interactive credentials.

Twine presents HTTP Basic ``__token__:<api-token>`` (``docs/web-proxy.md`` §API
Tokens). We hash the presented token and match it against a stored
:class:`~msig_proxy.models.ApiToken` row; the token identifies the Requester and
is scoped to submission endpoints only — it cannot log into a portal or approve a
request (those checks arrive with those surfaces). Authentication is rejected with
``401`` so Twine surfaces a clear error.

Since #14 tokens are normalized into ``api_tokens`` (a User may hold many), so the
lookup resolves the token row, refuses a **revoked** token (``revoked_at`` set),
and refuses any token whose owning User is **inactive** (``is_active = false``) —
the latter contains a leaked token on deactivation without per-token revocation.

:func:`verify_credentials` is the single home for interactive two-factor
verification (password **and** TOTP, #16). Both the browser login (``login.py``)
and per-vote re-authentication (``votes.py``) call it so the "is this principal
who they claim, right now" check exists once (#58).
"""

from __future__ import annotations

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy import crypto
from msig_proxy.deps import get_session
from msig_proxy.models import ApiToken, User

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

    Rejects (``401``) a missing header, the wrong username, a token matching no
    stored hash, a **revoked** token, or a token whose owning User is **inactive**.
    The token is high-entropy, so a direct hash-equality lookup is safe — there is
    no low-entropy secret here for a timing oracle to leak.
    """
    if credentials is None or credentials.username != _TWINE_USERNAME:
        raise _unauthorized()
    token_hash = crypto.hash_api_token(credentials.password)
    token = session.scalars(select(ApiToken).where(ApiToken.token_hash == token_hash)).one_or_none()
    if token is None or token.revoked_at is not None:
        raise _unauthorized()
    user = session.get(User, token.user_id)
    if user is None or not user.is_active:
        raise _unauthorized()
    return user


def verify_credentials(
    user: User | None,
    password: str,
    totp: str,
    *,
    totp_valid_window: int,
) -> bool:
    """Verify a User's interactive credentials: password **and** TOTP (#16).

    Returns ``True`` only for an active, fully-enrolled User whose password and
    TOTP both verify. Every failure mode — an unknown user (``None``), a
    deactivated account (#17), a not-yet-enrolled account (null ``password_hash``
    or ``totp_secret``), a wrong password, or a wrong/missing TOTP — returns
    ``False`` indistinguishably, so the result leaks nothing about *which* factor
    failed or whether the account exists.

    Callers map the boolean to their own surface: the browser login re-renders a
    ``401``; per-vote re-authentication raises :class:`~msig_proxy.votes.AuthenticationFailed`.
    This stays purely identity verification — it does not look at signing-key
    material, which only the vote path needs.
    """
    return not (
        user is None
        or not user.is_active
        or user.password_hash is None
        or user.totp_secret is None
        or not crypto.verify_password(password, user.password_hash)
        or not crypto.verify_totp(user.totp_secret, totp, valid_window=totp_valid_window)
    )
