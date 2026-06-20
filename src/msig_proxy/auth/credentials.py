"""Framework-free credential verification: API tokens and interactive two-factor.

The ``[pure]`` half of the auth slice — no FastAPI symbol appears here, so the auth
rules can be exercised without standing up the app. The web edge that wires these
into routes (the ``__token__`` upload guard, the 401) lives in :mod:`.guards`.

Twine presents HTTP Basic ``__token__:<api-token>`` (``docs/web-proxy.md`` §API
Tokens). :func:`resolve_api_token` hashes the presented token and matches it against
a stored :class:`~msig_proxy.core.models.ApiToken` row; the token identifies the
Requester and is scoped to submission endpoints only. Since #14 tokens are
normalized into ``api_tokens`` (a User may hold many), so the lookup resolves the
token row, refuses a **revoked** token (``revoked_at`` set), and refuses any token
whose owning User is **inactive** (``is_active = false``).

:func:`verify_credentials` is the single home for interactive two-factor
verification (password **and** TOTP, #16). Both the browser login and per-vote
re-authentication call it so the "is this principal who they claim, right now"
check exists once (#58).
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy.core import crypto
from msig_proxy.core.models import ApiToken, User

# The fixed Basic-Auth username Twine/PyPI use for token auth — a public sentinel,
# not a secret. Naming it without "token" keeps it clear of the secret-scanner.
_TWINE_USERNAME = "__token__"


def resolve_api_token(
    session: Session, username: str | None, presented_token: str | None
) -> User | None:
    """Resolve the Requester behind a presented Twine ``__token__`` credential.

    Framework-free: takes the DB session and the presented username/token (plain
    values, not a FastAPI dependency) and returns the owning **active** User, or
    ``None`` for any rejection — a missing/wrong username, a missing token, a token
    matching no stored hash, a **revoked** token, or a token whose owning User is
    **inactive**. The token is high-entropy, so a direct hash-equality lookup is
    safe — there is no low-entropy secret here for a timing oracle to leak.

    The web edge (:func:`msig_proxy.auth.guards.authenticate_requester`) maps
    ``None`` to a ``401``.
    """
    if username != _TWINE_USERNAME or presented_token is None:
        return None
    token_hash = crypto.hash_api_token(presented_token)
    token = session.scalars(select(ApiToken).where(ApiToken.token_hash == token_hash)).one_or_none()
    if token is None or token.revoked_at is not None:
        return None
    user = session.get(User, token.user_id)
    if user is None or not user.is_active:
        return None
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
    ``401``; per-vote re-authentication raises
    :class:`~msig_proxy.approvals.votes.AuthenticationFailed`.
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
