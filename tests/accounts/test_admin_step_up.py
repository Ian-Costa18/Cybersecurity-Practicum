"""Step-up re-authentication on sensitive Admin Portal actions (issue #135, VOTE-1).

Black-box HTTP integration tests (real DB, real crypto, real HTTP): the top tier of
the pyramid, driving the actual ``/admin/*`` surface with real Proxy Session cookies.

The adversarial oracle for the VOTE-1 → IDENT-1 severity reduction: a sensitive admin
action carried by a **valid admin session alone** is rejected — a hijacked session
(VOTE-1) cannot silently mutate the roster. The same action with a fresh password +
fresh single-use TOTP succeeds. Step-up reuses the very ``verify_credentials`` path the
per-vote re-authentication uses (#16, #58, #73), so a stolen session — which never
unlocks the second factor — is capped at its non-admin outcome.
"""

from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select

from msig_proxy.accounts.seed import seed_user
from msig_proxy.auth.sessions import SESSION_COOKIE
from msig_proxy.core.db import session_scope
from msig_proxy.core.models import User
from tests.support import current_totp, current_totp_at

_ADMIN_PW = "admin-pw-12345"
_ALICE_PW = "alice-pw-12345"


@pytest.fixture
def seeded(app: FastAPI) -> None:
    for session in session_scope(app.state.session_factory):
        seed_user(
            session, username="root", email="root@example.com", password=_ADMIN_PW, is_admin=True
        )
        seed_user(session, username="alice", email="alice@example.com", password=_ALICE_PW)


async def _admin_session(client: httpx.AsyncClient, app: FastAPI) -> dict[str, str]:
    """Log the admin in and return the Proxy Session cookie header (burns TOTP step 0)."""
    login = await client.post(
        "/login",
        data={
            "username": "root",
            "password": _ADMIN_PW,
            "totp": current_totp(app.state.session_factory, "root", _ADMIN_PW),
        },
        follow_redirects=False,
    )
    return {"Cookie": f"{SESSION_COOKIE}={login.cookies[SESSION_COOKIE]}"}


def _step_up(app: FastAPI) -> dict[str, str]:
    """A fresh step-up credential for ``root`` — a distinct (offset +1) single-use TOTP so
    it does not replay the code the login burned in the same 30s window (#73)."""
    return {
        "password": _ADMIN_PW,
        "totp": current_totp_at(app.state.session_factory, "root", 1, _ADMIN_PW),
    }


def _user_id(app: FastAPI, username: str) -> str:
    for session in session_scope(app.state.session_factory):
        return str(session.scalars(select(User.id).where(User.username == username)).one())
    raise AssertionError  # pragma: no cover


def _is_active(app: FastAPI, username: str) -> bool:
    for session in session_scope(app.state.session_factory):
        return bool(session.scalars(select(User.is_active).where(User.username == username)).one())
    raise AssertionError  # pragma: no cover


async def test_sensitive_admin_action_requires_fresh_step_up_reauth(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    """A valid admin session alone cannot drive a sensitive action; fresh step-up can.

    The VOTE-1 severity-reduction oracle. Deactivation stands in for the roster
    mutations gated by #135: a session-only attempt (a stolen cookie, VOTE-1) is
    rejected 401 and leaves the account untouched, while the same call carrying a
    fresh password + fresh single-use TOTP succeeds.
    """
    admin_auth = await _admin_session(client, app)
    alice = _user_id(app, "alice")

    # Session alone — no step-up credential in the body — is refused (a hijacked
    # admin session, VOTE-1). The account is not mutated.
    session_only = await client.post(f"/admin/users/{alice}/deactivate", headers=admin_auth)
    assert session_only.status_code == 401
    assert _is_active(app, "alice") is True

    # The same action re-proving possession of the second factor succeeds.
    stepped_up = await client.post(
        f"/admin/users/{alice}/deactivate", headers=admin_auth, data=_step_up(app)
    )
    assert stepped_up.status_code == 200
    assert _is_active(app, "alice") is False


async def test_step_up_rejects_wrong_password_and_a_replayed_totp(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    """A wrong password and a replayed (already-burned) TOTP are the same 401.

    Two failure modes, one indistinguishable rejection: a valid session with the
    wrong password, and a valid session presenting the very TOTP code the login just
    consumed (single-use, #73). Neither mutates the account.
    """
    admin_auth = await _admin_session(client, app)
    alice = _user_id(app, "alice")

    wrong_pw = await client.post(
        f"/admin/users/{alice}/deactivate",
        headers=admin_auth,
        data={
            "password": "not-the-admin-pw",
            "totp": current_totp_at(app.state.session_factory, "root", 1, _ADMIN_PW),
        },
    )
    assert wrong_pw.status_code == 401
    assert _is_active(app, "alice") is True

    # Replay the step-0 code the login already burned — the single-use gate refuses it.
    replayed = await client.post(
        f"/admin/users/{alice}/deactivate",
        headers=admin_auth,
        data={
            "password": _ADMIN_PW,
            "totp": current_totp(app.state.session_factory, "root", _ADMIN_PW),
        },
    )
    assert replayed.status_code == 401
    assert _is_active(app, "alice") is True


@pytest.mark.parametrize(
    ("method", "suffix", "extra"),
    [
        ("POST", "", {"username": "neo", "email": "neo@example.com"}),  # create / enroll
        ("PATCH", "", {"groups": "x"}),  # edit contact-or-groups
        ("POST", "/deactivate", {}),
        ("DELETE", "", {}),
        ("POST", "/reset", {}),
        ("POST", "/enrollment-link", {}),  # re-enroll-forward
    ],
)
async def test_every_sensitive_action_is_step_up_gated(
    client: httpx.AsyncClient,
    app: FastAPI,
    seeded: None,
    method: str,
    suffix: str,
    extra: dict[str, str],
) -> None:
    """Each enrollment / credential / roster mutation refuses a bad step-up (401).

    The full gated set from #135. ``POST /admin/users`` (create) targets the
    collection; the rest target ``alice``. A valid admin session carrying a wrong
    password is rejected on every one — proving none of the six is reachable on the
    session alone.
    """
    admin_auth = await _admin_session(client, app)
    alice = _user_id(app, "alice")
    base = (
        "/admin/users"
        if method == "POST" and suffix == "" and "username" in extra
        else (f"/admin/users/{alice}")
    )
    body = {"password": "not-the-admin-pw", "totp": "000000", **extra}
    resp = await client.request(method, f"{base}{suffix}", headers=admin_auth, data=body)
    assert resp.status_code == 401


async def test_activate_and_token_revoke_stay_session_only(
    client: httpx.AsyncClient, app: FastAPI, seeded: None
) -> None:
    """Scope boundary: activate and token-revoke are deliberately NOT step-up gated (#135).

    #135 gates the enrollment / credential / roster mutations only. Activation is the
    IDENT-2 confirmation gate whose enroll-forward prerequisites (create / reset /
    regenerate-link) are themselves gated, so the takeover chain is already broken at
    its first link; token revoke is a defensive action. Both must therefore still run
    on the admin session alone — no step-up body — and specifically must not return the
    step-up 401.
    """
    admin_auth = await _admin_session(client, app)
    alice = _user_id(app, "alice")

    # Re-activate an already-active account: reaches the handler on the session alone.
    activated = await client.post(f"/admin/users/{alice}/activate", headers=admin_auth)
    assert activated.status_code == 200

    # Token revoke on a non-existent token reaches its own 404 (past require_admin),
    # never the step-up 401 — proving it, too, is not step-up gated.
    fake = _user_id(app, "root")
    revoke = await client.delete(f"/admin/users/{alice}/tokens/{fake}", headers=admin_auth)
    assert revoke.status_code == 404
