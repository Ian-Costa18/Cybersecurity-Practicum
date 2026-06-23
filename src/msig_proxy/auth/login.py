"""Interactive browser login → a server-side, revocable Proxy Session (issue #9).

`GET /login` renders the credential form (username, password, TOTP). `POST /login`
verifies both factors — password (bcrypt) and TOTP (#16) — creates a Proxy Session
row, and sets the signed ``session_id`` cookie (HttpOnly + Secure + SameSite=Strict). `POST /logout`
deletes the session row, revoking it immediately. `GET /me` is a small
session-gated probe that returns the authenticated User — the first surface to
consume :func:`msig_proxy.auth.guards.require_session_user`; the real authenticated
surfaces (waiting room, ``/auth``, the portals) reuse the same dependency in
later slices.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy.auth import credentials, sessions
from msig_proxy.auth.guards import require_session_user
from msig_proxy.core.config import AppConfig
from msig_proxy.core.models import FORWARD_AUTH, User
from msig_proxy.deps import get_config, get_session

router = APIRouter()

_jinja = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _set_session_cookie(response: Response, cookie_value: str, max_age: int) -> None:
    """Attach the Proxy Session cookie with the hardened attributes."""
    response.set_cookie(
        sessions.SESSION_COOKIE,
        cookie_value,
        max_age=max_age,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )


@router.get("/login", response_class=HTMLResponse)
def login_page(
    request: Request,
    service: str | None = None,
    return_to: str | None = None,
) -> HTMLResponse:
    """Render the login form. ``service`` / ``return_to`` are carried through for
    the forward-auth redirect added in #10."""
    return _jinja.TemplateResponse(
        request=request,
        name="login.html",
        context={"service": service, "return_to": return_to, "error": None},
    )


@router.post("/login")
def login(
    request: Request,
    session: Session = Depends(get_session),
    config: AppConfig = Depends(get_config),
    username: str = Form(...),
    password: str = Form(...),
    totp: str = Form(default=""),
    return_to: str | None = Form(default=None),
    service: str | None = Form(default=None),
) -> Response:
    """Verify password **and** TOTP, issue a Proxy Session, or re-render with a 401.

    Authenticate-and-redirect only (the login de-smudge, ADR 0012): two factors, no
    fallback (#16) — a correct password with a missing or wrong TOTP code is
    rejected. On success it sets the session cookie and hands off: when ``service``
    names a configured forward-auth Service, it redirects to the guarded
    ``GET /access`` (which creates/resumes the request and enters the waiting room),
    so login itself imports nothing from ``service_types``.
    """
    user = session.scalars(select(User).where(User.username == username)).one_or_none()
    # A not-yet-enrolled account (null credentials), a bad password, or a bad/missing
    # TOTP all fail here — indistinguishable, so none leaks whether the account exists.
    # The leading ``user is None`` also narrows the type for the success path below.
    if user is None or not credentials.verify_credentials(
        session, user, password, totp, totp_valid_window=config.auth.totp_window
    ):
        return _jinja.TemplateResponse(
            request=request,
            name="login.html",
            context={"service": service, "return_to": return_to, "error": "Invalid credentials"},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    _, cookie_value = sessions.create_session(
        session,
        user,
        lifetime_hours=config.auth.session_expiry_hours,
        secret_key=config.server.secret_key,
    )
    max_age = config.auth.session_expiry_hours * 3600

    svc = config.services.get(service) if service else None
    if service is not None and svc is not None and svc.type == FORWARD_AUTH:
        # Hand off to the guarded forward-auth access trigger — request creation and
        # the request.created emit live there now, not here (auth/ imports no slice).
        # Carry ``return_to`` (the original backend URL) so the waiting room can send
        # the browser back on quorum (#77, docs/web-proxy.md §Forward-Auth Flow).
        access_params = {"service": service}
        if return_to:
            access_params["return_to"] = return_to
        response: Response = RedirectResponse(
            f"/access?{urlencode(access_params)}", status_code=status.HTTP_303_SEE_OTHER
        )
    elif return_to:
        response = RedirectResponse(return_to, status_code=status.HTTP_303_SEE_OTHER)
    else:
        response = HTMLResponse(f"Signed in as {user.username}.")
    _set_session_cookie(response, cookie_value, max_age)
    return response


@router.post("/logout", response_class=HTMLResponse)
def logout(
    request: Request,
    session: Session = Depends(get_session),
    config: AppConfig = Depends(get_config),
) -> HTMLResponse:
    """Delete the Proxy Session row (immediate revocation) and clear the cookie."""
    cookie = request.cookies.get(sessions.SESSION_COOKIE)
    if cookie:
        session_id = sessions.unsign_session_id(cookie, config.server.secret_key)
        if session_id is not None:
            sessions.delete_session(session, session_id)
    response = HTMLResponse("Signed out.")
    response.delete_cookie(sessions.SESSION_COOKIE, path="/")
    return response


@router.get("/me")
def me(user: User = Depends(require_session_user)) -> dict[str, str]:
    """Session-gated probe: the authenticated User, or ``401`` without a live session."""
    return {"username": user.username, "user_id": str(user.id)}
