"""Interactive browser login → a server-side, revocable Proxy Session (issue #9).

`GET /login` renders the password form (TOTP is Phase 2). `POST /login` verifies
the password (bcrypt), creates a Proxy Session row, and sets the signed
``session_id`` cookie (HttpOnly + Secure + SameSite=Strict). `POST /logout`
deletes the session row, revoking it immediately. `GET /me` is a small
session-gated probe that returns the authenticated User — the first surface to
consume :func:`msig_proxy.deps.require_session_user`; the real authenticated
surfaces (waiting room, ``/auth``, the portals) reuse the same dependency in
later slices.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from msig_proxy import crypto, sessions
from msig_proxy.config import AppConfig
from msig_proxy.deps import get_config, get_session, require_session_user
from msig_proxy.models import User

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
    return_to: str | None = Form(default=None),
) -> Response:
    """Verify the password and issue a Proxy Session, or re-render with a 401 error."""
    user = session.scalars(select(User).where(User.username == username)).one_or_none()
    if user is None or not crypto.verify_password(password, user.password_hash):
        return _jinja.TemplateResponse(
            request=request,
            name="login.html",
            context={"service": None, "return_to": return_to, "error": "Invalid credentials"},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    _, cookie_value = sessions.create_session(
        session,
        user,
        lifetime_hours=config.auth.session_expiry_hours,
        secret_key=config.server.secret_key,
    )
    max_age = config.auth.session_expiry_hours * 3600

    if return_to:
        response: Response = RedirectResponse(return_to, status_code=status.HTTP_303_SEE_OTHER)
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
