"""A minimal in-process event seam (ADR 0005: the lifecycle emits *blind*).

The lifecycle advances and emits events without knowing who listens; consumers
subscribe. This is **not** a durable bus — the proxy is single-process and
best-effort. The seam is an :class:`EventBus` instance **owned by the application**
(``app.state.event_bus``, created in the app factory); the audit (#85) and
notification (#13/#65) subscribers register against that instance during app wiring,
and emit sites obtain it from application state / DI rather than a module global.
One bus per app means a test that builds a fresh app gets a fresh bus, with nothing
to clear between cases. The waiting room projects lifecycle state by polling the DB
(it does not consume this seam).

Subscribers must not raise into the emitter: a handler failure is logged and
swallowed so a notification fault never blocks the lifecycle.

**The emitter's session is bound once, at the session scope — not at each emit.**
A lifecycle event is emitted *inside* the transition's transaction (the row is
flushed, not yet committed). A subscriber that must read the just-transitioned state
needs the emitter's own session — a separate connection would not see uncommitted
rows. Rather than have every emit site hand-lend its session, the request session
dependency (:func:`msig_proxy.deps.get_session`) and the provisioning session scope
bind it **once** via :func:`session_bound`; :func:`emit` and the subscribers read it
ambiently through :func:`active_session`. :func:`deliver_with_session` owns the
borrow-vs-own choice in one place — borrow the bound transition when one is in flight,
otherwise open a session off a factory — so each subscriber supplies only its dispatch
body and never re-implements that closure.
"""

from __future__ import annotations

import contextlib
import contextvars
import logging
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sqlalchemy.orm import Session, sessionmaker

_log = logging.getLogger(__name__)

# The session of the transition currently in flight, if any. Bound by the session
# scope (:func:`session_bound`) so a subscriber can read flushed-but-uncommitted state
# from the same transaction; emit no longer sets it per-call.
_active_session: contextvars.ContextVar[Session | None] = contextvars.ContextVar(
    "msig_active_event_session", default=None
)


def active_session() -> Session | None:
    """The emitter's bound session for the current scope, or ``None`` outside one."""
    return _active_session.get()


def bind_active_session(session: Session) -> contextvars.Token[Session | None]:
    """Bind ``session`` as the active event session; the returned token undoes it.

    Pass the token to :func:`reset_active_session` to restore the prior binding.
    The web request path uses the token form because the bind must straddle an
    ``async`` ``yield`` (the FastAPI session dependency); synchronous callers and tests
    use the :func:`session_bound` context manager instead.
    """
    return _active_session.set(session)


def reset_active_session(token: contextvars.Token[Session | None]) -> None:
    """Undo a :func:`bind_active_session`, restoring the previously bound session."""
    _active_session.reset(token)


@contextlib.contextmanager
def session_bound(session: Session) -> Iterator[None]:
    """Bind ``session`` as the active event session for the duration of the block.

    Used by synchronous session scopes (the provisioning CLI) and by tests that
    exercise the borrow path below HTTP. The web request dependency binds with
    :func:`bind_active_session` instead, because its bind spans an ``async`` yield.
    """
    token = bind_active_session(session)
    try:
        yield
    finally:
        reset_active_session(token)


def deliver_with_session(
    body: Callable[[Session], object],
    *,
    session_factory: sessionmaker[Session],
    commit: bool,
) -> None:
    """Run ``body`` with a session, borrowing the bound transition or opening its own.

    The borrow-vs-own choice the audit and notification subscribers used to each
    re-implement, owned here once. When a transition is in flight (:func:`active_session`),
    ``body`` runs on that **borrowed** session — neither committed nor closed here, since
    its owning scope (the request dependency / provisioning scope) does that, so an audit
    row commits atomically with the transition it records. With no transition bound,
    ``body`` runs on an **owned** session opened off ``session_factory``, always closed
    and committed only when ``commit`` is set — the *critical* audit consumer needs its
    row durable even outside a transition; the *best-effort* notification consumer reads.
    """
    active = active_session()
    if active is not None:
        body(active)
        return
    session = session_factory()
    try:
        body(session)
        if commit:
            session.commit()
    finally:
        session.close()

# Event names (subset of ``docs/request-lifecycle.md`` §Event catalog, plus the
# ``account.*`` catalog in ``docs/account-management.md``).
REQUEST_CREATED = "request.created"
REQUEST_CANCELLED = "request.cancelled"
REQUEST_APPROVED = "request.approved"
REQUEST_DENIED = "request.denied"
ACTION_SUCCEEDED = "action.succeeded"
ACTION_FAILED = "action.failed"
GRANT_ACTIVATED = "grant.activated"
GRANT_EXPIRED = "grant.expired"
ARTIFACT_DESTROYED = "artifact.destroyed"
# Account events (``docs/account-management.md`` §Account Events). The affected User
# is the subject; the notification matrix is in ``docs/notification-system.md``.
ENROLLMENT_ISSUED = "account.enrollment_issued"
CREDENTIALS_RESET = "account.credentials_reset"
ACCOUNT_DEACTIVATED = "account.deactivated"
ACCOUNT_DELETED = "account.deleted"


@dataclass(frozen=True)
class Event:
    name: str
    payload: dict[str, Any] = field(default_factory=dict)


class EventBus:
    """The in-process lifecycle event seam (ADR 0005), owned by the application.

    Holds the subscriber registry on the instance — one bus per app, created at app
    construction — so there is no process-global state to clear between tests. The
    seam stays **blind, in-process, and best-effort**: a subscriber that raises is
    logged and swallowed and never blocks a transition.
    """

    def __init__(self) -> None:
        self._subscribers: list[Callable[[Event], None]] = []

    def subscribe(self, handler: Callable[[Event], None]) -> None:
        """Register a handler to receive every emitted event."""
        self._subscribers.append(handler)

    def unsubscribe(self, handler: Callable[[Event], None]) -> None:
        """Remove a previously registered handler (idempotent)."""
        if handler in self._subscribers:
            self._subscribers.remove(handler)

    def emit(self, event: Event) -> None:
        """Deliver ``event`` to every subscriber, best-effort (failures are logged).

        The seam stays blind: the emitting transition's session is bound ambiently at
        the session scope (:func:`active_session`), so emit takes no session argument.
        A subscriber that must read the flushed-but-uncommitted transition borrows that
        session through :func:`deliver_with_session`; emit only fans the event out.
        """
        for handler in list(self._subscribers):
            try:
                handler(event)
            except Exception:
                _log.warning("event subscriber failed for %s", event.name, exc_info=True)
