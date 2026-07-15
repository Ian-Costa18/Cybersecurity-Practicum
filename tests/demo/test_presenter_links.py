"""Backing check for the demo's presenter deep-links + inbox reset (epic #142).

The notebook hands the presenter click-out links into the live UIs — a single person's
filtered Mailpit inbox, a deep link to the exact message that just landed, and the
internal PyPI index — and empties the shared inbox on reset so a take opens clean. These
are pure string-builders plus two thin Mailpit REST calls, testable without a live stack
(the URL formatting is asserted directly; the HTTP calls run against a mocked transport).
"""

from __future__ import annotations

import demo_flow
import demo_lib
import httpx
import respx

_STACK = demo_flow.DemoStack(
    proxy_url="http://proxy.test",
    mailpit_url="http://mail.api",
    pypiserver_url="http://pypi.api",
    smtp_host="smtp.test",
    smtp_port=1025,
    mailpit_web_url="http://mail.web",
    pypiserver_web_url="http://pypi.web",
)

_ADA = demo_lib.person("ada")


def _messages_payload(*messages: dict[str, object]) -> dict[str, object]:
    """A Mailpit ``/api/v1/messages`` response body wrapping the given message rows."""
    return {"total": len(messages), "messages": list(messages)}


def _row(msg_id: str, *, to: str, subject: str) -> dict[str, object]:
    return {
        "ID": msg_id,
        "From": {"Address": "someone@acme.example"},
        "To": [{"Address": to}],
        "Subject": subject,
        "Snippet": "",
    }


# --- pure URL builders ------------------------------------------------------


def test_mailpit_inbox_url_filters_to_the_person() -> None:
    # The whole team shares one SMTP sink; the link pre-filters Mailpit to one recipient so
    # the presenter opens a clean inbox, not the team's clutter. The `to:` query is encoded.
    assert (
        demo_flow.mailpit_inbox_url(_STACK, _ADA)
        == "http://mail.web/search?q=to%3Aada%40acme.example"
    )


def test_mailpit_message_url_targets_the_id() -> None:
    assert demo_flow.mailpit_message_url(_STACK, "abc123") == "http://mail.web/view/abc123"


def test_pypiserver_index_url_points_at_the_internal_index() -> None:
    # The host-facing (localhost) index the presenter opens — never the container name.
    assert demo_flow.pypiserver_index_url(_STACK) == "http://pypi.web/simple/acme-widgets/"


# --- Mailpit REST-backed helpers (mocked transport) -------------------------


def test_find_message_to_matches_recipient_and_subject() -> None:
    with respx.mock as router:
        router.get("http://mail.api/api/v1/messages").mock(
            return_value=httpx.Response(
                200,
                json=_messages_payload(
                    _row("to-charles", to="charles@acme.example", subject="Are you pushing 1.0.1?"),
                    _row("to-ada", to=_ADA.email, subject="Re: Are you pushing 1.0.1?"),
                ),
            )
        )

        found = demo_flow.find_message_to(
            _STACK, to_email=_ADA.email, subject_contains="Are you pushing"
        )

    assert found is not None and found.id == "to-ada"  # picks the message addressed to Ada


def test_mailpit_link_for_deep_links_when_found_else_falls_back_to_inbox() -> None:
    with respx.mock as router:
        route = router.get("http://mail.api/api/v1/messages")

        route.mock(
            return_value=httpx.Response(
                200, json=_messages_payload(_row("m1", to=_ADA.email, subject="Approval needed"))
            )
        )
        deep = demo_flow.mailpit_link_for(_STACK, _ADA, subject_contains="Approval needed")
        assert deep == "http://mail.web/view/m1"  # exact message when it can be found

        route.mock(return_value=httpx.Response(200, json=_messages_payload()))
        fallback = demo_flow.mailpit_link_for(_STACK, _ADA, subject_contains="Approval needed")
        assert fallback == demo_flow.mailpit_inbox_url(_STACK, _ADA)  # else the filtered inbox


def test_delete_all_mail_reports_success_and_swallows_failure() -> None:
    with respx.mock as router:
        route = router.delete("http://mail.api/api/v1/messages")

        route.mock(return_value=httpx.Response(200))
        assert demo_flow.delete_all_mail(_STACK) is True

        # Best-effort: a failure is reported, not raised.
        route.mock(return_value=httpx.Response(500))
        assert demo_flow.delete_all_mail(_STACK) is False
