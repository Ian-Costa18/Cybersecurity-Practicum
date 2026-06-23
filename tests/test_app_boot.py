"""``create_app()`` boots through the real config-file + env path, end to end.

The other tests inject ``Settings``/``AppConfig`` directly; this one exercises
the production boot path — no arguments, config read from the file named by
``MSIG_CONFIG_FILE`` — so the "validates at startup, fails loudly" contract
cannot silently regress.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from msig_proxy.app import create_app
from msig_proxy.core.config import ConfigError

CONFIG = """\
server:
  base_url: http://localhost:8080
  secret_key: integration-secret-0123456789
"""


def _point_env_at(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, config_text: str | None) -> None:
    if config_text is not None:
        (tmp_path / "config.yaml").write_text(config_text, encoding="utf-8")
    monkeypatch.setenv("MSIG_CONFIG_FILE", str(tmp_path / "config.yaml"))
    monkeypatch.setenv(
        "MSIG_DATABASE_URL", f"sqlite+pysqlite:///{(tmp_path / 'boot.db').as_posix()}"
    )


async def test_create_app_loads_config_from_file_and_serves(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _point_env_at(tmp_path, monkeypatch, CONFIG)

    app = create_app()  # no injected settings/config — the real boot path

    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.get("/health")
        assert response.status_code == 200
    finally:
        app.state.db_engine.dispose()  # close pooled connections (no GC ResourceWarning)


def test_create_app_fails_loudly_when_config_file_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _point_env_at(tmp_path, monkeypatch, config_text=None)  # no file written

    with pytest.raises(ConfigError):
        create_app()
