"""Put the single-file ``tools/`` scripts on ``sys.path`` so tests can import them
by module name, independent of how the wheel packages them. ``threat_model`` is
repo dev/analysis tooling (issue #130), not part of the ``msig_proxy`` package."""

from __future__ import annotations

import sys
from pathlib import Path

_TOOLS = Path(__file__).resolve().parents[2] / "tools"
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))
