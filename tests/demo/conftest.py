"""Put ``demo/notebooks`` on ``sys.path`` so tests can import the demo-support
library (``demo_lib``) by module name.

The evaluation demo (epic #142) lives under ``demo/`` — it is presentation
scaffolding, not part of the ``msig_proxy`` package — so it is not on the default
import path. Mirrors ``tests/tools/conftest.py``, which does the same for the
single-file ``tools/`` scripts.
"""

from __future__ import annotations

import sys
from pathlib import Path

_DEMO_NOTEBOOKS = Path(__file__).resolve().parents[2] / "demo" / "notebooks"
if str(_DEMO_NOTEBOOKS) not in sys.path:
    sys.path.insert(0, str(_DEMO_NOTEBOOKS))
