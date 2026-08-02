"""Tiny .env loader shared by the bot and the monitor.

No dependency on python-dotenv; keeps values already in the real
environment authoritative (setdefault), so systemd/launchd overrides win.
"""

from __future__ import annotations

import os
from pathlib import Path


def load_env(path: str | Path | None = None) -> None:
    p = Path(path) if path else Path(__file__).resolve().parent.parent / ".env"
    if not p.exists():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())
