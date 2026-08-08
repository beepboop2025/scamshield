"""Runtime paths that must survive code releases.

Development keeps the historical repository-local defaults. Production can
point the Telethon session and source registry at Hetzner-owned state/config
directories so an atomic code deploy never replaces either one.
"""

from __future__ import annotations

import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def session_base_path() -> Path:
    """Return Telethon's session base path (normally without ``.session``)."""

    configured = os.environ.get("SCAMSHIELD_SESSION", "").strip()
    return Path(configured).expanduser() if configured else PROJECT_ROOT / "scamshield_monitor"


def session_file_path() -> Path:
    """Return the SQLite session filename Telethon derives from the base."""

    base = session_base_path()
    if str(base).endswith(".session"):
        return base
    return Path(f"{base}.session")


def channels_file_path() -> Path:
    """Return the operator-managed Telegram source registry."""

    configured = os.environ.get("SCAMSHIELD_CHANNELS_FILE", "").strip()
    return Path(configured).expanduser() if configured else PROJECT_ROOT / "channels.txt"


__all__ = ["channels_file_path", "session_base_path", "session_file_path"]
