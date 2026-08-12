"""Minimal systemd readiness/watchdog notifications without a dependency."""

from __future__ import annotations

import os
import socket
from typing import Mapping


def notify_systemd(message: str, environment: Mapping[str, str] | None = None) -> bool:
    """Send one datagram to systemd and return whether a socket was available."""

    env = os.environ if environment is None else environment
    address = env.get("NOTIFY_SOCKET", "")
    if not address:
        return False
    if address.startswith("@"):
        address = f"\0{address[1:]}"
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        sock.connect(address)
        sock.sendall(message.encode("utf-8"))
    finally:
        sock.close()
    return True


def watchdog_interval(environment: Mapping[str, str] | None = None) -> float | None:
    """Return a conservative half-watchdog interval, or ``None`` outside systemd."""

    env = os.environ if environment is None else environment
    raw = env.get("WATCHDOG_USEC", "").strip()
    if not raw:
        return None
    try:
        microseconds = int(raw)
    except ValueError:
        return None
    if microseconds <= 0:
        return None
    return max(1.0, microseconds / 2_000_000)


__all__ = ["notify_systemd", "watchdog_interval"]
