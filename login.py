"""One-time interactive login for the dedicated monitoring account.

Run this ONCE, on a machine where you can read the SMS code sent to the
monitoring number. It creates a saved Telethon session file
(scamshield_monitor.session) that monitor.py then uses headlessly — no
further OTP needed unless Telegram invalidates the session.

This is a SEPARATE, dedicated account — never your personal identity.
Read-only monitoring of hostile channels only.

Prereqs (both from https://my.telegram.org → API development tools,
logged in with the MONITORING number, not your personal one):
    TELETHON_API_ID, TELETHON_API_HASH   (put them in .env)
    SCAMSHIELD_PHONE                      (optional; otherwise prompted once)

    python login.py
"""

from __future__ import annotations

import asyncio
import os
import re
from pathlib import Path
from typing import Callable, Mapping

from telethon import TelegramClient

from scamshield.envload import load_env
from scamshield.runtime import session_base_path, session_file_path

load_env()

SESSION = session_base_path()

_E164_PHONE = re.compile(r"^\+[1-9][0-9]{6,14}$")


def monitoring_phone(
    environment: Mapping[str, str],
    prompt: Callable[[str], str] = input,
) -> str:
    """Return an E.164 phone without requiring it to persist in the env file."""

    phone = environment.get("SCAMSHIELD_PHONE", "").strip()
    if not phone:
        try:
            phone = prompt("Monitoring Telegram phone (+countrycode...): ").strip()
        except (EOFError, KeyboardInterrupt) as exc:
            raise SystemExit("Telegram phone entry was cancelled") from exc
    if not _E164_PHONE.fullmatch(phone):
        raise SystemExit(
            "Monitoring phone must use E.164 form, for example +919876543210"
        )
    return phone


async def main() -> None:
    try:
        api_id = int(os.environ["TELETHON_API_ID"])
        api_hash = os.environ["TELETHON_API_HASH"]
    except (KeyError, ValueError) as e:
        raise SystemExit(
            f"Missing {e}. Add TELETHON_API_ID / TELETHON_API_HASH to .env "
            "(get them from my.telegram.org, logged in with the monitoring "
            "number)."
        )
    phone = monitoring_phone(os.environ)

    Path(SESSION).parent.mkdir(parents=True, exist_ok=True)
    client = TelegramClient(str(SESSION), api_id, api_hash)
    # start() prompts on stdin for the SMS code (and 2FA password if set).
    await client.start(phone=phone)
    me = await client.get_me()
    print(f"\n✓ Logged in as @{me.username or me.first_name} (id {me.id}).")
    await client.disconnect()
    session_file = session_file_path()
    session_file.chmod(0o600)
    print(f"✓ Session saved to {session_file} — monitor.py can now run headless.")


if __name__ == "__main__":
    asyncio.run(main())
