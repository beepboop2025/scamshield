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
    SCAMSHIELD_PHONE                      (already set to the new number)

    python login.py
"""

from __future__ import annotations

import asyncio
import os

from telethon import TelegramClient

from scamshield.envload import load_env

load_env()

SESSION = "scamshield_monitor"


async def main() -> None:
    try:
        api_id = int(os.environ["TELETHON_API_ID"])
        api_hash = os.environ["TELETHON_API_HASH"]
        phone = os.environ["SCAMSHIELD_PHONE"]
    except KeyError as e:
        raise SystemExit(
            f"Missing {e}. Add TELETHON_API_ID / TELETHON_API_HASH to .env "
            "(get them from my.telegram.org, logged in with the monitoring "
            "number)."
        )

    client = TelegramClient(SESSION, api_id, api_hash)
    # start() prompts on stdin for the SMS code (and 2FA password if set).
    await client.start(phone=phone)
    me = await client.get_me()
    print(f"\n✓ Logged in as @{me.username or me.first_name} (id {me.id}).")
    print(f"✓ Session saved to {SESSION}.session — monitor.py can now run headless.")
    await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
