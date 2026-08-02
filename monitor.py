"""ScamShield monitor: dedicated read-only account that watches hostile
channels and feeds every message through the offline detector.

Runs headless off the session created by login.py. For each new message
in a watched channel it:
  1. classifies it (scamshield.detector),
  2. records any IOCs to the shared SQLite store,
  3. DMs you (via the bot) when a message hits LIKELY or CONFIRMED.

Channels to watch live in channels.txt (one @username / t.me link / id per
line, # for comments). The account must be able to see them — public
channels are joined automatically on startup; private ones you must join
manually from the client first.

    python monitor.py
"""

from __future__ import annotations

import asyncio
import logging
import os
import urllib.parse
import urllib.request
from pathlib import Path

from telethon import TelegramClient, events

from scamshield.detector import classify
from scamshield.envload import load_env
from scamshield.iocstore import IocStore

load_env()
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("scamshield.monitor")

SESSION = "scamshield_monitor"
STORE = IocStore(os.environ.get("SCAMSHIELD_DB", "scamshield.db"))
CHANNELS_FILE = Path(__file__).with_name("channels.txt")


def read_channels() -> list[str]:
    if not CHANNELS_FILE.exists():
        return []
    out = []
    for line in CHANNELS_FILE.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def alert_owner(text: str) -> None:
    token = os.environ.get("SCAMSHIELD_TOKEN")
    owner = os.environ.get("SCAMSHIELD_OWNER_ID")
    if not (token and owner):
        return
    data = urllib.parse.urlencode({"chat_id": owner, "text": text}).encode()
    try:
        urllib.request.urlopen(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=data, timeout=15,
        )
    except Exception as e:
        log.warning("owner alert failed: %s", e)


async def main() -> None:
    try:
        api_id = int(os.environ["TELETHON_API_ID"])
        api_hash = os.environ["TELETHON_API_HASH"]
    except KeyError as e:
        raise SystemExit(f"Missing {e}. Run login.py setup first.")

    client = TelegramClient(SESSION, api_id, api_hash)
    await client.start()  # uses saved session; exits if not logged in

    if not await client.is_user_authorized():
        raise SystemExit("Not logged in. Run: python login.py")

    watch = read_channels()
    entities = []
    for ch in watch:
        try:
            ent = await client.get_entity(ch)
            try:
                from telethon.tl.functions.channels import JoinChannelRequest
                await client(JoinChannelRequest(ent))
            except Exception:
                pass  # already joined, or a group that doesn't need joining
            entities.append(ent)
            log.info("watching %s", ch)
        except Exception as e:
            log.warning("cannot resolve %s: %s", ch, e)

    if not entities:
        log.warning("No channels resolved. Add some to channels.txt.")

    @client.on(events.NewMessage(chats=entities or None))
    async def handler(event) -> None:
        text = event.raw_text or ""
        if not text.strip():
            return
        verdict = classify(text)
        if verdict.iocs:
            STORE.record(verdict.iocs, sample=text)
        if verdict.tier in ("LIKELY_SCAM", "CONFIRMED_PATTERN"):
            title = getattr(event.chat, "title", "?")
            alert_owner(
                f"🛡 {verdict.tier} (score {verdict.score}) in “{title}”\n\n"
                f"{text[:250]}"
            )
            log.info("%s in %s (score %s)", verdict.tier, title, verdict.score)

    log.info("Monitor up on %d channel(s).", len(entities))
    await client.run_until_disconnected()


if __name__ == "__main__":
    asyncio.run(main())
