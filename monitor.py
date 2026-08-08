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

from scamshield.analysis import AnalysisService, ObservationContext
from scamshield.envload import load_env
from scamshield.iocstore import IocStore
from scamshield.runtime import channels_file_path, session_base_path

load_env()
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("scamshield.monitor")

SESSION = session_base_path()
STORE = IocStore(os.environ.get("SCAMSHIELD_DB", "scamshield.db"))
ANALYZER = AnalysisService.from_environment()
STORE_RAW_SAMPLES = os.environ.get("SCAMSHIELD_STORE_RAW_SAMPLES", "0") == "1"
CHANNELS_FILE = channels_file_path()


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
        # urllib exceptions can echo the request URL, which contains the bot
        # token. Log the failure class without leaking the credential.
        log.warning("owner alert failed (%s)", type(e).__name__)


async def main() -> None:
    try:
        api_id = int(os.environ["TELETHON_API_ID"])
        api_hash = os.environ["TELETHON_API_HASH"]
    except KeyError as e:
        raise SystemExit(f"Missing {e}. Run login.py setup first.")

    client = TelegramClient(str(SESSION), api_id, api_hash)
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

    async def handler(event) -> None:
        text = event.raw_text or ""
        if not text.strip():
            return
        is_public = bool(getattr(event.chat, "username", None))
        surface = "public_channel" if is_public else "authorized_private_channel"
        authorization = "public" if is_public else "operator_authorized"
        collection = ObservationContext.create(
            text,
            surface=surface,
            authorization=authorization,
            raw_source=str(event.chat_id),
        )
        try:
            result = await asyncio.to_thread(
                ANALYZER.analyze, text, collection=collection,
            )
        except Exception as exc:
            STORE.record_collection_error(surface, collection.source_pseudonym)
            log.exception("analysis failed for %s: %s", event.chat_id, exc)
            return
        if result.iocs:
            STORE.record(
                result.iocs, sample=text if STORE_RAW_SAMPLES else "",
            )
        if result.overall_tier == "CLEAN":
            STORE.record_coverage(result)
        else:
            STORE.record_analysis(result)
        if result.overall_tier in ("LIKELY_SCAM", "CONFIRMED_PATTERN"):
            title = getattr(event.chat, "title", "?")
            families = ", ".join(result.threats.families) or ", ".join(
                sorted(result.detector.families)
            )
            await asyncio.to_thread(
                alert_owner,
                f"🛡 {result.overall_tier} (score {result.overall_score}) "
                f"in “{title}” [{families or 'general'}]\n\n{text[:250]}",
            )
            log.info(
                "%s in %s (score %s)",
                result.overall_tier, title, result.overall_score,
            )

    # Never use chats=None here: in Telethon that means every visible chat,
    # turning an empty configuration into broad account surveillance.
    if entities:
        client.add_event_handler(handler, events.NewMessage(chats=entities))

    log.info("Monitor up on %d channel(s).", len(entities))
    await client.run_until_disconnected()


if __name__ == "__main__":
    asyncio.run(main())
