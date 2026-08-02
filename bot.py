"""ScamShield Telegram bot.

Two modes, one detector:

1. Shield mode (private chat): anyone forwards a suspicious message to the
   bot and gets an instant verdict, an explanation of the scam mechanics,
   and official reporting channels. Zero special access needed.

2. Guardian mode (group): added as *admin* to a group, it scores every
   message and acts per POLICY below (flag / delete / ban).

Setup:
  1. Create a bot with @BotFather, get the token.
  2. export SCAMSHIELD_TOKEN=...  SCAMSHIELD_OWNER_ID=<your numeric TG id>
  3. pip install -r requirements.txt && python bot.py

Owner commands: /digest — dump the IOC table collected so far.
"""

from __future__ import annotations

import html
import logging
import os
import socket
from pathlib import Path

# This network blackholes IPv6 (see claude-telegram-bridge force_ipv4);
# filter DNS results to IPv4 before httpx opens any connection.
if os.environ.get("SCAMSHIELD_FORCE_IPV4", "1") != "0":
    _real_getaddrinfo = socket.getaddrinfo

    def _ipv4_getaddrinfo(host, port, family=0, *args, **kwargs):
        return _real_getaddrinfo(host, port, socket.AF_INET, *args, **kwargs)

    socket.getaddrinfo = _ipv4_getaddrinfo

# Minimal .env loader so `python bot.py` works without exporting anything.
_env = Path(__file__).with_name(".env")
if _env.exists():
    for line in _env.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import (Application, CommandHandler, ContextTypes,
                          MessageHandler, filters)

from scamshield.detector import Verdict, classify
from scamshield.iocstore import IocStore

logging.basicConfig(level=logging.INFO)
# httpx logs every request URL at INFO, and a Telegram request URL embeds the
# bot token. Left alone it writes the token into the journal on every poll.
for _noisy in ("httpx", "httpcore", "telegram.ext.Application"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)
log = logging.getLogger("scamshield")

TOKEN = os.environ.get("SCAMSHIELD_TOKEN", "")
OWNER_ID = int(os.environ.get("SCAMSHIELD_OWNER_ID", "0"))
STORE = IocStore(os.environ.get("SCAMSHIELD_DB", "scamshield.db"))

REPORT_FOOTER = (
    "\n\n<b>Report it (India):</b>\n"
    "• Helpline 1930 / cybercrime.gov.in (I4C) — can freeze mule accounts\n"
    "• In Telegram: long-press the message → Report → Scam\n"
    "• Never send a 'prepaid deposit'; never rent out your UPI/bank account — "
    "account holders are the first people the police trace."
)


# ---------------------------------------------------------------------------
# TODO(owner): Guardian-mode moderation policy — this is the decision that
# shapes the bot's character, and it is a legal/moderation call, not a
# technical one. For each verdict tier, choose one of:
#   "ignore" | "flag" (reply publicly) | "delete" | "delete_and_ban"
#
# Trade-offs to weigh:
#   - delete_and_ban on CONFIRMED_PATTERN maximizes protection but a false
#     positive silently censors a legit member (they rarely appeal).
#   - flag-only creates a public record and teaches the group what these
#     ads look like, but leaves the contact handles visible and clickable.
#   - delete-without-ban stops the ad but lets the account repost (they
#     rotate accounts anyway, so bans buy less than you'd think).
# The conservative defaults below (never auto-ban) are placeholders —
# replace them with your policy.
# ---------------------------------------------------------------------------
POLICY = {
    "CONFIRMED_PATTERN": "delete",
    "LIKELY_SCAM": "flag",
    "WATCH": "ignore",
    "CLEAN": "ignore",
}


def render_verdict(v: Verdict) -> str:
    badge = {
        "CONFIRMED_PATTERN": "🔴 CONFIRMED scam pattern",
        "LIKELY_SCAM": "🟠 Likely scam",
        "WATCH": "🟡 Suspicious — be careful",
        "CLEAN": "🟢 No known scam patterns",
    }[v.tier]
    out = f"<b>{badge}</b> (score {v.score})\n\n{html.escape(v.explain())}"
    if v.tier in ("CONFIRMED_PATTERN", "LIKELY_SCAM"):
        out += REPORT_FOOTER
    return out


async def cmd_start(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "Forward me any suspicious crypto/payment message and I'll tell you "
        "if it matches known money-mule and scam-ad patterns — and how to "
        "report it. Add me to a group as admin and I'll watch it for you."
    )


async def cmd_digest(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_user.id != OWNER_ID:
        return
    rows = STORE.digest()
    if not rows:
        await update.message.reply_text("IOC store is empty.")
        return
    body = "\n".join(f"{k:<8} {v}  ×{h}" for k, v, h in rows[:100])
    await update.message.reply_text(f"<pre>{html.escape(body)}</pre>",
                                    parse_mode=ParseMode.HTML)


async def on_private(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    text = update.message.text or update.message.caption or ""
    if not text.strip():
        return
    verdict = classify(text)
    if verdict.iocs:
        STORE.record(verdict.iocs, sample=text)
    await update.message.reply_text(render_verdict(verdict),
                                    parse_mode=ParseMode.HTML)


async def on_group(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg = update.message
    text = (msg.text or msg.caption or "") if msg else ""
    if not text.strip():
        return
    verdict = classify(text)
    if verdict.iocs:
        STORE.record(verdict.iocs, sample=text)
    action = POLICY.get(verdict.tier, "ignore")

    if action == "ignore":
        return
    if action == "flag":
        await msg.reply_text(render_verdict(verdict), parse_mode=ParseMode.HTML)
        return
    if action in ("delete", "delete_and_ban"):
        try:
            await msg.delete()
        except Exception as e:  # not admin / message too old
            log.warning("delete failed: %s", e)
        if action == "delete_and_ban":
            try:
                await context.bot.ban_chat_member(msg.chat_id, msg.from_user.id)
            except Exception as e:
                log.warning("ban failed: %s", e)
        if OWNER_ID:
            await context.bot.send_message(
                OWNER_ID,
                f"[{msg.chat.title}] {action} on {verdict.tier} "
                f"(score {verdict.score}) from "
                f"{msg.from_user.mention_html()}",
                parse_mode=ParseMode.HTML,
            )


def main() -> None:
    if not TOKEN:
        raise SystemExit("Set SCAMSHIELD_TOKEN (from @BotFather) first.")
    app = Application.builder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("digest", cmd_digest))
    app.add_handler(MessageHandler(
        filters.ChatType.PRIVATE & ~filters.COMMAND, on_private))
    app.add_handler(MessageHandler(
        filters.ChatType.GROUPS & ~filters.COMMAND, on_group))
    log.info("ScamShield up.")
    app.run_polling()


if __name__ == "__main__":
    main()
