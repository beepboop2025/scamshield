"""ScamShield Telegram bot.

One detector, two modes. Only Shield mode is switched on in this build:

1. Shield mode (private chat, ALWAYS ON): anyone forwards a suspicious
   message to the bot and gets an instant verdict, an explanation of the
   scam mechanics, and official reporting channels. Zero special access
   needed. This is everything the bot does for users today.

2. Guardian mode (group moderation, OFF BY DEFAULT): scores every group
   message and acts per POLICY below (flag / delete / ban). It is fully
   implemented but is NOT registered unless SCAMSHIELD_GUARDIAN=1, and it
   additionally needs two @BotFather settings that are currently off. See
   GUARDIAN_ENABLED below for the exact toggles. Nothing in this bot may
   advertise group protection while Guardian mode is off: a user who is
   told to add the bot to a group, and whose add Telegram then refuses,
   walks away believing they are covered when they are not.

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

# ---------------------------------------------------------------------------
# Guardian mode master switch. Off by default, and deliberately explicit:
# the group handler below used to be registered unconditionally, which made
# it dead code that nobody could see was dead, while /start still told users
# to add the bot to a group.
#
# Turning it on takes THREE steps, all three required:
#   1. @BotFather -> /mybots -> this bot -> Bot Settings -> "Allow Groups?"
#      set to ENABLED.  (getMe: can_join_groups -> true)
#   2. @BotFather -> /mybots -> this bot -> Bot Settings -> "Group Privacy"
#      set to DISABLED / turned OFF.  (getMe: can_read_all_group_messages
#      -> true)
#   3. Set SCAMSHIELD_GUARDIAN=1 in /etc/scamshield.env and restart.
#
# Step 1 WITHOUT step 2 is the dangerous half-state, and it is the easy
# mistake to make because step 1 alone looks like success: the bot joins
# groups happily, sits there as a member, and receives almost nothing.
# With Group Privacy still on, Telegram only delivers commands addressed to
# the bot, replies to it, and service messages, so the detector scores a
# tiny fraction of traffic and stays silent on the mule ads it exists to
# catch. Silence reads exactly like "no scams here". Do both toggles or
# neither, and confirm with a getMe before telling any user they are
# protected. main() logs a loud warning if this flag disagrees with getMe.
# ---------------------------------------------------------------------------
GUARDIAN_ENABLED = os.environ.get("SCAMSHIELD_GUARDIAN", "0") == "1"

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
# replace them with your policy. Nothing here takes effect while
# GUARDIAN_ENABLED is false; it is the policy for a mode that is off.
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


def start_text() -> str:
    """/start copy. Must describe only what is actually switched on.

    The group sentence is gated on GUARDIAN_ENABLED so the copy cannot
    drift away from the handler registration in main(): both read the same
    flag, so promising group protection and providing it are one decision.
    """
    out = ("Forward me any suspicious crypto/payment message and I'll tell "
           "you if it matches known money-mule and scam-ad patterns, and how "
           "to report it.")
    if GUARDIAN_ENABLED:
        out += (" You can also add me to a group as admin and I'll watch "
                "every message there.")
    else:
        out += (" I work in this private chat only. I don't monitor groups, "
                "so adding me to one will not protect it.")
    return out


async def cmd_start(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(start_text())


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


async def _warn_on_guardian_mismatch(app: Application) -> None:
    """Say out loud when the flag and the BotFather toggles disagree.

    Fail VISIBLE, not closed: this only logs. A bot that refuses to start
    because a toggle is off is an outage, and the whole point here is that
    Shield mode is independent of Guardian mode and must keep serving.
    """
    try:
        me = await app.bot.get_me()
        joins = bool(getattr(me, "can_join_groups", False))
        reads = bool(getattr(me, "can_read_all_group_messages", False))
        if GUARDIAN_ENABLED and not (joins and reads):
            log.warning(
                "GUARDIAN MODE IS NOT ACTUALLY ACTIVE. SCAMSHIELD_GUARDIAN=1 "
                "but @BotFather says can_join_groups=%s, "
                "can_read_all_group_messages=%s. Enable 'Allow Groups?' AND "
                "disable 'Group Privacy', or groups will look watched and "
                "will not be.", joins, reads)
        elif not GUARDIAN_ENABLED and joins and reads:
            log.warning(
                "@BotFather has both group toggles on but "
                "SCAMSHIELD_GUARDIAN is unset, so group messages are ignored "
                "and /start says so. Set SCAMSHIELD_GUARDIAN=1 to use them.")
    except Exception as e:  # never let a diagnostic take the bot down
        log.warning("guardian getMe cross-check skipped: %s", e)


def main() -> None:
    if not TOKEN:
        raise SystemExit("Set SCAMSHIELD_TOKEN (from @BotFather) first.")
    app = (Application.builder().token(TOKEN)
           .post_init(_warn_on_guardian_mismatch).build())
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("digest", cmd_digest))
    app.add_handler(MessageHandler(
        filters.ChatType.PRIVATE & ~filters.COMMAND, on_private))
    # Guardian mode: registered only when explicitly switched on. See the
    # GUARDIAN_ENABLED block near the top for the two @BotFather settings
    # this also needs. on_group() and POLICY are kept intact and working;
    # they are simply not wired up while the mode is off.
    if GUARDIAN_ENABLED:
        app.add_handler(MessageHandler(
            filters.ChatType.GROUPS & ~filters.COMMAND, on_group))
    log.info("ScamShield up. Shield mode on; guardian mode %s.",
             "ON" if GUARDIAN_ENABLED else "off")
    app.run_polling()


if __name__ == "__main__":
    main()
