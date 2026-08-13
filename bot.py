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

Owner commands:
  /digest — dump the IOC table collected so far.
  /coverage — show measured collection coverage.
  /monitor — show aggregate Telethon collector health and backlog.
  /funnel — show aggregate starts, unsupported inputs, and verdict feedback.
  /liquidity [YYYY-MM-DD] — show the reviewed UTC-day liquidity pulse.
  /review_amount ... — bind one explicit monetary review to a scanned message.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import logging
import os
import re
import socket
import time
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

from telegram import BotCommand, InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.ext import (Application, CommandHandler, ContextTypes,
                          CallbackQueryHandler, MessageHandler, filters)

from scamshield.analysis import AnalysisService, ObservationContext
from scamshield.detector import Verdict
from scamshield.iocstore import IocStore
from scamshield.liquidity_ui import (
    parse_pulse_day,
    parse_review_observation,
    render_liquidity_pulse,
    render_review_confirmation,
    review_id_from_alert,
    review_usage,
)
from scamshield.rendering import render_analysis
from scamshield.surfaces import reporting_steps, typology_catalog

logging.basicConfig(level=logging.INFO)
# httpx logs every request URL at INFO, and a Telegram request URL embeds the
# bot token. Left alone it writes the token into the journal on every poll.
for _noisy in ("httpx", "httpcore", "telegram.ext.Application"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)
log = logging.getLogger("scamshield")

TOKEN = os.environ.get("SCAMSHIELD_TOKEN", "")
OWNER_ID = int(os.environ.get("SCAMSHIELD_OWNER_ID", "0"))
STORE = IocStore(os.environ.get("SCAMSHIELD_DB", "scamshield.db"))
ANALYZER = AnalysisService.from_environment()
STORE_RAW_SAMPLES = os.environ.get("SCAMSHIELD_STORE_RAW_SAMPLES", "0") == "1"
PALIMPSEST_URL = os.environ.get("PALIMPSEST_URL", "https://palimpsest.info")
NARCOSCOPE_URL = os.environ.get(
    "NARCOSCOPE_URL", "https://narcoscope.com"
)
SCAMSHIELD_GUIDE_URL = os.environ.get(
    "SCAMSHIELD_GUIDE_URL",
    "https://palimpsest.info/guides/telegram-scam-message-checker/",
)
EVIDENCE_CHANNEL_URL = os.environ.get("EVIDENCE_CHANNEL_URL", "").strip()

PUBLIC_COMMANDS = (
    BotCommand("start", "Scan a suspicious message"),
    BotCommand("how", "See what ScamShield checks"),
    BotCommand("typologies", "Explore covered scam patterns"),
    BotCommand("privacy", "See what is stored and shared"),
    BotCommand("explore", "Open the evidence products"),
    BotCommand("help", "Show commands and reporting help"),
)

_CAMPAIGN_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_FEEDBACK_RE = re.compile(
    r"^feedback:([0-9a-f]{24}):(CLEAN|WATCH|LIKELY_SCAM|CONFIRMED_PATTERN):"
    r"(agree|disagree|unsure)$"
)

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
    "CONFIRMED_PATTERN": "flag",
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
    out = (
        "<b>Turn a suspicious message into an evidence-bounded risk readout.</b>\n\n"
        "Forward or paste the message here. ScamShield checks for money-mule, "
        "phishing, impersonation, advance-fee, counterfeit, illicit-market, and "
        "trafficking-risk patterns. You get the matched mechanics, evidence "
        "limits, and practical reporting steps — usually in one reply.\n\n"
        "No supported pattern is a guarantee of safety."
    )
    if GUARDIAN_ENABLED:
        out += ("\n\nYou can also add me to a group as admin and I'll watch "
                "every message there.")
    else:
        out += ("\n\n<b>Private-chat Shield mode is on.</b> I don't monitor groups, "
                "so adding me to one will not protect it.")
    out += "\n\n<b>Try it now:</b> forward the message you are unsure about."
    return out


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    campaign = start_campaign(context.args)
    try:
        STORE.record_product_event("start", campaign)
    except Exception as exc:
        log.warning("start attribution skipped: %s", exc)
    await update.message.reply_text(
        start_text(), parse_mode=ParseMode.HTML, reply_markup=product_keyboard(),
    )


def start_campaign(args: list[str] | tuple[str, ...] | None) -> str:
    """Normalize Telegram's /start payload without retaining user identity."""

    if not args:
        return "direct"
    candidate = str(args[0]).strip().lower()
    return candidate if _CAMPAIGN_RE.fullmatch(candidate) else "unattributed"


def _product_rows() -> list[list[InlineKeyboardButton]]:
    rows = []
    if EVIDENCE_CHANNEL_URL:
        rows.append([InlineKeyboardButton("Follow Evidence Signal", url=EVIDENCE_CHANNEL_URL)])
    rows.append([
        InlineKeyboardButton("Public safety guide", url=SCAMSHIELD_GUIDE_URL),
    ])
    rows.append([
        InlineKeyboardButton("Palimpsest", url=PALIMPSEST_URL),
        InlineKeyboardButton("NarcoScope", url=NARCOSCOPE_URL),
    ])
    return rows


def product_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(_product_rows())


def result_keyboard(result) -> InlineKeyboardMarkup:
    """Offer one explicit, privacy-safe assessment response."""

    assessment_id = result.provenance.assessment_id
    tier = result.overall_tier
    positive_label = "Seems right" if tier == "CLEAN" else "Useful"
    negative_label = "Missed risk" if tier == "CLEAN" else "Looks wrong"

    def button(label: str, response: str) -> InlineKeyboardButton:
        return InlineKeyboardButton(
            label,
            callback_data=f"feedback:{assessment_id}:{tier}:{response}",
        )

    feedback = [[
        button(f"✅ {positive_label}", "agree"),
        button(f"⚠️ {negative_label}", "disagree"),
        button("❓ Unsure", "unsure"),
    ]]
    return InlineKeyboardMarkup([*feedback, *_product_rows()])


def how_text() -> str:
    return (
        "<b>How the check works</b>\n\n"
        "1. Forward or paste the suspicious message.\n"
        "2. ScamShield looks for combinations of behaviour — payment pressure, "
        "credential requests, fulfilment, coercion, and other transaction mechanics.\n"
        "3. It returns the supported risk tier, why it matched, what it cannot prove, "
        "and what to preserve or report.\n\n"
        "A subject word alone is not enough, and a clean result is not a safety guarantee."
    )


async def cmd_how(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(how_text(), parse_mode=ParseMode.HTML)


def privacy_text() -> str:
    storage = (
        "Raw message samples are retained only when the operator explicitly enables "
        "SCAMSHIELD_STORE_RAW_SAMPLES; the production-safe default is off."
    )
    return (
        "<b>Privacy boundary</b>\n\n"
        "• Your submitted text is used to produce the reply.\n"
        "• Indicators and privacy-minimized assessment records may be retained for "
        "review; raw sample storage is off by default.\n"
        "• Verdict feedback stores only an opaque assessment reference, its tier, "
        "and your selected response — not your Telegram identity or message text.\n"
        "• Public API/MCP assessments are memory-only: no storage, no Palimpsest "
        "bridge, and no raw text or exact IOC values in their response.\n"
        f"• {html.escape(storage)}\n\n"
        "Do not submit passwords, OTPs, PINs, seed phrases, or material you are not "
        "authorized to share."
    )


async def cmd_privacy(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(privacy_text(), parse_mode=ParseMode.HTML)


def typologies_text() -> str:
    catalog = typology_catalog()
    lines = [
        "<b>Evidence typologies</b>",
        f"Pack {html.escape(catalog['version'])} • {catalog['source_count']} published sources",
        "",
    ]
    for item in catalog["typologies"]:
        lines.append(
            f"• <b>{html.escape(item['label'])}</b> "
            f"<i>({html.escape(item['dimension'])})</i>"
        )
    lines.extend([
        "",
        "These are resemblance hypotheses, not identity or guilt findings. Forward a "
        "message to see which evidence classes it actually supports.",
    ])
    return "\n".join(lines)


async def cmd_typologies(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(typologies_text(), parse_mode=ParseMode.HTML)


def explore_text() -> str:
    return (
        "<b>One evidence stack, three jobs</b>\n\n"
        "• <b>ScamShield</b> — triage a suspicious message here.\n"
        "• <b>Palimpsest</b> — inspect censorship, information-control, model-eval, "
        "and evidence-newsroom signals.\n"
        "• <b>NarcoScope</b> — inspect official drug-market records and "
        "the stories built from them.\n\n"
        "Open the products below or follow Evidence Signal for reviewed updates."
    )


async def cmd_explore(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        explore_text(), parse_mode=ParseMode.HTML, reply_markup=product_keyboard(),
    )


def help_text() -> str:
    steps = reporting_steps()
    india = steps["steps"][0]["action"]
    return (
        "<b>ScamShield commands</b>\n\n"
        "/start — scan a suspicious message\n"
        "/how — understand the evidence check\n"
        "/typologies — see covered pattern families\n"
        "/privacy — understand data handling\n"
        "/explore — open Palimpsest, NarcoScope, and Evidence Signal\n"
        "/help — show this guide\n\n"
        f"<b>Financial fraud in India:</b> {html.escape(india)}"
    )


async def cmd_help(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(help_text(), parse_mode=ParseMode.HTML)


def funnel_text() -> str:
    starts = STORE.product_event_digest("start")
    unsupported = STORE.product_event_digest("unsupported_input")
    feedback = STORE.assessment_feedback_digest()
    lines = ["<b>Privacy-safe product funnel · last 30 UTC days</b>"]
    lines.append("\n<b>Bot starts:</b>")
    lines.extend(
        f"• {html.escape(value)} — {count}" for value, count in starts
    )
    if not starts:
        lines.append("• none recorded")
    lines.append("\n<b>Unsupported inputs:</b>")
    lines.extend(
        f"• {html.escape(value)} — {count}" for value, count in unsupported
    )
    if not unsupported:
        lines.append("• none recorded")
    lines.append("\n<b>Assessment feedback:</b>")
    lines.extend(
        f"• {html.escape(tier)} / {html.escape(response)} — {count}"
        for tier, response, count in feedback
    )
    if not feedback:
        lines.append("• none recorded")
    lines.append("\nNo Telegram user IDs, submitted text, or exact IOCs are in this view.")
    return "\n".join(lines)


async def cmd_funnel(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    if (
        update.effective_user.id != OWNER_ID
        or update.effective_chat.type != "private"
    ):
        return
    await update.message.reply_text(funnel_text(), parse_mode=ParseMode.HTML)


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


async def cmd_coverage(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_user.id != OWNER_ID:
        return
    rows = STORE.coverage_digest()
    if not rows:
        await update.message.reply_text("No collection coverage recorded yet.")
        return
    body = "\n".join(
        f"{surface:<26} {(source or 'unlinked')[:12]:<12} "
        f"seen={messages} flagged={flagged} errors={errors}"
        for surface, source, messages, flagged, errors, _last_seen in rows[:100]
    )
    await update.message.reply_text(
        f"<pre>{html.escape(body)}</pre>", parse_mode=ParseMode.HTML,
    )


def _short_duration(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    minutes, _ = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m"
    hours, minutes = divmod(minutes, 60)
    if hours < 48:
        return f"{hours}h {minutes}m"
    days, hours = divmod(hours, 24)
    return f"{days}d {hours}h"


def monitor_text(*, now: int | None = None) -> str:
    state = STORE.monitor_state()
    if state is None:
        return (
            "<b>Telegram monitor · no heartbeat</b>\n\n"
            "The Telethon collector has not published runtime health yet. "
            "Check the service before assuming configured sources are covered."
        )
    current = int(time.time()) if now is None else now
    age = max(0, current - state["updated_at"])
    uptime = max(0, current - state["started_at"])
    reconcile_age = max(
        0,
        current - (state["last_reconcile_success_at"] or state["started_at"]),
    )
    candidate_age = max(
        0,
        current - (state["last_candidate_success_at"] or state["started_at"]),
    )
    maintenance_overdue = (
        reconcile_age > state["reconcile_interval_seconds"]
        or candidate_age > state["candidate_verify_interval_seconds"]
    )
    maintenance_failed = (
        state["reconcile_failure_streak"] > 0
        or state["candidate_failure_streak"] > 0
    )
    maintenance_starting = (
        state["last_reconcile_success_at"] == 0
        or state["last_candidate_success_at"] == 0
    )
    if age > 600:
        condition = "OFFLINE OR STALLED"
    elif age > 180:
        condition = "STALE"
    elif maintenance_failed:
        condition = "DEGRADED"
    elif maintenance_overdue:
        condition = "MAINTENANCE STALE"
    elif maintenance_starting:
        condition = "STARTING"
    else:
        condition = "HEALTHY"
    handled = state["live_completed"] + state["live_failed"]
    reconcile_success = (
        "not yet"
        if state["last_reconcile_success_at"] == 0
        else f"{_short_duration(reconcile_age)} ago"
    )
    candidate_success = (
        "not yet"
        if state["last_candidate_success_at"] == 0
        else f"{_short_duration(candidate_age)} ago"
    )
    return (
        f"<b>Telegram monitor · {condition}</b>\n\n"
        f"Heartbeat: {_short_duration(age)} ago · uptime {_short_duration(uptime)}\n"
        f"Sources: {state['resolved_sources']} resolved · "
        f"{state['unresolved_sources']} unresolved\n"
        f"Live since restart: {handled} handled · {state['live_failed']} failed\n"
        f"Queue: {state['live_queue_depth']}/{state['live_queue_capacity']} · "
        f"{state['live_deferred']} deferred to durable recovery\n"
        f"Recovery: {reconcile_success} · {state['last_reconciled']} message(s) · "
        f"failure streak {state['reconcile_failure_streak']}\n"
        f"Candidates: {candidate_success} · "
        f"{state['last_candidates_checked']} checked · "
        f"failure streak {state['candidate_failure_streak']}\n\n"
        "Aggregate operational data only; no source IDs or message contents."
    )


async def cmd_monitor(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    if (
        update.effective_user.id != OWNER_ID
        or update.effective_chat.type != "private"
    ):
        return
    await update.message.reply_text(monitor_text(), parse_mode=ParseMode.HTML)


async def cmd_liquidity(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_user.id != OWNER_ID:
        return
    try:
        day = parse_pulse_day(context.args)
        pulse = STORE.daily_liquidity_pulse(day)
    except (TypeError, ValueError) as exc:
        await update.message.reply_text(html.escape(str(exc)), parse_mode=ParseMode.HTML)
        return
    await update.message.reply_text(
        render_liquidity_pulse(pulse), parse_mode=ParseMode.HTML,
    )


async def cmd_review_amount(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
) -> None:
    """Persist one owner-reviewed amount without auto-reading message values."""
    if update.effective_user.id != OWNER_ID:
        return
    message = update.message
    reply = message.reply_to_message if message else None
    text = (reply.text or reply.caption or "") if reply else ""
    if not text.strip():
        await message.reply_text(review_usage(), parse_mode=ParseMode.HTML)
        return
    alert_review_id = review_id_from_alert(text)
    if alert_review_id:
        review_context = STORE.assessment_review_context_by_id(alert_review_id)
    else:
        source_context = ObservationContext.create(
            text,
            surface="private_submission",
            authorization="user_submitted",
            raw_source=f"telegram-user:{update.effective_user.id}",
        )
        if not source_context.source_pseudonym:
            await message.reply_text(
                "The production pseudonym key is unavailable; refusing monetary review."
            )
            return
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        review_context = STORE.assessment_review_context(
            digest,
            surface="private_submission",
            source_pseudonym=source_context.source_pseudonym,
        )
    if review_context is None:
        await message.reply_text(
            "Reply to a suspicious message scanned after liquidity tracking was enabled. "
            "Clean or previously unseen messages cannot become monetary evidence."
        )
        return
    try:
        observation = parse_review_observation(context.args, review_context)
        STORE.record_monetary_observation(
            observation, assessment_id=review_context["assessment_id"],
        )
    except (TypeError, ValueError) as exc:
        await message.reply_text(
            f"{html.escape(str(exc))}\n\n{review_usage()}",
            parse_mode=ParseMode.HTML,
        )
        return
    await message.reply_text(
        render_review_confirmation(observation), parse_mode=ParseMode.HTML,
    )


def _record_result(result, text: str) -> None:
    if result.iocs:
        STORE.record(result.iocs, sample=text if STORE_RAW_SAMPLES else "")
    if result.overall_tier == "CLEAN":
        STORE.record_coverage(result)
    else:
        STORE.record_analysis(result)


async def on_private(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    text = update.message.text or update.message.caption or ""
    if not text.strip():
        kind = unsupported_input_kind(update.message)
        try:
            STORE.record_product_event("unsupported_input", kind)
        except Exception as exc:
            log.warning("unsupported-input metric skipped: %s", exc)
        await update.message.reply_text(
            unsupported_input_text(kind),
            parse_mode=ParseMode.HTML,
            reply_markup=product_keyboard(),
        )
        return
    collection = ObservationContext.create(
        text,
        surface="private_submission",
        authorization="user_submitted",
        raw_source=f"telegram-user:{update.effective_user.id}",
    )
    result = await asyncio.to_thread(
        ANALYZER.analyze, text, collection=collection,
    )
    _record_result(result, text)
    await update.message.reply_text(render_analysis(result, surface="private_submission"),
                                    parse_mode=ParseMode.HTML,
                                    reply_markup=result_keyboard(result))


def unsupported_input_kind(message) -> str:
    """Classify only the media type; never inspect or persist the payload."""

    if getattr(message, "photo", None):
        return "photo"
    if getattr(message, "voice", None):
        return "voice"
    if getattr(message, "audio", None):
        return "audio"
    document = getattr(message, "document", None)
    if document is not None:
        mime = str(getattr(document, "mime_type", "") or "").lower()
        if mime == "application/pdf":
            return "pdf"
        if mime.startswith("image/"):
            return "image_document"
        return "document"
    if getattr(message, "video", None) or getattr(message, "video_note", None):
        return "video"
    if getattr(message, "sticker", None):
        return "sticker"
    if getattr(message, "contact", None):
        return "contact"
    return "non_text"


def unsupported_input_text(kind: str) -> str:
    labels = {
        "photo": "a photo or screenshot",
        "image_document": "an image file",
        "voice": "a voice note",
        "audio": "an audio file",
        "pdf": "a PDF",
        "document": "a document",
        "video": "a video",
        "sticker": "a sticker",
        "contact": "a contact card",
        "non_text": "a non-text message",
    }
    label = labels.get(kind, "a non-text message")
    return (
        f"<b>I received {html.escape(label)}, but this production check is text-only today.</b>\n\n"
        "Please paste the suspicious wording or resend it with a caption. "
        "Do not transcribe or submit passwords, OTPs, PINs, or seed phrases.\n\n"
        "Screenshot OCR, QR extraction, and voice transcription are being added only "
        "with an explicit privacy boundary; I will not pretend this upload was checked."
    )


async def on_feedback(update: Update, _: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    match = _FEEDBACK_RE.fullmatch(str(getattr(query, "data", "") or ""))
    if match is None:
        await query.answer("That feedback link is invalid or expired.", show_alert=True)
        return
    assessment_id, tier, response = match.groups()
    try:
        STORE.record_assessment_feedback(
            assessment_id,
            original_tier=tier,
            response=response,
        )
    except Exception as exc:
        log.warning("assessment feedback failed: %s", exc)
        await query.answer("I could not record that safely. Please try again.", show_alert=True)
        return
    messages = {
        "agree": "Thanks — recorded without your identity or message text.",
        "disagree": "Thanks — this is now counted as a possible miss.",
        "unsure": "Thanks — uncertainty is useful feedback too.",
    }
    await query.answer(messages[response])
    try:
        await query.edit_message_reply_markup(reply_markup=product_keyboard())
    except Exception as exc:
        log.warning("feedback keyboard cleanup skipped: %s", exc)


async def on_group(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    msg = update.message
    text = (msg.text or msg.caption or "") if msg else ""
    if not text.strip():
        return
    collection = ObservationContext.create(
        text,
        surface="guardian_group",
        authorization="administrator_authorized",
        raw_source=str(msg.chat_id),
    )
    result = await asyncio.to_thread(
        ANALYZER.analyze, text, collection=collection,
    )
    _record_result(result, text)
    action = POLICY.get(result.overall_tier, "ignore")

    if action == "ignore":
        return
    if action == "flag":
        await msg.reply_text(
            render_analysis(result, surface="guardian_group"),
            parse_mode=ParseMode.HTML,
        )
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
                f"[{msg.chat.title}] {action} on {result.overall_tier} "
                f"(score {result.overall_score}) from "
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


async def _configure_public_surface(app: Application) -> None:
    """Keep BotFather-facing discovery copy in sync with shipped commands."""
    try:
        await app.bot.set_my_name("ScamShield — Message Risk Check")
        await app.bot.set_my_short_description(
            "Forward a suspicious message. Get an evidence-bounded risk readout and reporting steps."
        )
        await app.bot.set_my_description(
            "ScamShield checks user-submitted messages for supported scam, money-mule, "
            "phishing, impersonation, illicit-market, and trafficking-risk patterns. "
            "It explains what matched, what the evidence cannot prove, and what to do next. "
            "Private-chat Shield mode is on; group monitoring is separately gated."
        )
        await app.bot.set_my_commands(PUBLIC_COMMANDS)
    except Exception as exc:
        log.warning("Telegram discovery metadata update skipped: %s", exc)
    await _warn_on_guardian_mismatch(app)


def main() -> None:
    if not TOKEN:
        raise SystemExit("Set SCAMSHIELD_TOKEN (from @BotFather) first.")
    app = (Application.builder().token(TOKEN)
           .post_init(_configure_public_surface).build())
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("how", cmd_how))
    app.add_handler(CommandHandler("typologies", cmd_typologies))
    app.add_handler(CommandHandler("privacy", cmd_privacy))
    app.add_handler(CommandHandler("explore", cmd_explore))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("digest", cmd_digest))
    app.add_handler(CommandHandler("coverage", cmd_coverage))
    app.add_handler(CommandHandler("monitor", cmd_monitor))
    app.add_handler(CommandHandler("liquidity", cmd_liquidity))
    app.add_handler(CommandHandler("review_amount", cmd_review_amount))
    app.add_handler(CommandHandler("funnel", cmd_funnel))
    app.add_handler(CallbackQueryHandler(on_feedback, pattern=r"^feedback:"))
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
