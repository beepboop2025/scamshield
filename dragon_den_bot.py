"""Whispers from the Dragon Den: raw public-channel mirror.

The dedicated Bot API identity must be an administrator in every configured
source and destination channel. Incoming source posts are queued by Telegram
coordinates, fanned out with native forwarding, and analyzed independently by
ScamShield for the private Palimpsest review path. Classification never gates
or rewrites the raw forward.
"""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import suppress
from datetime import timedelta
from pathlib import Path
from typing import Any

from telegram import LinkPreviewOptions, ReplyParameters, Update
from telegram.error import BadRequest, Forbidden, NetworkError, RetryAfter
from telegram.ext import Application, ContextTypes, TypeHandler

from scamshield.analysis import AnalysisService, ObservationContext
from scamshield.dragon_den import (
    DeliveryBatch,
    DragonDenError,
    DragonDenOutbox,
    canonical_observed_at,
    disclaimer_text,
    load_routes,
    source_from_chat,
)
from scamshield.envload import load_env


load_env()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
for _noisy in ("httpx", "httpcore", "telegram.ext.Application"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)
log = logging.getLogger("scamshield.dragon_den_bot")

TOKEN = os.environ.get("DRAGON_DEN_BOT_TOKEN", "").strip()
ROUTES_FILE = Path(
    os.environ.get("DRAGON_DEN_ROUTES_FILE", "dragon-den-routes.json")
).expanduser()
OUTBOX_PATH = Path(
    os.environ.get("DRAGON_DEN_DB", "dragon-den.db")
).expanduser()
PROTECT_CONTENT = os.environ.get("DRAGON_DEN_PROTECT_CONTENT", "1") == "1"


class PartialForwardError(RuntimeError):
    """Telegram skipped one or more members of an album."""


class DragonDenRuntime:
    def __init__(self) -> None:
        self.routes = load_routes(ROUTES_FILE)
        self.outbox = DragonDenOutbox(OUTBOX_PATH)
        self.analyzer: AnalysisService | None = None
        self.analysis_init_lock = asyncio.Lock()
        self.analysis_retry_at = 0.0
        self.analysis_slots = asyncio.Semaphore(4)
        self.worker: asyncio.Task[Any] | None = None

    def close(self) -> None:
        self.outbox.close()


def _runtime(context: ContextTypes.DEFAULT_TYPE) -> DragonDenRuntime:
    runtime = context.application.bot_data.get("dragon_den_runtime")
    if not isinstance(runtime, DragonDenRuntime):
        raise RuntimeError("Dragon Den runtime is not initialized")
    return runtime


def _retry_seconds(exc: RetryAfter) -> int:
    value = exc.retry_after
    if isinstance(value, timedelta):
        return max(1, int(value.total_seconds()))
    return max(1, int(value))


async def _analysis_service(runtime: DragonDenRuntime) -> AnalysisService | None:
    """Initialize analysis lazily so it can never gate raw mirror startup."""

    if runtime.analyzer is not None:
        return runtime.analyzer
    loop = asyncio.get_running_loop()
    if loop.time() < runtime.analysis_retry_at:
        return None
    async with runtime.analysis_init_lock:
        if runtime.analyzer is not None:
            return runtime.analyzer
        now = loop.time()
        if now < runtime.analysis_retry_at:
            return None
        runtime.analysis_retry_at = now + 60.0
        try:
            runtime.analyzer = await asyncio.to_thread(
                AnalysisService.from_environment
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning(
                "ScamShield side analysis unavailable; raw mirror remains live (%s)",
                type(exc).__name__,
            )
            return None
        log.info("ScamShield side analysis initialized")
        return runtime.analyzer


def _permanent_forward_error(exc: BadRequest) -> bool:
    message = str(exc).casefold()
    return any(fragment in message for fragment in (
        "message to forward not found",
        "message can't be forwarded",
        "message can not be forwarded",
        "protected content",
        "message_id_invalid",
    ))


async def _send_tombstone(bot: Any, batch: DeliveryBatch, code: str) -> None:
    first = batch.first
    text = (
        f"⚠️ RAW FORWARD UNAVAILABLE · {batch.receipt_label}\n\n"
        "Telegram would not forward this source post. It may be protected, "
        "deleted, unavailable to the bot, or a non-forwardable service post. "
        "The mirror did not download, copy, or bypass the source restriction.\n"
        f"Reason class: {code}"
    )
    kwargs: dict[str, Any] = {
        "chat_id": first.destination_chat_id,
        "text": text,
        "disable_notification": True,
        "link_preview_options": LinkPreviewOptions(is_disabled=True),
    }
    if first.header_message_id is not None:
        kwargs["reply_parameters"] = ReplyParameters(
            message_id=first.header_message_id,
            allow_sending_without_reply=True,
        )
    await bot.send_message(**kwargs)


async def _deliver(bot: Any, runtime: DragonDenRuntime, batch: DeliveryBatch) -> None:
    first = batch.first
    try:
        if first.header_message_id is None:
            header = await bot.send_message(
                chat_id=first.destination_chat_id,
                text=disclaimer_text(batch),
                disable_notification=True,
                protect_content=PROTECT_CONTENT,
                link_preview_options=LinkPreviewOptions(is_disabled=True),
            )
            runtime.outbox.record_header(batch, int(header.message_id))
            batch = DeliveryBatch(tuple(
                type(item)(**{**item.__dict__, "header_message_id": int(header.message_id)})
                for item in batch.deliveries
            ))
            first = batch.first

        source_message_ids = [
            item.source_message_id for item in batch.deliveries
        ]
        if len(source_message_ids) == 1:
            result = await bot.forward_message(
                chat_id=first.destination_chat_id,
                from_chat_id=first.source_chat_id,
                message_id=source_message_ids[0],
                disable_notification=True,
                protect_content=PROTECT_CONTENT,
            )
            destination_message_ids = [int(result.message_id)]
        else:
            forwarded = await bot.forward_messages(
                chat_id=first.destination_chat_id,
                from_chat_id=first.source_chat_id,
                message_ids=source_message_ids,
                disable_notification=True,
                protect_content=PROTECT_CONTENT,
            )
            destination_message_ids = [int(item.message_id) for item in forwarded]
        if len(destination_message_ids) != len(source_message_ids):
            raise PartialForwardError("Telegram skipped part of a raw album")
        runtime.outbox.complete(batch, destination_message_ids)
        log.info(
            "raw receipt %s delivered to route %s (%d source post(s))",
            batch.receipt_label,
            first.destination_id,
            len(batch.deliveries),
        )
    except RetryAfter as exc:
        runtime.outbox.retry(
            batch, "RetryAfter", retry_after=_retry_seconds(exc),
        )
    except BadRequest as exc:
        code = type(exc).__name__
        if _permanent_forward_error(exc):
            with suppress(Exception):
                await _send_tombstone(bot, batch, code)
            runtime.outbox.unforwardable(batch, code)
        else:
            runtime.outbox.retry(batch, code)
    except PartialForwardError as exc:
        with suppress(Exception):
            await _send_tombstone(bot, batch, type(exc).__name__)
        runtime.outbox.unforwardable(batch, type(exc).__name__)
    except (Forbidden, NetworkError) as exc:
        runtime.outbox.retry(batch, type(exc).__name__)
    except asyncio.CancelledError:
        runtime.outbox.retry(batch, "CancelledError", retry_after=1)
        raise
    except Exception as exc:
        log.exception(
            "raw receipt %s delivery failed (%s)",
            batch.receipt_label,
            type(exc).__name__,
        )
        runtime.outbox.retry(batch, type(exc).__name__)


async def _delivery_loop(app: Application, runtime: DragonDenRuntime) -> None:
    while True:
        batch = runtime.outbox.claim()
        if batch is None:
            await asyncio.sleep(0.5)
            continue
        await _deliver(app.bot, runtime, batch)


async def _analyze(
    runtime: DragonDenRuntime,
    *,
    text: str,
    source_chat_id: str,
    observed_at: str,
) -> None:
    """Run the full ScamShield/Palimpsest path without gating raw delivery."""

    if not text.strip():
        return
    try:
        analyzer = await _analysis_service(runtime)
        if analyzer is None:
            return
        collection = ObservationContext.create(
            text,
            surface="public_channel",
            authorization="public",
            raw_source=source_chat_id,
            pseudonym_key=os.environ.get("SCAMSHIELD_PSEUDONYM_KEY", ""),
            observed_at=observed_at,
        )
        async with runtime.analysis_slots:
            result = await asyncio.to_thread(
                analyzer.analyze,
                text,
                collection=collection,
            )
        log.info(
            "ScamShield side analysis completed: tier=%s bridge=%s",
            result.overall_tier,
            result.bridge.status,
        )
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        # Raw publication is already queued; analysis failure is observable but
        # can never delete, delay, or mutate that delivery.
        log.warning("ScamShield side analysis failed (%s)", type(exc).__name__)


async def on_update(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.channel_post or update.edited_channel_post
    if message is None:
        return
    runtime = _runtime(context)
    try:
        source = source_from_chat(message.chat)
        destinations = runtime.routes.destinations_for(source)
        if not destinations:
            log.warning("ignored channel update outside the raw-mirror allowlist")
            return
        observed_at = canonical_observed_at(message.date)
        revision = (
            canonical_observed_at(message.edit_date)
            if update.edited_channel_post is not None and message.edit_date is not None
            else ""
        )
        runtime.outbox.enqueue(
            source=source,
            source_chat_id=str(message.chat_id),
            source_message_id=int(message.message_id),
            revision=revision,
            media_group_id=str(message.media_group_id or ""),
            observed_at=observed_at,
            destinations=destinations,
        )
    except (DragonDenError, TypeError, ValueError) as exc:
        log.warning("rejected raw-mirror update (%s)", type(exc).__name__)
        return

    raw_text = message.text or message.caption or ""
    if raw_text.strip():
        context.application.create_task(
            _analyze(
                runtime,
                text=raw_text,
                source_chat_id=str(message.chat_id),
                observed_at=observed_at,
            ),
            update=update,
            name=f"dragon-den-analysis-{message.chat_id}-{message.message_id}",
        )


async def _verify_admin(bot: Any, chat_id: str, *, purpose: str) -> None:
    me = await bot.get_me()
    member = await bot.get_chat_member(chat_id, me.id)
    status = str(member.status).lower()
    if status not in {"administrator", "creator", "owner"}:
        raise RuntimeError(f"Dragon Den bot is not an administrator in {purpose}")
    if purpose.startswith("destination") and getattr(
        member, "can_post_messages", True
    ) is False:
        raise RuntimeError(f"Dragon Den bot cannot post in {purpose}")


async def post_init(app: Application) -> None:
    runtime = DragonDenRuntime()
    app.bot_data["dragon_den_runtime"] = runtime
    await app.bot.set_my_name("Whispers from the Dragon Den")
    await app.bot.set_my_short_description(
        "Raw, automatic forwards from configured public channels. Unverified."
    )
    await app.bot.set_my_description(
        "Whispers from the Dragon Den mirrors every post from an explicit public-"
        "channel allowlist into configured destination channels. Posts are raw, "
        "automatic, and unverified; they may be false or malicious. Palimpsest "
        "publishes only a separately reviewed and sanitized projection."
    )
    for destination in runtime.routes.destinations.values():
        await _verify_admin(
            app.bot, destination.chat_id, purpose=f"destination {destination.id}"
        )
    for route in runtime.routes.sources.values():
        await _verify_admin(app.bot, route.source, purpose=f"source {route.source}")
    runtime.worker = app.create_task(
        _delivery_loop(app, runtime), name="dragon-den-delivery"
    )
    log.info(
        "Dragon Den ready: %d public source(s), %d destination(s), protect=%s",
        len(runtime.routes.sources),
        len(runtime.routes.destinations),
        PROTECT_CONTENT,
    )


async def post_shutdown(app: Application) -> None:
    runtime = app.bot_data.get("dragon_den_runtime")
    if not isinstance(runtime, DragonDenRuntime):
        return
    if runtime.worker is not None:
        runtime.worker.cancel()
        await asyncio.gather(runtime.worker, return_exceptions=True)
    runtime.close()


def main() -> None:
    if not TOKEN:
        raise SystemExit("Set DRAGON_DEN_BOT_TOKEN from the dedicated @BotFather bot")
    if os.environ.get("DRAGON_DEN_PROTECT_CONTENT", "1") not in {"0", "1"}:
        raise SystemExit("DRAGON_DEN_PROTECT_CONTENT must be 0 or 1")
    app = (
        Application.builder()
        .token(TOKEN)
        .post_init(post_init)
        .post_shutdown(post_shutdown)
        .build()
    )
    app.add_handler(TypeHandler(Update, on_update))
    app.run_polling(
        allowed_updates=["channel_post", "edited_channel_post"],
        drop_pending_updates=False,
    )


if __name__ == "__main__":
    main()
