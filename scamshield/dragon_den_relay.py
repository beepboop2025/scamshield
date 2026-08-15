"""Raw Dragon Den relay for the authenticated Telethon monitor.

Telegram bots cannot observe arbitrary third-party public channels.  The
existing ScamShield user session can, so this relay records only Telegram
coordinates, posts the mandatory warning with the dedicated bot, and asks
Telethon to perform an attribution-preserving native forward.  Analysis stays
in the monitor's separate live queue and never gates this path.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request
from contextlib import suppress
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping

from telethon import errors

from .dragon_den import (
    DeliveryBatch,
    DragonDenError,
    DragonDenOutbox,
    DragonDenRoutes,
    canonical_observed_at,
    disclaimer_text,
    load_routes,
)
from .telegram_collector import ResolvedSource


NoticeSender = Callable[..., Awaitable[int]]


class DragonDenBotAPIError(RuntimeError):
    """A token-redacted Bot API failure."""

    def __init__(
        self,
        code: str,
        *,
        retry_after: int = 0,
        description: str = "",
    ) -> None:
        super().__init__(code)
        self.code = code
        self.retry_after = max(0, int(retry_after))
        self.description = description[:240]


def _bot_api_call(
    token: str,
    method: str,
    payload: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Call Telegram without ever placing the token in an exception message."""

    encoded: dict[str, str] = {}
    for key, value in payload.items():
        if isinstance(value, bool):
            encoded[key] = "true" if value else "false"
        elif isinstance(value, (dict, list)):
            encoded[key] = json.dumps(value, separators=(",", ":"))
        else:
            encoded[key] = str(value)
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/{method}",
        data=urllib.parse.urlencode(encoded).encode("utf-8"),
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read(1024 * 1024)
    except urllib.error.HTTPError as exc:
        try:
            failure = json.loads(exc.read(64 * 1024).decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            failure = {}
        parameters = failure.get("parameters", {})
        retry_after = (
            parameters.get("retry_after", 0)
            if isinstance(parameters, dict)
            else 0
        )
        raise DragonDenBotAPIError(
            f"HTTP_{exc.code}",
            retry_after=retry_after if isinstance(retry_after, int) else 0,
            description=(
                failure.get("description", "")
                if isinstance(failure, dict)
                else ""
            ),
        ) from None
    except OSError as exc:
        raise DragonDenBotAPIError(type(exc).__name__) from None
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise DragonDenBotAPIError("INVALID_RESPONSE") from None
    if not isinstance(value, dict) or value.get("ok") is not True:
        parameters = value.get("parameters", {}) if isinstance(value, dict) else {}
        retry_after = (
            parameters.get("retry_after", 0)
            if isinstance(parameters, dict)
            else 0
        )
        raise DragonDenBotAPIError(
            str(value.get("error_code", "BOT_API_ERROR"))
            if isinstance(value, dict)
            else "BOT_API_ERROR",
            retry_after=retry_after if isinstance(retry_after, int) else 0,
            description=str(value.get("description", ""))
            if isinstance(value, dict)
            else "",
        )
    result = value.get("result")
    if not isinstance(result, dict):
        raise DragonDenBotAPIError("MISSING_RESULT")
    return result


def _permanent_forward_error(exc: BaseException) -> bool:
    name = type(exc).__name__
    if name in {
        "ChannelPrivateError",
        "ChatForwardsRestrictedError",
        "MessageIdInvalidError",
        "MessageIdsEmptyError",
        "PeerIdInvalidError",
    }:
        return True
    message = str(exc).casefold()
    return any(
        fragment in message
        for fragment in (
            "content is protected",
            "forwards restricted",
            "message id invalid",
            "message was deleted",
        )
    )


def _tombstone_text(batch: DeliveryBatch, code: str) -> str:
    return (
        f"⚠️ RAW FORWARD UNAVAILABLE · {batch.receipt_label}\n\n"
        "Telegram would not forward this source post. It may be protected, "
        "deleted, or unavailable to the monitoring account. The relay did not "
        "download, copy, or bypass the source restriction.\n"
        f"Reason class: {code[:120]}"
    )


class DragonDenTelethonRelay:
    """Durable raw fan-out owned by the already-authorized monitor session."""

    def __init__(
        self,
        *,
        client: Any,
        routes: DragonDenRoutes,
        outbox: DragonDenOutbox,
        token: str,
        protect_content: bool,
        notice_sender: NoticeSender | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        if not token or ":" not in token:
            raise DragonDenError("Dragon Den relay token is missing or malformed")
        self.client = client
        self.routes = routes
        self.outbox = outbox
        self.token = token
        self.protect_content = protect_content
        self.notice_sender = notice_sender or self._bot_notice
        self.log = logger or logging.getLogger("scamshield.dragon_den_relay")
        self.worker: asyncio.Task[Any] | None = None
        self.enqueued = 0
        self.completed = 0
        self.unforwardable = 0
        self.failed = 0
        self.active_route_sources = 0
        self.missing_route_sources = len(routes.sources)

    @classmethod
    def from_environment(
        cls,
        client: Any,
        environment: Mapping[str, str] | None = None,
        *,
        logger: logging.Logger | None = None,
    ) -> DragonDenTelethonRelay | None:
        env = os.environ if environment is None else environment
        enabled = env.get("DRAGON_DEN_RELAY_ENABLED", "0").strip()
        if enabled not in {"0", "1"}:
            raise DragonDenError("DRAGON_DEN_RELAY_ENABLED must be 0 or 1")
        if enabled == "0":
            return None
        protect = env.get("DRAGON_DEN_PROTECT_CONTENT", "1").strip()
        if protect not in {"0", "1"}:
            raise DragonDenError("DRAGON_DEN_PROTECT_CONTENT must be 0 or 1")
        token = env.get("DRAGON_DEN_BOT_TOKEN", "").strip()
        if token == env.get("SCAMSHIELD_TOKEN", "").strip():
            raise DragonDenError("Dragon Den must use a dedicated Bot API token")
        routes = load_routes(
            Path(
                env.get(
                    "DRAGON_DEN_ROUTES_FILE",
                    "/etc/scamshield/dragon-den-routes.json",
                )
            ).expanduser()
        )
        outbox = DragonDenOutbox(
            Path(
                env.get(
                    "DRAGON_DEN_DB",
                    "/var/lib/scamshield/dragon-den/dragon-den.db",
                )
            ).expanduser()
        )
        return cls(
            client=client,
            routes=routes,
            outbox=outbox,
            token=token,
            protect_content=protect == "1",
            logger=logger,
        )

    async def _bot_notice(
        self,
        *,
        chat_id: str,
        text: str,
        reply_to_message_id: int | None = None,
    ) -> int:
        payload: dict[str, Any] = {
            "chat_id": chat_id,
            "text": text,
            "disable_notification": True,
            "protect_content": self.protect_content,
            "link_preview_options": {"is_disabled": True},
        }
        if reply_to_message_id is not None:
            payload["reply_parameters"] = {
                "message_id": reply_to_message_id,
                "allow_sending_without_reply": True,
            }
        result = await asyncio.to_thread(
            _bot_api_call,
            self.token,
            "sendMessage",
            payload,
        )
        message_id = result.get("message_id")
        if type(message_id) is not int or message_id <= 0:
            raise DragonDenBotAPIError("INVALID_MESSAGE_ID")
        return message_id

    async def _notice_with_fallback(
        self,
        *,
        chat_id: str,
        text: str,
        reply_to_message_id: int | None = None,
    ) -> int:
        try:
            return await self.notice_sender(
                chat_id=chat_id,
                text=text,
                reply_to_message_id=reply_to_message_id,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.log.warning(
                "Dragon Den bot notice failed; using monitor-session fallback (%s)",
                type(exc).__name__,
            )
        kwargs: dict[str, Any] = {
            "entity": chat_id,
            "message": text,
            "silent": True,
            "link_preview": False,
        }
        if reply_to_message_id is not None:
            kwargs["reply_to"] = reply_to_message_id
        message = await self.client.send_message(**kwargs)
        message_id = getattr(message, "id", None)
        if type(message_id) is not int or message_id <= 0:
            raise DragonDenError("fallback notice did not return a message ID")
        return message_id

    def enqueue(self, source: ResolvedSource, message: Any) -> tuple[str, ...]:
        """Persist routing coordinates before the analysis queue sees a post."""

        if source.surface != "public_channel" or not source.reference.startswith("@"):
            return ()
        destinations = self.routes.destinations_for(source.reference)
        if not destinations:
            return ()
        message_id = getattr(message, "id", None)
        if type(message_id) is not int:
            raise DragonDenError("Telethon message ID is missing")
        edit_date = getattr(message, "edit_date", None)
        receipts = self.outbox.enqueue(
            source=source.reference,
            source_chat_id=source.peer_id,
            source_message_id=message_id,
            revision=canonical_observed_at(edit_date) if edit_date else "",
            media_group_id=str(getattr(message, "grouped_id", None) or ""),
            observed_at=canonical_observed_at(getattr(message, "date", None)),
            destinations=destinations,
        )
        self.enqueued += len(receipts)
        return receipts

    def update_source_coverage(
        self,
        sources: tuple[ResolvedSource, ...],
    ) -> None:
        """Track aggregate route coverage without exposing source identities."""

        active = {
            source.reference.casefold()
            for source in sources
            if source.surface == "public_channel"
            and source.reference.startswith("@")
        }
        configured = set(self.routes.sources)
        self.active_route_sources = len(configured & active)
        self.missing_route_sources = len(configured - active)

    async def _forward(self, batch: DeliveryBatch) -> list[int]:
        first = batch.first
        message_ids = [item.source_message_id for item in batch.deliveries]
        source_peer: str | int = first.source_chat_id
        if first.source_chat_id.lstrip("-").isdigit():
            source_peer = int(first.source_chat_id)
        result = await self.client.forward_messages(
            entity=first.destination_chat_id,
            messages=message_ids,
            from_peer=source_peer,
            silent=True,
            as_album=len(message_ids) > 1,
        )
        forwarded = list(result) if isinstance(result, (list, tuple)) else [result]
        forwarded_ids = [getattr(message, "id", None) for message in forwarded]
        if (
            len(forwarded_ids) != len(message_ids)
            or any(type(message_id) is not int or message_id <= 0 for message_id in forwarded_ids)
        ):
            raise DragonDenError("Telethon forward result did not match the batch")
        return [int(message_id) for message_id in forwarded_ids]

    async def _deliver(self, batch: DeliveryBatch) -> None:
        first = batch.first
        if first.header_message_id is None:
            header_id = await self._notice_with_fallback(
                chat_id=first.destination_chat_id,
                text=disclaimer_text(batch),
            )
            self.outbox.record_header(batch, header_id)
            batch = DeliveryBatch(
                tuple(
                    type(item)(**{**item.__dict__, "header_message_id": header_id})
                    for item in batch.deliveries
                )
            )
            first = batch.first
        try:
            forwarded_ids = await self._forward(batch)
        except asyncio.CancelledError:
            raise
        except errors.FloodWaitError as exc:
            self.outbox.retry(
                batch,
                type(exc).__name__,
                retry_after=max(1, int(getattr(exc, "seconds", 1))),
            )
            self.failed += len(batch.deliveries)
            return
        except Exception as exc:
            if _permanent_forward_error(exc):
                with suppress(Exception):
                    await self._notice_with_fallback(
                        chat_id=first.destination_chat_id,
                        text=_tombstone_text(batch, type(exc).__name__),
                        reply_to_message_id=first.header_message_id,
                    )
                self.outbox.unforwardable(batch, type(exc).__name__)
                self.unforwardable += len(batch.deliveries)
            else:
                self.outbox.retry(batch, type(exc).__name__)
                self.failed += len(batch.deliveries)
            return
        self.outbox.complete(batch, forwarded_ids)
        self.completed += len(batch.deliveries)

    async def deliver_once(self) -> bool:
        batch = self.outbox.claim()
        if batch is None:
            return False
        try:
            await self._deliver(batch)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.outbox.retry(batch, type(exc).__name__)
            self.failed += len(batch.deliveries)
            self.log.exception(
                "Dragon Den delivery failed before forward (%s)",
                type(exc).__name__,
            )
        return True

    async def _delivery_loop(self) -> None:
        while True:
            if not await self.deliver_once():
                await asyncio.sleep(0.5)

    async def verify_destinations(self) -> None:
        """Require the Telethon owner/admin path; bot failures retain fallback."""

        for destination in self.routes.destinations.values():
            entity = await self.client.get_entity(destination.chat_id)
            is_channel = bool(getattr(entity, "broadcast", False))
            rights = getattr(entity, "admin_rights", None)
            can_post = bool(
                getattr(entity, "creator", False)
                or (rights is not None and getattr(rights, "post_messages", False))
            )
            if not is_channel or not can_post:
                raise DragonDenError(
                    f"monitor session cannot post to destination {destination.id}"
                )

    async def start(self) -> asyncio.Task[Any]:
        await self.verify_destinations()
        if self.worker is None or self.worker.done():
            self.worker = asyncio.create_task(
                self._delivery_loop(),
                name="dragon-den-telethon-delivery",
            )
        return self.worker

    async def shutdown(self) -> None:
        if self.worker is not None:
            self.worker.cancel()
            await asyncio.gather(self.worker, return_exceptions=True)
            self.worker = None
        self.outbox.close()

    def status_text(self) -> str:
        counts = self.outbox.status_counts()
        queue = ",".join(
            f"{status.lower()}={count}" for status, count in sorted(counts.items())
        ) or "empty"
        return (
            f"raw[{queue};routes={self.active_route_sources}/"
            f"{len(self.routes.sources)};missing_routes={self.missing_route_sources};"
            f"enqueued={self.enqueued};completed={self.completed};"
            f"unforwardable={self.unforwardable};failed={self.failed}]"
        )


__all__ = [
    "DragonDenBotAPIError",
    "DragonDenTelethonRelay",
]
