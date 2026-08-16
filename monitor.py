"""Always-on ScamShield collector for public or operator-authorized Telegram.

``login.py`` creates one persistent Telethon session.  This process only
connects with that saved session; it never prompts for a phone, OTP, or 2FA
password under systemd.  For every configured source it combines live updates,
Telethon update catch-up, and a bounded durable history cursor.

The source registry remains an allowlist. Public references discovered inside
flagged messages enter a private candidate queue. The monitor may resolve those
handles without joining them so a separate, credential-free policy job can
promote only corroborated public channels. Media is not downloaded; text and
captions alone are classified.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
import urllib.parse
import urllib.request
from contextlib import suppress

from telethon import TelegramClient, errors, events, types, utils
from telethon.tl.functions.channels import JoinChannelRequest

from scamshield.analysis import AnalysisService, ObservationContext
from scamshield.dragon_den import DragonDenError
from scamshield.dragon_den_relay import DragonDenTelethonRelay
from scamshield.envload import load_env
from scamshield.iocstore import IocStore
from scamshield.runtime import channels_file_path, session_base_path
from scamshield.service_health import notify_systemd, watchdog_interval
from scamshield.social_observation_spool import SocialObservationSpool
from scamshield.telegram_collector import ResolvedSource, TelegramCollector
from scamshield.telegram_sources import (
    MonitorSettings,
    normalize_source_reference,
    parse_source_registry,
    source_reference_digest,
)

load_env()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("scamshield.monitor")

SESSION = session_base_path()
CHANNELS_FILE = channels_file_path()
SOCIAL_REVISION_LOOKBACK = 50


def alert_owner(text: str) -> None:
    token = os.environ.get("SCAMSHIELD_TOKEN")
    owner = os.environ.get("SCAMSHIELD_OWNER_ID")
    if not (token and owner):
        return
    data = urllib.parse.urlencode({"chat_id": owner, "text": text}).encode()
    try:
        urllib.request.urlopen(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=data,
            timeout=15,
        )
    except Exception as exc:
        # urllib exceptions can echo the URL, which contains the bot token.
        log.warning("owner alert failed (%s)", type(exc).__name__)


class MonitorRuntime:
    def __init__(
        self,
        *,
        client: TelegramClient,
        collector: TelegramCollector,
        settings: MonitorSettings,
        pseudonym_key: str,
        dragon_den_relay: DragonDenTelethonRelay | None = None,
        social_spool: SocialObservationSpool | None = None,
    ):
        self.client = client
        self.collector = collector
        self.settings = settings
        self.pseudonym_key = pseudonym_key
        self.dragon_den_relay = dragon_den_relay
        self.social_spool = social_spool
        # refresh_sources() closes this gate while either reviewed allowlist is
        # being refreshed. Tests and direct runtime users start ready; the
        # production process refreshes before registering live workers.
        self.social_authorization_ready = social_spool is not None
        self.sources_by_reference: dict[str, ResolvedSource] = {}
        self.sources_by_peer: dict[str, ResolvedSource] = {}
        self.failed_references: set[str] = set()
        self._message_handler = self._handle_message
        self._deleted_handler = self._handle_deleted
        self._event_handlers: list[tuple[object, object]] = []
        self.live_queue: asyncio.Queue[tuple[ResolvedSource, object]] = asyncio.Queue(
            maxsize=settings.live_queue_size
        )
        self.social_queue: asyncio.Queue[
            tuple[str, ResolvedSource, object]
        ] = asyncio.Queue(maxsize=settings.live_queue_size)
        self.started_at = int(time.time())
        self.live_enqueued = 0
        self.live_completed = 0
        self.live_failed = 0
        self.live_deferred = 0
        self.social_captured = 0
        self.social_failed = 0
        self.social_deferred = 0
        self.last_reconciled = 0
        self.last_reconcile_success_at = 0
        self.reconcile_failure_streak = 0
        self.last_candidates_checked = 0
        self.last_candidate_success_at = 0
        self.candidate_failure_streak = 0

    @property
    def sources(self) -> tuple[ResolvedSource, ...]:
        return tuple(self.sources_by_peer.values())

    async def _resolve(self, reference: str) -> ResolvedSource:
        lookup: str | int = reference if reference.startswith("@") else int(reference)
        try:
            input_entity = await self.client.get_input_entity(lookup)
            entity = await self.client.get_entity(input_entity)
        except ValueError:
            if isinstance(lookup, int):
                # A private source joined in an official client belongs to the
                # account, but this Telethon session may not have its access
                # hash cached until dialogs are synchronized once.
                await self.client.get_dialogs(limit=500)
                input_entity = await self.client.get_input_entity(lookup)
                entity = await self.client.get_entity(input_entity)
            else:
                entity = await self.client.get_entity(lookup)

        is_public = (
            isinstance(entity, types.Channel)
            and bool(getattr(entity, "username", None))
            and getattr(entity, "broadcast", None) is True
            and getattr(entity, "megagroup", False) is False
        )
        surface = "public_channel" if is_public else "authorized_private_channel"
        authorization = "public" if is_public else "operator_authorized"
        peer_id = str(utils.get_peer_id(entity))
        context = ObservationContext.create(
            "",
            surface=surface,
            authorization=authorization,
            raw_source=peer_id,
            pseudonym_key=self.pseudonym_key,
        )
        source = ResolvedSource(
            reference=reference,
            reference_digest=source_reference_digest(reference),
            peer_id=peer_id,
            source_key=context.source_pseudonym,
            surface=surface,
            authorization=authorization,
            entity=entity,
        )
        self.collector.activate_source(source.source_key)
        if is_public and self.settings.auto_join_public:
            try:
                await self.client(JoinChannelRequest(entity))
            except errors.UserAlreadyParticipantError:
                pass
            except errors.RPCError as exc:
                # A public channel can still be readable without a successful
                # join. Reconciliation will make the actual coverage visible.
                log.warning(
                    "public-source join was not completed for %s (%s)",
                    source.reference_digest,
                    type(exc).__name__,
                )
        self.collector.store.register_collector_source(
            source.source_key,
            configured_ref_sha256=source.reference_digest,
            surface=source.surface,
            authorization=source.authorization,
        )
        with suppress(Exception):
            self.collector.store.set_source_candidate_status(reference, "APPROVED")
        return source

    async def _reattest_social_source(
        self,
        source: ResolvedSource,
    ) -> ResolvedSource:
        """Resolve a reviewed handle again and enforce its pinned channel identity."""

        reference = normalize_source_reference(source.reference)
        if not reference.startswith("@"):
            raise ValueError("social source must use a public handle")
        entity = await self.client.get_entity(reference)
        username = getattr(entity, "username", None)
        if (
            not isinstance(entity, types.Channel)
            or type(username) is not str
            or getattr(entity, "broadcast", None) is not True
            or getattr(entity, "megagroup", False) is not False
            or normalize_source_reference(f"@{username}").casefold()
            != reference.casefold()
        ):
            raise ValueError("reviewed Telegram source is not a public broadcast channel")
        peer_id = str(utils.get_peer_id(entity))
        if peer_id != source.peer_id:
            raise ValueError("reviewed Telegram source peer identity changed")
        return ResolvedSource(
            reference=reference,
            reference_digest=source.reference_digest,
            peer_id=source.peer_id,
            source_key=source.source_key,
            surface="public_channel",
            authorization="public",
            entity=entity,
        )

    async def refresh_sources(self) -> None:
        if self.social_spool is not None:
            self.social_authorization_ready = False
            try:
                await asyncio.to_thread(self.social_spool.reload_registry)
            except Exception as exc:
                self.social_failed += 1
                log.warning(
                    "social publisher registry refresh failed (%s)",
                    type(exc).__name__,
                )
                raise
        registry = parse_source_registry(CHANNELS_FILE)
        if self.social_spool is not None:
            try:
                await asyncio.to_thread(
                    self.social_spool.note_monitor_registry,
                    registry.references,
                )
            except Exception as exc:
                self.social_failed += 1
                log.warning(
                    "social monitor-allowlist sync failed (%s)",
                    type(exc).__name__,
                )
                raise
        self.failed_references.intersection_update(registry.references)
        for issue in registry.issues:
            log.warning("source registry line %s: %s", issue.line_number, issue.reason)

        desired = set(registry.references)
        for reference in tuple(self.sources_by_reference):
            if reference in desired:
                continue
            removed = self.sources_by_reference.pop(reference)
            if not any(
                source.source_key == removed.source_key
                for source in self.sources_by_reference.values()
            ):
                self.collector.deactivate_source(removed.source_key)
                self.collector.store.register_collector_source(
                    removed.source_key,
                    configured_ref_sha256=removed.reference_digest,
                    surface=removed.surface,
                    authorization=removed.authorization,
                    status="REMOVED",
                )

        for reference in registry.references:
            if reference in self.sources_by_reference:
                continue
            try:
                source = await self._resolve(reference)
            except Exception as exc:
                if self.social_spool is not None:
                    try:
                        await asyncio.to_thread(
                            self.social_spool.note_source_error,
                            reference,
                            "source-resolution-error",
                        )
                    except Exception as spool_exc:
                        self.social_failed += 1
                        log.warning(
                            "social coverage error recording failed (%s)",
                            type(spool_exc).__name__,
                        )
                if reference not in self.failed_references:
                    surface = (
                        "public_channel" if reference.startswith("@")
                        else "authorized_private_channel"
                    )
                    authorization = "public" if reference.startswith("@") else "operator_authorized"
                    unresolved = ObservationContext.create(
                        "",
                        surface=surface,
                        authorization=authorization,
                        raw_source=f"configured:{source_reference_digest(reference)}",
                        pseudonym_key=self.pseudonym_key,
                    )
                    self.collector.store.record_collection_error(
                        surface, unresolved.source_pseudonym,
                    )
                    log.warning(
                        "cannot resolve configured source %s (%s)",
                        source_reference_digest(reference),
                        type(exc).__name__,
                    )
                self.failed_references.add(reference)
                continue
            self.failed_references.discard(reference)
            self.sources_by_reference[reference] = source
            log.info(
                "resolved configured source %s as %s",
                source.reference_digest,
                source.surface,
            )

        previous_peers = set(self.sources_by_peer)
        by_peer: dict[str, ResolvedSource] = {}
        for source in self.sources_by_reference.values():
            by_peer.setdefault(source.peer_id, source)
        self.sources_by_peer = by_peer
        for source in self.sources_by_peer.values():
            self.collector.store.register_collector_source(
                source.source_key,
                configured_ref_sha256=source.reference_digest,
                surface=source.surface,
                authorization=source.authorization,
            )
        if set(self.sources_by_peer) != previous_peers:
            self._replace_event_handler()
        if self.dragon_den_relay is not None:
            self.dragon_den_relay.update_source_coverage(self.sources)
        if self.social_spool is not None:
            # Open capture only after both registries and the resulting runtime
            # source map have been applied as one refresh operation.
            self.social_authorization_ready = True
        if not self.sources_by_peer:
            log.warning("no configured Telegram sources are currently resolved")

    async def verify_discovery_candidates(self) -> int:
        """Resolve a bounded candidate batch without joining or reading it."""

        if not self.settings.discovery_verify_enabled:
            return 0
        candidates = self.collector.store.source_candidates_for_verification(
            min_hits=self.settings.discovery_verify_min_hits,
            min_sources=self.settings.discovery_verify_min_sources,
            limit=self.settings.discovery_verify_batch,
        )
        checked = 0
        for candidate in candidates:
            now = int(time.time())
            status = "RETRY"
            entity_kind = ""
            canonical = ""
            error_code = ""
            next_check = now + self.settings.discovery_retry_seconds
            try:
                entity = await self.client.get_entity(candidate)
                entity_kind = type(entity).__name__
                username = getattr(entity, "username", None)
                if isinstance(entity, types.Channel) and username:
                    status = "VERIFIED_PUBLIC_CHANNEL"
                    canonical = f"@{username.lower()}"
                    next_check = now + self.settings.discovery_recheck_seconds
                else:
                    status = "NOT_CHANNEL"
                    next_check = now + self.settings.discovery_recheck_seconds
            except (errors.UsernameInvalidError, errors.UsernameNotOccupiedError, ValueError) as exc:
                status = "INVALID"
                error_code = type(exc).__name__
                next_check = now + self.settings.discovery_recheck_seconds
            except errors.FloodWaitError as exc:
                error_code = type(exc).__name__
                flood_wait = max(0, int(getattr(exc, "seconds", 0)))
                next_check = now + max(
                    self.settings.discovery_retry_seconds,
                    flood_wait,
                )
            except errors.RPCError as exc:
                error_code = type(exc).__name__
            except Exception as exc:
                error_code = type(exc).__name__
                log.warning(
                    "candidate verification failed for %s (%s)",
                    source_reference_digest(candidate),
                    error_code,
                )
            self.collector.store.record_source_candidate_verification(
                candidate,
                status,
                entity_kind=entity_kind,
                canonical_reference=canonical,
                error_code=error_code,
                checked_at=now,
                next_check=next_check,
            )
            checked += 1
        if checked:
            log.info("verified %d bounded public-source candidate(s)", checked)
        return checked

    def _replace_event_handler(self) -> None:
        for handler, builder in self._event_handlers:
            self.client.remove_event_handler(handler, builder)
        self._event_handlers = []
        if self.sources_by_peer:
            chats = [source.entity for source in self.sources_by_peer.values()]
            self._event_handlers = [
                (self._message_handler, events.NewMessage(chats=chats)),
                (self._message_handler, events.MessageEdited(chats=chats)),
                (self._deleted_handler, events.MessageDeleted(chats=chats)),
            ]
            for handler, builder in self._event_handlers:
                self.client.add_event_handler(handler, builder)

    def status_text(self) -> str:
        """Return a bounded, identity-free operational summary."""

        condition = (
            "degraded"
            if self.reconcile_failure_streak or self.candidate_failure_streak
            else "connected"
        )
        status = (
            f"{condition}; sources={len(self.sources)}; "
            f"unresolved={len(self.failed_references)}; "
            f"live_queue={self.live_queue.qsize()}/{self.live_queue.maxsize}; "
            f"live_done={self.live_completed}; live_failed={self.live_failed}; "
            f"deferred={self.live_deferred}; reconciled={self.last_reconciled}; "
            f"reconcile_failure_streak={self.reconcile_failure_streak}; "
            f"candidates_checked={self.last_candidates_checked}; "
            f"candidate_failure_streak={self.candidate_failure_streak}"
        )
        if self.dragon_den_relay is not None:
            status = f"{status}; {self.dragon_den_relay.status_text()}"
        if self.social_spool is not None:
            status = (
                f"{status}; social_captured={self.social_captured}; "
                f"social_failed={self.social_failed}; "
                f"social_queue={self.social_queue.qsize()}/{self.social_queue.maxsize}; "
                f"social_deferred={self.social_deferred}"
            )
        return status

    def publish_status(self, *, ready: bool = False, watchdog: bool = False) -> None:
        """Publish aggregate health to SQLite and systemd."""

        try:
            self.collector.store.record_monitor_state(
                started_at=self.started_at,
                resolved_sources=len(self.sources),
                unresolved_sources=len(self.failed_references),
                live_queue_depth=self.live_queue.qsize(),
                live_queue_capacity=self.live_queue.maxsize,
                live_enqueued=self.live_enqueued,
                live_completed=self.live_completed,
                live_failed=self.live_failed,
                live_deferred=self.live_deferred,
                reconcile_interval_seconds=self.settings.reconcile_seconds,
                candidate_verify_interval_seconds=(
                    self.settings.candidate_verify_seconds
                ),
                last_reconciled=self.last_reconciled,
                last_reconcile_success_at=self.last_reconcile_success_at,
                reconcile_failure_streak=self.reconcile_failure_streak,
                last_candidates_checked=self.last_candidates_checked,
                last_candidate_success_at=self.last_candidate_success_at,
                candidate_failure_streak=self.candidate_failure_streak,
            )
        except Exception as exc:
            log.warning("monitor heartbeat storage failed (%s)", type(exc).__name__)
        notifications = []
        if ready:
            notifications.append("READY=1")
        if watchdog:
            notifications.append("WATCHDOG=1")
        notifications.append(f"STATUS={self.status_text()}")
        notify_systemd("\n".join(notifications))

    def enqueue_raw(self, source: ResolvedSource, message: object) -> None:
        """Best-effort raw enqueue that never gates the analysis path."""

        if self.dragon_den_relay is not None:
            try:
                self.dragon_den_relay.enqueue(source, message)
            except Exception as exc:
                self.dragon_den_relay.failed += 1
                log.warning(
                    "raw relay enqueue failed for source %s (%s)",
                    source.source_key,
                    type(exc).__name__,
                )

    def enqueue_social(self, source: ResolvedSource, message: object) -> None:
        """Bounded enqueue; SQLite work is performed outside the event loop."""

        if self.social_spool is None or not self.social_authorization_ready:
            return
        try:
            self.social_queue.put_nowait(("capture", source, message))
        except asyncio.QueueFull:
            self.social_deferred += 1

    def enqueue_social_deletion(
        self,
        source: ResolvedSource,
        message_id: int,
    ) -> None:
        if self.social_spool is None or not self.social_authorization_ready:
            return
        try:
            self.social_queue.put_nowait(("tombstone", source, message_id))
        except asyncio.QueueFull:
            self.social_deferred += 1

    def enqueue_auxiliary(self, source: ResolvedSource, message: object) -> None:
        """Fan out pre-analysis observations to independent best-effort sinks."""

        self.enqueue_raw(source, message)
        self.enqueue_social(source, message)

    async def _handle_message(self, event) -> None:
        source = self.sources_by_peer.get(str(event.chat_id))
        if source is None:
            return
        self.enqueue_auxiliary(source, event.message)
        try:
            self.live_queue.put_nowait((source, event))
            self.live_enqueued += 1
        except asyncio.QueueFull:
            # Do not block Telethon's update dispatcher. This event remains
            # unclaimed, so the durable history sweep will recover it.
            self.live_deferred += 1
            if self.live_deferred == 1 or self.live_deferred % 100 == 0:
                log.warning(
                    "live queue saturated; %d message(s) deferred to history recovery",
                    self.live_deferred,
                )

    async def _handle_deleted(self, event) -> None:
        source = self.sources_by_peer.get(str(event.chat_id))
        if source is None:
            return
        for message_id in tuple(getattr(event, "deleted_ids", ())):
            if isinstance(message_id, int) and not isinstance(message_id, bool):
                self.enqueue_social_deletion(source, message_id)

    async def _process_live_event(self, source: ResolvedSource, event) -> None:
        try:
            outcome = await self.collector.process_live(source, event.message)
        except asyncio.CancelledError:
            raise
        except Exception:
            self.live_failed += 1
            raise
        if outcome.status == "COMPLETE":
            self.live_completed += 1
        elif outcome.status == "FAILED":
            self.live_failed += 1
        result = outcome.result
        if result is None or result.overall_tier not in {
            "LIKELY_SCAM", "CONFIRMED_PATTERN",
        }:
            return
        try:
            chat = await event.get_chat()
            title = getattr(chat, "title", None) or source.reference
        except Exception:
            title = source.reference
        families = ", ".join(result.threats.families) or ", ".join(
            sorted(result.detector.families)
        )
        await asyncio.to_thread(
            alert_owner,
            f"🛡 {result.overall_tier} (score {result.overall_score}) "
            f"in “{title}” [{families or 'general'}]\n\n{outcome.text[:250]}"
            f"\n\nReview ID: {result.provenance.assessment_id}",
        )
        log.info(
            "%s from source %s (score %s)",
            result.overall_tier,
            source.source_key,
            result.overall_score,
        )

    async def live_worker(self, worker_number: int) -> None:
        """Drain the bounded live queue without blocking Telethon dispatch."""

        while True:
            source, event = await self.live_queue.get()
            try:
                await self._process_live_event(source, event)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.exception(
                    "live worker %d failed for source %s (%s)",
                    worker_number,
                    source.source_key,
                    type(exc).__name__,
                )
            finally:
                self.live_queue.task_done()

    async def social_worker(self) -> None:
        """Drain sanitized capture work on a thread, independently of analysis."""

        assert self.social_spool is not None
        while True:
            action, source, payload = await self.social_queue.get()
            try:
                if not self.social_authorization_ready:
                    self.social_deferred += 1
                # Preserve already-authorized work while a registry refresh is
                # applying. New events remain closed at enqueue time, and the
                # bounded reconciliation overlap recovers those after refresh.
                while not self.social_authorization_ready:
                    await asyncio.sleep(0.1)
                if action == "capture":
                    outcome = await asyncio.to_thread(
                        self.social_spool.capture, source, payload,
                    )
                else:
                    outcome = await asyncio.to_thread(
                        self.social_spool.tombstone, source, int(payload),
                    )
                if outcome.status in {"CAPTURED", "REPLAYED"}:
                    self.social_captured += 1
                elif outcome.status == "FAILED":
                    self.social_failed += 1
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.social_failed += 1
                log.warning(
                    "social observation %s failed for source %s (%s)",
                    action,
                    source.source_key,
                    type(exc).__name__,
                )
            finally:
                self.social_queue.task_done()

    async def reconcile_social_source(self, source: ResolvedSource) -> int:
        """Advance the social cursor without depending on analysis success."""

        if self.social_spool is None or not self.social_authorization_ready:
            return 0
        reviewed = await asyncio.to_thread(
            self.social_spool.is_source_authorized, source,
        )
        if not reviewed:
            return 0
        try:
            fresh = await self._reattest_social_source(source)
            if not await asyncio.to_thread(
                self.social_spool.is_source_authorized, fresh,
            ):
                raise ValueError("social source lost double-allowlist authorization")
            initialized, cursor = await asyncio.to_thread(
                self.social_spool.source_cursor, fresh,
            )
            if not initialized:
                messages = [
                    message
                    async for message in self.client.iter_messages(
                        fresh.entity,
                        limit=max(1, self.settings.initial_history),
                    )
                ]
                if not self.social_authorization_ready:
                    return 0
                messages.sort(key=lambda item: int(getattr(item, "id", 0)))
                await asyncio.to_thread(
                    self.social_spool.begin_source_batch, fresh,
                )
                if self.settings.initial_history == 0:
                    latest = max(
                        (int(getattr(item, "id", 0)) for item in messages),
                        default=0,
                    )
                    await asyncio.to_thread(
                        self.social_spool.initialize_source_cursor, fresh, latest,
                    )
                    await asyncio.to_thread(
                        self.social_spool.note_source_available, fresh,
                    )
                    return 0
                baseline = (
                    max(0, int(getattr(messages[0], "id", 1)) - 1)
                    if messages
                    else 0
                )
                await asyncio.to_thread(
                    self.social_spool.initialize_source_cursor, fresh, baseline,
                )
            else:
                new_messages = [
                    message
                    async for message in self.client.iter_messages(
                        fresh.entity,
                        min_id=cursor,
                        reverse=True,
                        limit=self.settings.backfill_batch,
                    )
                ]
                recent_messages = [
                    message
                    async for message in self.client.iter_messages(
                        fresh.entity,
                        limit=SOCIAL_REVISION_LOOKBACK,
                    )
                ]
                if not self.social_authorization_ready:
                    return 0
                await asyncio.to_thread(
                    self.social_spool.begin_source_batch, fresh,
                )
                by_id: dict[int, object] = {}
                for message in (*new_messages, *recent_messages):
                    message_id = getattr(message, "id", None)
                    if (
                        isinstance(message_id, int)
                        and not isinstance(message_id, bool)
                        and message_id > 0
                    ):
                        by_id[message_id] = message
                messages = [by_id[message_id] for message_id in sorted(by_id)]
                remote_recent_ids = {
                    int(message.id)
                    for message in recent_messages
                    if isinstance(getattr(message, "id", None), int)
                    and not isinstance(message.id, bool)
                    and message.id > 0
                }
                known_live_ids = await asyncio.to_thread(
                    self.social_spool.recent_live_message_ids,
                    fresh,
                    limit=SOCIAL_REVISION_LOOKBACK,
                )
                if len(remote_recent_ids) < SOCIAL_REVISION_LOOKBACK:
                    missing_ids = set(known_live_ids) - remote_recent_ids
                else:
                    oldest_visible = min(remote_recent_ids)
                    missing_ids = {
                        message_id
                        for message_id in known_live_ids
                        if message_id >= oldest_visible
                        and message_id not in remote_recent_ids
                    }

            processed = 0
            for message in messages:
                if not self.social_authorization_ready:
                    return processed
                outcome = await asyncio.to_thread(
                    self.social_spool.capture, fresh, message,
                )
                if outcome.status not in {
                    "CAPTURED",
                    "REPLAYED",
                    "SKIPPED_OUTSIDE_SCOPE",
                    "SKIPPED_TOMBSTONED",
                }:
                    raise RuntimeError("social backlog record was rejected")
                await asyncio.to_thread(
                    self.social_spool.advance_source_cursor,
                    fresh,
                    int(message.id),
                )
                processed += 1
            if initialized:
                for message_id in sorted(missing_ids):
                    if not self.social_authorization_ready:
                        return processed
                    outcome = await asyncio.to_thread(
                        self.social_spool.tombstone, fresh, message_id,
                    )
                    if outcome.status not in {"CAPTURED", "REPLAYED"}:
                        raise RuntimeError("social deletion recovery was rejected")
                    processed += 1
            await asyncio.to_thread(
                self.social_spool.note_source_available, fresh,
            )
            return processed
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.social_failed += 1
            with suppress(Exception):
                await asyncio.to_thread(
                    self.social_spool.note_source_error,
                    source.reference,
                    "social-reconciliation-error",
                )
            log.warning(
                "social history reconciliation failed for source %s (%s)",
                source.source_key,
                type(exc).__name__,
            )
            return 0

    async def reconcile_social_sources(self) -> int:
        if self.social_spool is None:
            return 0
        gate = asyncio.Semaphore(self.settings.max_reconcile_concurrency)

        async def reconcile_one(source: ResolvedSource) -> int:
            async with gate:
                return await self.reconcile_social_source(source)

        results = await asyncio.gather(
            *(reconcile_one(source) for source in self.sources),
        )
        return sum(results)

    def start_live_workers(self) -> list[asyncio.Task]:
        workers = [
            asyncio.create_task(
                self.live_worker(index + 1),
                name=f"monitor-live-{index + 1}",
            )
            for index in range(self.settings.live_worker_count)
        ]
        if self.social_spool is not None:
            workers.append(
                asyncio.create_task(
                    self.social_worker(), name="monitor-social-spool",
                )
            )
        return workers


async def reconciliation_loop(runtime: MonitorRuntime) -> None:
    while True:
        try:
            outcome = await runtime.collector.reconcile_sources(
                runtime.sources,
                before_process=runtime.enqueue_raw,
            )
        except Exception as exc:
            runtime.reconcile_failure_streak += 1
            log.exception("history reconciliation failed (%s)", type(exc).__name__)
        else:
            runtime.last_reconciled = outcome.processed
            if outcome.failed_sources:
                runtime.reconcile_failure_streak += 1
                log.warning(
                    "history reconciliation failed for %d source(s)",
                    outcome.failed_sources,
                )
            else:
                runtime.last_reconcile_success_at = int(time.time())
                runtime.reconcile_failure_streak = 0
        runtime.publish_status()
        await asyncio.sleep(runtime.settings.reconcile_seconds)


async def social_reconciliation_loop(runtime: MonitorRuntime) -> None:
    while True:
        await asyncio.sleep(runtime.settings.reconcile_seconds)
        try:
            await runtime.reconcile_social_sources()
        except Exception as exc:
            runtime.social_failed += 1
            log.exception("social history reconciliation failed (%s)", type(exc).__name__)
        runtime.publish_status()


async def source_refresh_loop(runtime: MonitorRuntime) -> None:
    while True:
        await asyncio.sleep(runtime.settings.source_refresh_seconds)
        try:
            await runtime.refresh_sources()
            runtime.publish_status()
        except Exception as exc:
            log.exception("source refresh failed (%s)", type(exc).__name__)


async def candidate_verification_loop(runtime: MonitorRuntime) -> None:
    while True:
        try:
            runtime.last_candidates_checked = (
                await runtime.verify_discovery_candidates()
            )
        except Exception as exc:
            runtime.candidate_failure_streak += 1
            log.exception("candidate verification failed (%s)", type(exc).__name__)
        else:
            runtime.last_candidate_success_at = int(time.time())
            runtime.candidate_failure_streak = 0
        runtime.publish_status()
        await asyncio.sleep(runtime.settings.candidate_verify_seconds)


async def watchdog_loop(runtime: MonitorRuntime) -> None:
    interval = watchdog_interval()
    if interval is None:
        return
    while True:
        await asyncio.sleep(interval)
        runtime.publish_status(watchdog=True)


async def main() -> None:
    try:
        api_id = int(os.environ["TELETHON_API_ID"])
        api_hash = os.environ["TELETHON_API_HASH"]
    except (KeyError, ValueError) as exc:
        raise SystemExit("TELETHON_API_ID / TELETHON_API_HASH are missing or invalid") from exc
    pseudonym_key = os.environ.get("SCAMSHIELD_PSEUDONYM_KEY", "")
    if len(pseudonym_key) < 32:
        raise SystemExit("SCAMSHIELD_PSEUDONYM_KEY must contain at least 32 characters")
    try:
        settings = MonitorSettings.from_environment()
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    store = IocStore(os.environ.get("SCAMSHIELD_DB", "scamshield.db"))
    analyzer = AnalysisService.from_environment()
    store_raw_samples = os.environ.get("SCAMSHIELD_STORE_RAW_SAMPLES", "0") == "1"

    client = TelegramClient(
        str(SESSION),
        api_id,
        api_hash,
        auto_reconnect=True,
        connection_retries=10,
        retry_delay=2,
        flood_sleep_threshold=settings.flood_sleep_threshold,
        raise_last_call_error=True,
    )
    collector = TelegramCollector(
        client=client,
        store=store,
        analyzer=analyzer,
        settings=settings,
        pseudonym_key=pseudonym_key,
        store_raw_samples=store_raw_samples,
        logger=log,
    )
    try:
        dragon_den_relay = DragonDenTelethonRelay.from_environment(
            client,
            logger=log,
        )
    except DragonDenError as exc:
        raise SystemExit(str(exc)) from exc
    try:
        social_spool = await asyncio.to_thread(
            SocialObservationSpool.from_environment,
        )
    except Exception as exc:
        # The feature is optional only while disabled.  Once opted in, an
        # invalid registry or private-spool failure must not degrade silently.
        raise SystemExit(
            f"social observation spool initialization failed: {type(exc).__name__}"
        ) from exc
    runtime = MonitorRuntime(
        client=client,
        collector=collector,
        settings=settings,
        pseudonym_key=pseudonym_key,
        dragon_den_relay=dragon_den_relay,
        social_spool=social_spool,
    )

    tasks: list[asyncio.Task] = []
    try:
        await client.connect()
        if not await client.is_user_authorized():
            raise SystemExit(
                "Saved Telegram session is unauthorized. Run authorize-monitor.sh once."
            )
        await runtime.refresh_sources()
        if runtime.dragon_den_relay is not None:
            await runtime.dragon_den_relay.start()
        # Telethon explicitly requires handlers to be registered before this
        # call, otherwise missed updates are fetched but not processed.
        if runtime.social_spool is not None:
            await runtime.reconcile_social_sources()
        tasks = runtime.start_live_workers()
        await client.catch_up()
        runtime.publish_status(ready=True)
        tasks.extend([
            asyncio.create_task(
                reconciliation_loop(runtime), name="monitor-reconciliation",
            ),
            asyncio.create_task(
                source_refresh_loop(runtime), name="monitor-source-refresh",
            ),
            asyncio.create_task(
                candidate_verification_loop(runtime),
                name="monitor-candidate-verification",
            ),
            asyncio.create_task(
                watchdog_loop(runtime), name="systemd-watchdog",
            ),
        ])
        if runtime.social_spool is not None:
            tasks.append(
                asyncio.create_task(
                    social_reconciliation_loop(runtime),
                    name="monitor-social-reconciliation",
                )
            )
        log.info("monitor ready on %d configured source(s)", len(runtime.sources))
        await client.run_until_disconnected()
    finally:
        with suppress(OSError):
            notify_systemd("STOPPING=1\nSTATUS=disconnecting")
        if social_spool is not None:
            # Give the independent sanitized queue a bounded chance to persist
            # already accepted work before worker cancellation.
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(runtime.social_queue.join(), timeout=10)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if runtime.dragon_den_relay is not None:
            await runtime.dragon_den_relay.shutdown()
        if client.is_connected():
            await client.disconnect()
        if social_spool is not None:
            with suppress(Exception):
                await asyncio.to_thread(social_spool.close)
        store.close()


if __name__ == "__main__":
    asyncio.run(main())
