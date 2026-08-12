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
from scamshield.envload import load_env
from scamshield.iocstore import IocStore
from scamshield.runtime import channels_file_path, session_base_path
from scamshield.service_health import notify_systemd, watchdog_interval
from scamshield.telegram_collector import ResolvedSource, TelegramCollector
from scamshield.telegram_sources import (
    MonitorSettings,
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
STORE = IocStore(os.environ.get("SCAMSHIELD_DB", "scamshield.db"))
ANALYZER = AnalysisService.from_environment()
STORE_RAW_SAMPLES = os.environ.get("SCAMSHIELD_STORE_RAW_SAMPLES", "0") == "1"


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
    ):
        self.client = client
        self.collector = collector
        self.settings = settings
        self.pseudonym_key = pseudonym_key
        self.sources_by_reference: dict[str, ResolvedSource] = {}
        self.sources_by_peer: dict[str, ResolvedSource] = {}
        self.failed_references: set[str] = set()
        self._handler = self._handle_message
        self._event_builder = None

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

        is_public = bool(getattr(entity, "username", None))
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
        STORE.register_collector_source(
            source.source_key,
            configured_ref_sha256=source.reference_digest,
            surface=source.surface,
            authorization=source.authorization,
        )
        with suppress(Exception):
            STORE.set_source_candidate_status(reference, "APPROVED")
        return source

    async def refresh_sources(self) -> None:
        registry = parse_source_registry(CHANNELS_FILE)
        self.failed_references.intersection_update(registry.references)
        for issue in registry.issues:
            log.warning("source registry line %s: %s", issue.line_number, issue.reason)

        desired = set(registry.references)
        for reference in tuple(self.sources_by_reference):
            if reference in desired:
                continue
            removed = self.sources_by_reference.pop(reference)
            STORE.register_collector_source(
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
                    STORE.record_collection_error(surface, unresolved.source_pseudonym)
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
            STORE.register_collector_source(
                source.source_key,
                configured_ref_sha256=source.reference_digest,
                surface=source.surface,
                authorization=source.authorization,
            )
        if set(self.sources_by_peer) != previous_peers:
            self._replace_event_handler()
        if not self.sources_by_peer:
            log.warning("no configured Telegram sources are currently resolved")

    async def verify_discovery_candidates(self) -> int:
        """Resolve a bounded candidate batch without joining or reading it."""

        if not self.settings.discovery_verify_enabled:
            return 0
        candidates = STORE.source_candidates_for_verification(
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
            STORE.record_source_candidate_verification(
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
        if self._event_builder is not None:
            self.client.remove_event_handler(self._handler, self._event_builder)
            self._event_builder = None
        if self.sources_by_peer:
            self._event_builder = events.NewMessage(
                chats=[source.entity for source in self.sources_by_peer.values()]
            )
            self.client.add_event_handler(self._handler, self._event_builder)

    async def _handle_message(self, event) -> None:
        source = self.sources_by_peer.get(str(event.chat_id))
        if source is None:
            return
        outcome = await self.collector.process_live(source, event.message)
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


async def maintenance_loop(runtime: MonitorRuntime) -> None:
    while True:
        try:
            processed = await runtime.collector.reconcile_sources(runtime.sources)
            verified = await runtime.verify_discovery_candidates()
            notify_systemd(
                "STATUS=connected; "
                f"sources={len(runtime.sources)}; reconciled={processed}; "
                f"candidates_checked={verified}"
            )
        except Exception as exc:
            log.exception("monitor maintenance failed (%s)", type(exc).__name__)
            with suppress(OSError):
                notify_systemd(f"STATUS=degraded; maintenance={type(exc).__name__}")
        await asyncio.sleep(runtime.settings.reconcile_seconds)
        try:
            await runtime.refresh_sources()
        except Exception as exc:
            log.exception("source refresh failed (%s)", type(exc).__name__)


async def watchdog_loop() -> None:
    interval = watchdog_interval()
    if interval is None:
        return
    while True:
        await asyncio.sleep(interval)
        notify_systemd("WATCHDOG=1")


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
        store=STORE,
        analyzer=ANALYZER,
        settings=settings,
        pseudonym_key=pseudonym_key,
        store_raw_samples=STORE_RAW_SAMPLES,
        logger=log,
    )
    runtime = MonitorRuntime(
        client=client,
        collector=collector,
        settings=settings,
        pseudonym_key=pseudonym_key,
    )

    tasks: list[asyncio.Task] = []
    try:
        await client.connect()
        if not await client.is_user_authorized():
            raise SystemExit(
                "Saved Telegram session is unauthorized. Run authorize-monitor.sh once."
            )
        await runtime.refresh_sources()
        # Telethon explicitly requires handlers to be registered before this
        # call, otherwise missed updates are fetched but not processed.
        await client.catch_up()
        notify_systemd(
            f"READY=1\nSTATUS=connected; sources={len(runtime.sources)}; reconciling"
        )
        tasks = [
            asyncio.create_task(maintenance_loop(runtime), name="monitor-maintenance"),
            asyncio.create_task(watchdog_loop(), name="systemd-watchdog"),
        ]
        log.info("monitor ready on %d configured source(s)", len(runtime.sources))
        await client.run_until_disconnected()
    finally:
        with suppress(OSError):
            notify_systemd("STOPPING=1\nSTATUS=disconnecting")
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if client.is_connected():
            await client.disconnect()
        STORE.close()


if __name__ == "__main__":
    asyncio.run(main())
