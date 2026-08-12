"""Restart-safe Telegram message processing independent of Telethon wiring."""

from __future__ import annotations

import asyncio
import logging
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

from .analysis import AnalysisResult, AnalysisService, ObservationContext
from .iocstore import IocStore
from .telegram_sources import MonitorSettings, discovery_candidates
from .threats import TIER_RANK


@dataclass(frozen=True)
class ResolvedSource:
    reference: str
    reference_digest: str
    peer_id: str
    source_key: str
    surface: str
    authorization: str
    entity: Any


@dataclass(frozen=True)
class ProcessOutcome:
    status: str
    result: AnalysisResult | None = None
    text: str = ""


def message_observed_at(message: Any) -> str:
    value = getattr(message, "date", None)
    if not isinstance(value, datetime):
        value = datetime.now(timezone.utc)
    elif value.tzinfo is None or value.utcoffset() is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    return value.isoformat().replace("+00:00", "Z")


class TelegramCollector:
    """Analyze live/history messages with durable idempotency and cursors."""

    def __init__(
        self,
        *,
        client: Any,
        store: IocStore,
        analyzer: AnalysisService,
        settings: MonitorSettings,
        pseudonym_key: str,
        store_raw_samples: bool = False,
        logger: logging.Logger | None = None,
    ):
        if len(pseudonym_key) < 32:
            raise ValueError("pseudonym_key must contain at least 32 characters")
        self.client = client
        self.store = store
        self.analyzer = analyzer
        self.settings = settings
        self.pseudonym_key = pseudonym_key
        self.store_raw_samples = store_raw_samples
        self.log = logger or logging.getLogger("scamshield.telegram_collector")
        self._locks: dict[str, asyncio.Lock] = {}
        self._analysis_slots = asyncio.Semaphore(settings.max_analysis_concurrency)

    def _lock(self, source_key: str) -> asyncio.Lock:
        return self._locks.setdefault(source_key, asyncio.Lock())

    async def process_live(self, source: ResolvedSource, message: Any) -> ProcessOutcome:
        async with self._lock(source.source_key):
            return await self._process(source, message)

    async def _process(self, source: ResolvedSource, message: Any) -> ProcessOutcome:
        message_id = getattr(message, "id", None)
        if isinstance(message_id, bool) or not isinstance(message_id, int) or message_id <= 0:
            self.log.warning("message without a usable ID from source %s", source.source_key)
            return ProcessOutcome("FAILED")
        observed_at = message_observed_at(message)
        claim = self.store.claim_telegram_message(
            source.source_key,
            message_id,
            observed_at=observed_at,
            lease_seconds=self.settings.claim_lease_seconds,
        )
        if claim == "COMPLETE":
            return ProcessOutcome("COMPLETE")
        if claim == "BUSY":
            return ProcessOutcome("BUSY")

        text = getattr(message, "raw_text", None) or getattr(message, "text", None) or ""
        if not text.strip():
            self.store.complete_telegram_skip(
                source.source_key,
                message_id,
                reason="SKIPPED_NO_TEXT",
                observed_at=observed_at,
            )
            return ProcessOutcome("COMPLETE")

        context = ObservationContext.create(
            text,
            surface=source.surface,
            authorization=source.authorization,
            raw_source=source.peer_id,
            pseudonym_key=self.pseudonym_key,
            observed_at=observed_at,
        )
        if context.source_pseudonym != source.source_key:
            self.store.fail_telegram_message(
                source.source_key,
                message_id,
                surface=source.surface,
                observed_at=observed_at,
                error_code="SourceIdentityMismatch",
            )
            return ProcessOutcome("FAILED")
        try:
            async with self._analysis_slots:
                result = await asyncio.to_thread(
                    self.analyzer.analyze, text, collection=context,
                )
            candidates: tuple[str, ...] = ()
            if TIER_RANK[result.overall_tier] >= TIER_RANK["LIKELY_SCAM"]:
                candidates = tuple(
                    value for value in discovery_candidates(result.iocs)
                    if value.casefold() != source.reference.casefold()
                )
            self.store.record_telegram_result(
                source.source_key,
                message_id,
                result,
                candidates=candidates,
                sample=text if self.store_raw_samples else "",
            )
            return ProcessOutcome("COMPLETE", result=result, text=text)
        except Exception as exc:
            error_code = type(exc).__name__
            self.log.exception(
                "analysis failed for source %s message %s (%s)",
                source.source_key,
                message_id,
                error_code,
            )
            # A database outage can be the original failure. Do not let the
            # best-effort retry bookkeeping replace that useful traceback.
            with suppress(Exception):
                self.store.fail_telegram_message(
                    source.source_key,
                    message_id,
                    surface=source.surface,
                    observed_at=observed_at,
                    error_code=error_code,
                )
            return ProcessOutcome("FAILED")

    async def reconcile_source(self, source: ResolvedSource) -> int:
        """Fill one bounded history gap without letting live traffic skip it."""

        processed = 0
        async with self._lock(source.source_key):
            initialized, cursor = self.store.source_cursor(source.source_key)
            if not initialized:
                messages = [
                    message async for message in self.client.iter_messages(
                        source.entity, limit=max(1, self.settings.initial_history)
                    )
                ]
                messages.sort(key=lambda item: int(getattr(item, "id", 0)))
                if self.settings.initial_history == 0:
                    latest = max(
                        (int(getattr(item, "id", 0)) for item in messages), default=0,
                    )
                    self.store.initialize_source_cursor(source.source_key, latest)
                    return 0
                baseline = max(0, int(getattr(messages[0], "id", 1)) - 1) if messages else 0
                self.store.initialize_source_cursor(source.source_key, baseline)
                candidates: Iterable[Any] = messages
            else:
                candidates = self.client.iter_messages(
                    source.entity,
                    min_id=cursor,
                    reverse=True,
                    limit=self.settings.backfill_batch,
                )

            if hasattr(candidates, "__aiter__"):
                async for message in candidates:
                    outcome = await self._process(source, message)
                    if outcome.status != "COMPLETE":
                        break
                    self.store.advance_source_cursor(source.source_key, message.id)
                    processed += 1
            else:
                for message in candidates:
                    outcome = await self._process(source, message)
                    if outcome.status != "COMPLETE":
                        break
                    self.store.advance_source_cursor(source.source_key, message.id)
                    processed += 1
        return processed

    async def reconcile_sources(self, sources: Iterable[ResolvedSource]) -> int:
        total = 0
        for source in sources:
            try:
                total += await self.reconcile_source(source)
            except Exception as exc:
                # Preserve the original Telegram/reconciliation exception in
                # logs even when the database is also temporarily unavailable.
                with suppress(Exception):
                    self.store.record_collection_error(
                        source.surface, source.source_key,
                    )
                self.log.exception(
                    "history reconciliation failed for source %s (%s)",
                    source.source_key,
                    type(exc).__name__,
                )
        return total


__all__ = [
    "ProcessOutcome",
    "ResolvedSource",
    "TelegramCollector",
    "message_observed_at",
]
