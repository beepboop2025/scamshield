import asyncio
import tempfile
import threading
import unittest
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from scamshield.analysis import AnalysisService, ObservationContext
from scamshield.iocstore import IocStore
from scamshield.provenance import ProvenanceEngine
from scamshield.rates import MarketRateOracle, RateObservation
from scamshield.telegram_collector import ResolvedSource, TelegramCollector
from scamshield.telegram_sources import MonitorSettings


PACK = Path(__file__).resolve().parents[1] / "scamshield" / "data" / "intelligence-pack-v1.json"


class _FixedRate:
    name = "fixed"

    def fetch(self):
        return RateObservation("fixed", 92.0, "2026-08-08T00:00:00Z", "https://example.test")


@dataclass
class _Message:
    id: int
    raw_text: str
    date: datetime = datetime(2026, 8, 8, 12, 0, tzinfo=timezone.utc)


class _Client:
    def __init__(self, messages):
        self.messages = list(messages)

    async def iter_messages(self, _entity, *, limit, min_id=0, reverse=False):
        values = [item for item in self.messages if item.id > min_id]
        values.sort(key=lambda item: item.id, reverse=not reverse)
        for item in values[:limit]:
            yield item


class _ConcurrentClient:
    def __init__(self, *, fail_entity=None):
        self.active = 0
        self.max_active = 0
        self.fail_entity = fail_entity

    async def iter_messages(self, entity, *, limit, min_id=0, reverse=False):
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            if entity == self.fail_entity:
                raise RuntimeError("history unavailable")
            await asyncio.sleep(0.02)
            yield _Message(1, f"ordinary update from {entity}")
        finally:
            self.active -= 1


class _BlockingAnalyzer:
    def __init__(self, delegate):
        self.delegate = delegate
        self.started = threading.Event()
        self.release = threading.Event()
        self.done = threading.Event()

    def analyze(self, text, *, collection):
        try:
            self.started.set()
            self.release.wait(timeout=2)
            return self.delegate.analyze(text, collection=collection)
        finally:
            self.done.set()


class TelegramCollectorTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = IocStore(Path(self.temp.name) / "scamshield.db")
        self.analyzer = AnalysisService(
            rate_oracle=MarketRateOracle([_FixedRate()]),
            provenance_engine=ProvenanceEngine.from_path(PACK),
        )
        self.key = "local-test-pseudonym-key-with-32-chars"
        self.peer_id = "-1001234567890"
        self.source_key = ObservationContext.create(
            "",
            surface="public_channel",
            authorization="public",
            raw_source=self.peer_id,
            pseudonym_key=self.key,
        ).source_pseudonym
        self.source = ResolvedSource(
            reference="@public_source",
            reference_digest="a" * 24,
            peer_id=self.peer_id,
            source_key=self.source_key,
            surface="public_channel",
            authorization="public",
            entity=object(),
        )
        self.store.register_collector_source(
            self.source_key,
            configured_ref_sha256=self.source.reference_digest,
            surface=self.source.surface,
            authorization=self.source.authorization,
        )

    async def asyncTearDown(self):
        self.store.close()
        self.temp.cleanup()

    async def test_initial_window_then_durable_gap_reconciliation(self):
        client = _Client([_Message(i, f"ordinary update {i}") for i in range(1, 6)])
        collector = TelegramCollector(
            client=client,
            store=self.store,
            analyzer=self.analyzer,
            settings=MonitorSettings(initial_history=2, backfill_batch=10),
            pseudonym_key=self.key,
        )

        self.assertEqual(await collector.reconcile_source(self.source), 2)
        self.assertEqual(self.store.source_cursor(self.source_key), (True, 5))
        self.assertEqual(self.store.coverage_digest()[0][2], 2)

        client.messages.extend([_Message(6, "ordinary update 6"), _Message(7, "ordinary update 7")])
        self.assertEqual(await collector.reconcile_source(self.source), 2)
        self.assertEqual(self.store.source_cursor(self.source_key), (True, 7))
        self.assertEqual(self.store.coverage_digest()[0][2], 4)

    async def test_live_receipt_does_not_jump_the_history_cursor(self):
        client = _Client([_Message(10, "ordinary update 10")])
        collector = TelegramCollector(
            client=client,
            store=self.store,
            analyzer=self.analyzer,
            settings=MonitorSettings(initial_history=1, backfill_batch=10),
            pseudonym_key=self.key,
        )
        await collector.reconcile_source(self.source)
        client.messages.append(_Message(11, "ordinary update 11"))

        outcome = await collector.process_live(self.source, client.messages[-1])
        self.assertEqual(outcome.status, "COMPLETE")
        self.assertEqual(self.store.source_cursor(self.source_key), (True, 10))
        self.assertEqual(self.store.coverage_digest()[0][2], 2)

        self.assertEqual(await collector.reconcile_source(self.source), 1)
        self.assertEqual(self.store.source_cursor(self.source_key), (True, 11))
        self.assertEqual(self.store.coverage_digest()[0][2], 2)

    async def test_non_text_history_is_receipted_but_not_analyzed(self):
        client = _Client([_Message(20, "")])
        collector = TelegramCollector(
            client=client,
            store=self.store,
            analyzer=self.analyzer,
            settings=MonitorSettings(initial_history=1),
            pseudonym_key=self.key,
        )
        self.assertEqual(await collector.reconcile_source(self.source), 1)
        self.assertEqual(self.store.source_cursor(self.source_key), (True, 20))
        self.assertEqual(self.store.coverage_digest(), [])

    async def test_independent_sources_reconcile_concurrently(self):
        second_peer = "-1001234567891"
        second_key = ObservationContext.create(
            "",
            surface="public_channel",
            authorization="public",
            raw_source=second_peer,
            pseudonym_key=self.key,
        ).source_pseudonym
        second = ResolvedSource(
            reference="@second_public_source",
            reference_digest="b" * 24,
            peer_id=second_peer,
            source_key=second_key,
            surface="public_channel",
            authorization="public",
            entity="second",
        )
        first = ResolvedSource(
            reference=self.source.reference,
            reference_digest=self.source.reference_digest,
            peer_id=self.source.peer_id,
            source_key=self.source.source_key,
            surface=self.source.surface,
            authorization=self.source.authorization,
            entity="first",
        )
        self.store.register_collector_source(
            second.source_key,
            configured_ref_sha256=second.reference_digest,
            surface=second.surface,
            authorization=second.authorization,
        )
        client = _ConcurrentClient()
        collector = TelegramCollector(
            client=client,
            store=self.store,
            analyzer=self.analyzer,
            settings=MonitorSettings(
                initial_history=1,
                max_reconcile_concurrency=2,
            ),
            pseudonym_key=self.key,
        )

        outcome = await collector.reconcile_sources((first, second))
        self.assertEqual(outcome.processed, 2)
        self.assertEqual(outcome.failed_sources, 0)
        self.assertEqual(client.max_active, 2)

        collector.client = _ConcurrentClient(fail_entity="second")
        outcome = await collector.reconcile_sources((first, second))
        self.assertEqual(outcome.processed, 1)
        self.assertEqual(outcome.failed_sources, 1)

    async def test_cancelled_live_analysis_is_immediately_retryable(self):
        client = _Client([])
        blocking = _BlockingAnalyzer(self.analyzer)
        collector = TelegramCollector(
            client=client,
            store=self.store,
            analyzer=blocking,
            settings=MonitorSettings(),
            pseudonym_key=self.key,
        )
        task = asyncio.create_task(collector.process_live(
            self.source, _Message(30, "ordinary update 30"),
        ))
        self.assertTrue(await asyncio.to_thread(blocking.started.wait, 1))
        task.cancel()
        try:
            with self.assertRaises(asyncio.CancelledError):
                await task
            status = self.store.conn.execute(
                """SELECT status, error_code FROM telegram_messages
                   WHERE source_key = ? AND message_id = 30""",
                (self.source_key,),
            ).fetchone()
            self.assertEqual(status, ("RETRY", "CancelledError"))
        finally:
            blocking.release.set()
            self.assertTrue(await asyncio.to_thread(blocking.done.wait, 1))

    async def test_inflight_analysis_cannot_reactivate_a_removed_source(self):
        client = _Client([])
        blocking = _BlockingAnalyzer(self.analyzer)
        collector = TelegramCollector(
            client=client,
            store=self.store,
            analyzer=blocking,
            settings=MonitorSettings(),
            pseudonym_key=self.key,
        )
        task = asyncio.create_task(collector.process_live(
            self.source, _Message(31, "ordinary update 31"),
        ))
        self.assertTrue(await asyncio.to_thread(blocking.started.wait, 1))
        collector.deactivate_source(self.source_key)
        self.store.register_collector_source(
            self.source_key,
            configured_ref_sha256=self.source.reference_digest,
            surface=self.source.surface,
            authorization=self.source.authorization,
            status="REMOVED",
        )
        blocking.release.set()

        outcome = await task
        self.assertEqual(outcome.status, "REMOVED")
        self.assertEqual(self.store.coverage_digest(), [])
        receipt = self.store.conn.execute(
            """SELECT tier FROM telegram_messages
               WHERE source_key = ? AND message_id = 31""",
            (self.source_key,),
        ).fetchone()
        self.assertEqual(receipt, ("SKIPPED_SOURCE_REMOVED",))
        source_status = self.store.conn.execute(
            "SELECT status FROM collector_sources WHERE source_key = ?",
            (self.source_key,),
        ).fetchone()
        self.assertEqual(source_status, ("REMOVED",))

    async def test_inflight_result_is_rejected_after_remove_and_reactivate(self):
        client = _Client([])
        blocking = _BlockingAnalyzer(self.analyzer)
        collector = TelegramCollector(
            client=client,
            store=self.store,
            analyzer=blocking,
            settings=MonitorSettings(),
            pseudonym_key=self.key,
        )
        task = asyncio.create_task(collector.process_live(
            self.source, _Message(32, "ordinary update 32"),
        ))
        self.assertTrue(await asyncio.to_thread(blocking.started.wait, 1))
        collector.deactivate_source(self.source_key)
        self.store.register_collector_source(
            self.source_key,
            configured_ref_sha256=self.source.reference_digest,
            surface=self.source.surface,
            authorization=self.source.authorization,
            status="REMOVED",
        )
        collector.activate_source(self.source_key)
        self.store.register_collector_source(
            self.source_key,
            configured_ref_sha256=self.source.reference_digest,
            surface=self.source.surface,
            authorization=self.source.authorization,
        )
        blocking.release.set()

        outcome = await task
        self.assertEqual(outcome.status, "REMOVED")
        self.assertEqual(self.store.coverage_digest(), [])
        receipt = self.store.conn.execute(
            """SELECT tier FROM telegram_messages
               WHERE source_key = ? AND message_id = 32""",
            (self.source_key,),
        ).fetchone()
        self.assertEqual(receipt, ("SKIPPED_SOURCE_REMOVED",))


if __name__ == "__main__":
    unittest.main()
