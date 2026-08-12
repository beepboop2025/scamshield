import tempfile
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


if __name__ == "__main__":
    unittest.main()
