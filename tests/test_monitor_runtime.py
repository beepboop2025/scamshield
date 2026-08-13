import asyncio
import types
import unittest

from monitor import MonitorRuntime
from scamshield.telegram_collector import ProcessOutcome, ResolvedSource
from scamshield.telegram_sources import MonitorSettings


class _Collector:
    def __init__(self):
        self.calls = []
        self.store = types.SimpleNamespace(state=None)

        def record_monitor_state(**state):
            self.store.state = state

        self.store.record_monitor_state = record_monitor_state

    async def process_live(self, source, message):
        self.calls.append((source, message))
        return ProcessOutcome("COMPLETE")


class MonitorRuntimeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.source = ResolvedSource(
            reference="@public_source",
            reference_digest="a" * 24,
            peer_id="-1001234567890",
            source_key="b" * 24,
            surface="public_channel",
            authorization="public",
            entity=object(),
        )

    @staticmethod
    def _event(number):
        return types.SimpleNamespace(
            chat_id=-1001234567890,
            message=types.SimpleNamespace(id=number),
        )

    def _runtime(self, *, queue_size=1, workers=1):
        collector = _Collector()
        runtime = MonitorRuntime(
            client=types.SimpleNamespace(),
            collector=collector,
            settings=MonitorSettings(
                live_queue_size=queue_size,
                live_worker_count=workers,
            ),
            pseudonym_key="local-test-pseudonym-key-with-32-chars",
        )
        runtime.sources_by_peer[self.source.peer_id] = self.source
        return runtime, collector

    async def test_full_live_queue_defers_without_blocking_dispatch(self):
        runtime, collector = self._runtime()

        await runtime._handle_message(self._event(1))
        await runtime._handle_message(self._event(2))

        self.assertEqual(runtime.live_enqueued, 1)
        self.assertEqual(runtime.live_deferred, 1)
        self.assertEqual(runtime.live_queue.qsize(), 1)
        self.assertEqual(collector.calls, [])
        status = runtime.status_text()
        self.assertNotIn(self.source.peer_id, status)
        self.assertNotIn(self.source.reference, status)

    async def test_live_workers_drain_the_bounded_queue(self):
        runtime, collector = self._runtime(queue_size=4, workers=2)
        tasks = runtime.start_live_workers()
        try:
            await runtime._handle_message(self._event(1))
            await runtime._handle_message(self._event(2))
            await asyncio.wait_for(runtime.live_queue.join(), timeout=1)
            self.assertEqual(len(collector.calls), 2)
            self.assertEqual(runtime.live_completed, 2)
            self.assertEqual(runtime.live_failed, 0)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def test_status_publication_contains_only_aggregate_runtime_data(self):
        runtime, collector = self._runtime(queue_size=4, workers=2)
        runtime.failed_references.add("@unresolved_source")
        await runtime._handle_message(self._event(1))

        runtime.publish_status()

        self.assertEqual(collector.store.state["resolved_sources"], 1)
        self.assertEqual(collector.store.state["unresolved_sources"], 1)
        self.assertEqual(collector.store.state["live_queue_depth"], 1)
        self.assertNotIn(self.source.reference, str(collector.store.state))
        self.assertNotIn(self.source.peer_id, str(collector.store.state))


if __name__ == "__main__":
    unittest.main()
