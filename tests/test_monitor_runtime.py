import asyncio
import types
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from telethon import types as telegram_types
from telethon import utils as telegram_utils

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
        self.store.register_collector_source = lambda *args, **kwargs: None

    async def process_live(self, source, message):
        self.calls.append((source, message))
        return ProcessOutcome("COMPLETE")


class _Relay:
    def __init__(self):
        self.calls = []
        self.failed = 0
        self.raise_on_enqueue = False

    def enqueue(self, source, message):
        if self.raise_on_enqueue:
            raise RuntimeError("outbox unavailable")
        self.calls.append((source, message))
        return ("receipt",)

    def update_source_coverage(self, sources):
        self.coverage = tuple(sources)

    def status_text(self):
        return "raw[pending=1]"


class _SocialSpool:
    def __init__(self):
        self.calls = []
        self.raise_on_capture = False
        self.registry_reloads = 0
        self.monitor_registries = []

    def reload_registry(self):
        self.registry_reloads += 1

    def note_monitor_registry(self, references):
        self.monitor_registries.append(tuple(references))

    def capture(self, source, message):
        if self.raise_on_capture:
            raise RuntimeError("social spool unavailable")
        self.calls.append((source, message))
        return types.SimpleNamespace(status="CAPTURED")

    def tombstone(self, source, message_id):
        self.calls.append((source, message_id, "tombstone"))
        return types.SimpleNamespace(status="CAPTURED")


class _BacklogSpool:
    def __init__(self):
        self.initialized = False
        self.cursor = 0
        self.attested = 0
        self.batches = 0
        self.captured = []
        self.advanced = []
        self.tombstoned = []
        self.known_live_ids = ()
        self.errors = []

    def is_source_authorized(self, source):
        return True

    def source_cursor(self, source):
        return self.initialized, self.cursor

    def note_source_available(self, source):
        self.attested += 1
        return True

    def begin_source_batch(self, source):
        self.batches += 1
        return True

    def recent_live_message_ids(self, source, *, limit):
        return tuple(self.known_live_ids[:limit])

    def initialize_source_cursor(self, source, message_id):
        self.initialized = True
        self.cursor = max(self.cursor, message_id)

    def advance_source_cursor(self, source, message_id):
        self.cursor = max(self.cursor, message_id)
        self.advanced.append(message_id)

    def capture(self, source, message):
        self.captured.append(message.id)
        status = "SKIPPED_OUTSIDE_SCOPE" if message.id == 10 else "CAPTURED"
        return types.SimpleNamespace(status=status)

    def tombstone(self, source, message_id):
        self.tombstoned.append(message_id)
        return types.SimpleNamespace(status="CAPTURED")

    def note_source_error(self, reference, error_code):
        self.errors.append((reference, error_code))


class _TelegramClient:
    def __init__(self, entity, messages=(), *, new_messages=None, recent_messages=None):
        self.entity = entity
        self.messages = tuple(messages)
        self.new_messages = None if new_messages is None else tuple(new_messages)
        self.recent_messages = (
            None if recent_messages is None else tuple(recent_messages)
        )
        self.iter_calls = []

    async def get_entity(self, reference):
        return self.entity

    def iter_messages(self, entity, **kwargs):
        self.iter_calls.append(kwargs)
        if "min_id" in kwargs and self.new_messages is not None:
            selected = self.new_messages
        elif "min_id" not in kwargs and self.recent_messages is not None:
            selected = self.recent_messages
        else:
            selected = self.messages

        async def generate():
            for message in selected:
                yield message

        return generate()

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

    def _runtime(
        self,
        *,
        queue_size=1,
        workers=1,
        relay=None,
        social_spool=None,
        client=None,
    ):
        collector = _Collector()
        runtime = MonitorRuntime(
            client=types.SimpleNamespace() if client is None else client,
            collector=collector,
            settings=MonitorSettings(
                live_queue_size=queue_size,
                live_worker_count=workers,
            ),
            pseudonym_key="local-test-pseudonym-key-with-32-chars",
            dragon_den_relay=relay,
            social_spool=social_spool,
        )
        runtime.sources_by_peer[self.source.peer_id] = self.source
        return runtime, collector

    @staticmethod
    def _channel(channel_id=1234567890, *, broadcast=True, megagroup=False):
        return telegram_types.Channel(
            id=channel_id,
            title="Public source",
            photo=telegram_types.ChatPhotoEmpty(),
            date=datetime(2026, 8, 16, tzinfo=timezone.utc),
            broadcast=broadcast,
            megagroup=megagroup,
            access_hash=42,
            username="public_source",
        )

    async def test_full_live_queue_defers_without_blocking_dispatch(self):
        relay = _Relay()
        runtime, collector = self._runtime(relay=relay)

        await runtime._handle_message(self._event(1))
        await runtime._handle_message(self._event(2))

        self.assertEqual(runtime.live_enqueued, 1)
        self.assertEqual(runtime.live_deferred, 1)
        self.assertEqual(runtime.live_queue.qsize(), 1)
        self.assertEqual(collector.calls, [])
        self.assertEqual(len(relay.calls), 2)
        status = runtime.status_text()
        self.assertIn("raw[pending=1]", status)
        self.assertNotIn(self.source.peer_id, status)
        self.assertNotIn(self.source.reference, status)

    async def test_raw_outbox_failure_does_not_gate_analysis_queue(self):
        relay = _Relay()
        relay.raise_on_enqueue = True
        runtime, _ = self._runtime(relay=relay)

        await runtime._handle_message(self._event(3))

        self.assertEqual(relay.failed, 1)
        self.assertEqual(runtime.live_queue.qsize(), 1)
        self.assertEqual(runtime.live_enqueued, 1)

    async def test_social_spool_failure_does_not_gate_raw_or_analysis(self):
        relay = _Relay()
        social_spool = _SocialSpool()
        social_spool.raise_on_capture = True
        runtime, _ = self._runtime(relay=relay, social_spool=social_spool)

        worker = asyncio.create_task(runtime.social_worker())
        try:
            await runtime._handle_message(self._event(4))
            await asyncio.wait_for(runtime.social_queue.join(), timeout=1)
        finally:
            worker.cancel()
            await asyncio.gather(worker, return_exceptions=True)

        self.assertEqual(len(relay.calls), 1)
        self.assertEqual(runtime.social_failed, 1)
        self.assertEqual(runtime.live_queue.qsize(), 1)
        self.assertEqual(runtime.live_enqueued, 1)

    async def test_social_capture_occurs_at_pre_analysis_seam(self):
        social_spool = _SocialSpool()
        runtime, collector = self._runtime(social_spool=social_spool)

        worker = asyncio.create_task(runtime.social_worker())
        try:
            await runtime._handle_message(self._event(5))
            self.assertEqual(collector.calls, [])
            await asyncio.wait_for(runtime.social_queue.join(), timeout=1)
        finally:
            worker.cancel()
            await asyncio.gather(worker, return_exceptions=True)

        self.assertEqual(len(social_spool.calls), 1)
        self.assertEqual(runtime.social_captured, 1)
        self.assertEqual(runtime.live_queue.qsize(), 1)

    async def test_social_queue_is_bounded_and_deferred_to_independent_history(self):
        social_spool = _SocialSpool()
        runtime, _ = self._runtime(queue_size=1, social_spool=social_spool)

        await runtime._handle_message(self._event(6))
        await runtime._handle_message(self._event(7))

        self.assertEqual(runtime.social_queue.qsize(), 1)
        self.assertEqual(runtime.social_deferred, 1)
        self.assertEqual(social_spool.calls, [])

    async def test_queued_social_work_waits_for_authorization_refresh(self):
        social_spool = _SocialSpool()
        runtime, _ = self._runtime(queue_size=2, social_spool=social_spool)
        runtime.enqueue_social(self.source, types.SimpleNamespace(id=71))
        runtime._set_social_authorization(False)
        worker = asyncio.create_task(runtime.social_worker())
        try:
            await asyncio.sleep(0.05)
            self.assertEqual(social_spool.calls, [])
            self.assertEqual(runtime.social_queue.qsize(), 0)
            runtime._set_social_authorization(True)
            await asyncio.wait_for(runtime.social_queue.join(), timeout=1)
        finally:
            worker.cancel()
            await asyncio.gather(worker, return_exceptions=True)

        self.assertEqual(len(social_spool.calls), 1)
        self.assertEqual(runtime.social_deferred, 1)

    async def test_failed_allowlist_refresh_closes_only_the_social_lane(self):
        social_spool = _SocialSpool()

        def fail_reload():
            raise RuntimeError("invalid replacement registry")

        social_spool.reload_registry = fail_reload
        runtime, _ = self._runtime(social_spool=social_spool)
        runtime.sources_by_reference[self.source.reference] = self.source

        registry = types.SimpleNamespace(
            references=(self.source.reference,),
            issues=(),
        )
        with patch("monitor.parse_source_registry", return_value=registry):
            await runtime.refresh_sources()
        await runtime._handle_message(self._event(8))

        self.assertFalse(runtime.social_authorization_ready)
        self.assertFalse(runtime.social_authorization_event.is_set())
        self.assertEqual(social_spool.monitor_registries, [])
        self.assertEqual(runtime.social_queue.qsize(), 0)
        self.assertEqual(runtime.live_queue.qsize(), 1)
        self.assertIn("social_ready=0", runtime.status_text())

    async def test_failed_monitor_allowlist_sync_closes_only_social_lane(self):
        social_spool = _SocialSpool()

        def fail_sync(_references):
            raise RuntimeError("database unavailable")

        social_spool.note_monitor_registry = fail_sync
        runtime, _ = self._runtime(social_spool=social_spool)
        runtime.sources_by_reference[self.source.reference] = self.source
        registry = types.SimpleNamespace(
            references=(self.source.reference,),
            issues=(),
        )

        with patch("monitor.parse_source_registry", return_value=registry):
            await runtime.refresh_sources()
        await runtime._handle_message(self._event(9))

        self.assertEqual(social_spool.registry_reloads, 1)
        self.assertFalse(runtime.social_authorization_ready)
        self.assertEqual(runtime.social_queue.qsize(), 0)
        self.assertEqual(runtime.live_queue.qsize(), 1)

    async def test_successful_allowlist_refresh_reopens_social_lane(self):
        social_spool = _SocialSpool()
        runtime, _ = self._runtime(social_spool=social_spool)
        runtime.sources_by_reference[self.source.reference] = self.source
        runtime._set_social_authorization(False)
        registry = types.SimpleNamespace(
            references=(self.source.reference,),
            issues=(),
        )

        with patch("monitor.parse_source_registry", return_value=registry):
            await runtime.refresh_sources()

        self.assertEqual(social_spool.registry_reloads, 1)
        self.assertEqual(social_spool.monitor_registries, [(self.source.reference,)])
        self.assertTrue(runtime.social_authorization_ready)
        self.assertTrue(runtime.social_authorization_event.is_set())

    async def test_edit_is_captured_without_replaying_core_analysis(self):
        relay = _Relay()
        social_spool = _SocialSpool()
        runtime, _ = self._runtime(relay=relay, social_spool=social_spool)

        await runtime._handle_edited(self._event(10))

        self.assertEqual(len(relay.calls), 1)
        self.assertEqual(runtime.social_queue.qsize(), 1)
        self.assertEqual(runtime.live_queue.qsize(), 0)
        self.assertEqual(runtime.live_enqueued, 0)

    async def test_deletion_event_enqueues_content_free_tombstone(self):
        social_spool = _SocialSpool()
        runtime, _ = self._runtime(queue_size=2, social_spool=social_spool)
        worker = asyncio.create_task(runtime.social_worker())
        try:
            await runtime._handle_deleted(
                types.SimpleNamespace(
                    chat_id=-1001234567890,
                    deleted_ids=[12],
                )
            )
            await asyncio.wait_for(runtime.social_queue.join(), timeout=1)
        finally:
            worker.cancel()
            await asyncio.gather(worker, return_exceptions=True)

        self.assertEqual(social_spool.calls[0][1:], (12, "tombstone"))

    async def test_social_backlog_advances_independently_of_analysis(self):
        entity = self._channel()
        client = _TelegramClient(
            entity,
            messages=(
                types.SimpleNamespace(id=10),
                types.SimpleNamespace(id=11),
            ),
        )
        spool = _BacklogSpool()
        runtime, collector = self._runtime(
            queue_size=4,
            social_spool=spool,
            client=client,
        )
        source = ResolvedSource(
            reference="@public_source",
            reference_digest="a" * 24,
            peer_id=str(telegram_utils.get_peer_id(entity)),
            source_key="b" * 24,
            surface="public_channel",
            authorization="public",
            entity=entity,
        )

        processed = await runtime.reconcile_social_source(source)

        self.assertEqual(processed, 2)
        self.assertEqual(spool.attested, 1)
        self.assertEqual(spool.batches, 1)
        self.assertEqual(spool.captured, [10, 11])
        self.assertEqual(spool.advanced, [10, 11])
        self.assertEqual(collector.calls, [])

    async def test_social_overlap_recovers_edits_and_deletions_behind_cursor(self):
        entity = self._channel()
        client = _TelegramClient(
            entity,
            new_messages=(types.SimpleNamespace(id=13),),
            recent_messages=(
                types.SimpleNamespace(id=12),
                types.SimpleNamespace(id=10, edit_date=datetime.now(timezone.utc)),
            ),
        )
        spool = _BacklogSpool()
        spool.initialized = True
        spool.cursor = 12
        spool.known_live_ids = (12, 11, 10)
        runtime, collector = self._runtime(
            queue_size=4,
            social_spool=spool,
            client=client,
        )
        source = ResolvedSource(
            reference="@public_source",
            reference_digest="a" * 24,
            peer_id=str(telegram_utils.get_peer_id(entity)),
            source_key="b" * 24,
            surface="public_channel",
            authorization="public",
            entity=entity,
        )

        processed = await runtime.reconcile_social_source(source)

        self.assertEqual(processed, 4)
        self.assertEqual(spool.batches, 1)
        self.assertEqual(spool.attested, 1)
        self.assertEqual(spool.captured, [10, 12, 13])
        self.assertEqual(spool.tombstoned, [11])
        self.assertEqual(spool.cursor, 13)
        self.assertEqual(len(client.iter_calls), 2)
        self.assertEqual(client.iter_calls[0]["min_id"], 12)
        self.assertEqual(client.iter_calls[1]["limit"], 50)
        self.assertEqual(collector.calls, [])

    async def test_social_reattest_rejects_user_group_and_peer_change(self):
        original = self._channel()
        source = ResolvedSource(
            reference="@public_source",
            reference_digest="a" * 24,
            peer_id=str(telegram_utils.get_peer_id(original)),
            source_key="b" * 24,
            surface="public_channel",
            authorization="public",
            entity=original,
        )
        invalid_entities = (
            telegram_types.User(id=123, username="public_source", bot=True),
            self._channel(broadcast=False, megagroup=True),
            self._channel(channel_id=999999999),
        )
        for entity in invalid_entities:
            runtime, _ = self._runtime(
                client=_TelegramClient(entity),
                social_spool=_BacklogSpool(),
            )
            with self.subTest(entity=type(entity).__name__, id=entity.id):
                with self.assertRaises(ValueError):
                    await runtime._reattest_social_source(source)

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
        self.assertEqual(collector.store.state["reconcile_interval_seconds"], 300)
        self.assertEqual(collector.store.state["last_reconcile_success_at"], 0)
        self.assertEqual(collector.store.state["reconcile_failure_streak"], 0)
        self.assertNotIn(self.source.reference, str(collector.store.state))
        self.assertNotIn(self.source.peer_id, str(collector.store.state))


if __name__ == "__main__":
    unittest.main()
