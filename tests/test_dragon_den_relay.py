import tempfile
import types
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scamshield.dragon_den import (
    Destination,
    DragonDenOutbox,
    DragonDenRoutes,
    SourceRoute,
)
from scamshield.dragon_den_relay import DragonDenTelethonRelay
from scamshield.telegram_collector import ResolvedSource


class _Client:
    def __init__(self):
        self.calls = []
        self.next_id = 200
        self.forward_error = None

    async def get_entity(self, chat_id):
        return types.SimpleNamespace(
            broadcast=True,
            creator=True,
            admin_rights=None,
        )

    async def send_message(self, **kwargs):
        self.calls.append(("fallback", kwargs))
        self.next_id += 1
        return types.SimpleNamespace(id=self.next_id)

    async def forward_messages(self, **kwargs):
        self.calls.append(("forward", kwargs))
        if self.forward_error is not None:
            raise self.forward_error
        values = []
        for _ in kwargs["messages"]:
            self.next_id += 1
            values.append(types.SimpleNamespace(id=self.next_id))
        return values


class ChatForwardsRestrictedError(RuntimeError):
    pass


class DragonDenTelethonRelayTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.outbox = DragonDenOutbox(Path(self.temp.name) / "relay.db")
        destination = Destination("all", "@dragon_den_feed", "All raw")
        route = SourceRoute("@public_source", "Public source", ())
        self.routes = DragonDenRoutes(
            destinations={"all": destination},
            catch_all_destination_ids=("all",),
            sources={"@public_source": route},
        )
        self.source = ResolvedSource(
            reference="@public_source",
            reference_digest="a" * 24,
            peer_id="-1001234567890",
            source_key="b" * 24,
            surface="public_channel",
            authorization="public",
            entity=object(),
        )
        self.client = _Client()
        self.notices = []

        async def notice(**kwargs):
            self.notices.append(kwargs)
            return 100 + len(self.notices)

        self.relay = DragonDenTelethonRelay(
            client=self.client,
            routes=self.routes,
            outbox=self.outbox,
            token="123456:dedicated-test-token-value",
            protect_content=True,
            notice_sender=notice,
        )

    async def asyncTearDown(self):
        if self.relay.worker is not None:
            await self.relay.shutdown()
        else:
            self.outbox.close()
        self.temp.cleanup()

    @staticmethod
    def message(number=10, *, grouped_id=None, edit_date=None):
        return types.SimpleNamespace(
            id=number,
            date=datetime(2026, 8, 15, 12, 0, tzinfo=timezone.utc),
            edit_date=edit_date,
            grouped_id=grouped_id,
        )

    async def test_warning_precedes_native_telethon_forward(self):
        self.relay.enqueue(self.source, self.message())

        self.assertTrue(await self.relay.deliver_once())

        self.assertEqual(len(self.notices), 1)
        self.assertIn("UNVERIFIED RAW FORWARD", self.notices[0]["text"])
        self.assertEqual(self.client.calls[0][0], "forward")
        forward = self.client.calls[0][1]
        self.assertEqual(forward["entity"], "@dragon_den_feed")
        self.assertEqual(forward["from_peer"], -1001234567890)
        self.assertEqual(forward["messages"], [10])
        self.assertEqual(self.outbox.status_counts(), {"COMPLETE": 1})

    async def test_bot_notice_failure_uses_session_without_gating_forward(self):
        async def unavailable(**kwargs):
            raise RuntimeError("bot transport unavailable")

        self.relay.notice_sender = unavailable
        self.relay.enqueue(self.source, self.message())

        await self.relay.deliver_once()

        self.assertEqual([name for name, _ in self.client.calls], ["fallback", "forward"])
        self.assertEqual(self.outbox.status_counts(), {"COMPLETE": 1})

    async def test_protected_source_gets_tombstone_without_copying(self):
        self.client.forward_error = ChatForwardsRestrictedError("forwards restricted")
        self.relay.enqueue(self.source, self.message())

        await self.relay.deliver_once()

        self.assertEqual(len(self.notices), 2)
        self.assertIn("RAW FORWARD UNAVAILABLE", self.notices[1]["text"])
        self.assertEqual(self.outbox.status_counts(), {"UNFORWARDABLE": 1})

    async def test_edit_revision_is_distinct_and_private_sources_are_ignored(self):
        edit_date = datetime(2026, 8, 15, 12, 5, tzinfo=timezone.utc)
        original = self.relay.enqueue(self.source, self.message())
        edited = self.relay.enqueue(
            self.source,
            self.message(edit_date=edit_date),
        )
        self.assertNotEqual(original, edited)

        private = types.SimpleNamespace(**{
            **self.source.__dict__,
            "reference": "-1009876543210",
            "surface": "authorized_private_channel",
        })
        self.assertEqual(self.relay.enqueue(private, self.message()), ())
        self.assertEqual(self.outbox.status_counts(), {"PENDING": 2})

    async def test_destination_verification_requires_channel_posting_rights(self):
        await self.relay.verify_destinations()
        self.client.get_entity = lambda chat_id: _awaitable(
            types.SimpleNamespace(
                broadcast=True,
                creator=False,
                admin_rights=types.SimpleNamespace(post_messages=False),
            )
        )
        with self.assertRaisesRegex(ValueError, "cannot post"):
            await self.relay.verify_destinations()

    async def test_status_reports_aggregate_route_coverage_only(self):
        self.relay.update_source_coverage((self.source,))

        status = self.relay.status_text()

        self.assertIn("routes=1/1", status)
        self.assertIn("missing_routes=0", status)
        self.assertNotIn(self.source.reference, status)
        self.assertNotIn(self.source.peer_id, status)


async def _awaitable(value):
    return value


if __name__ == "__main__":
    unittest.main()
