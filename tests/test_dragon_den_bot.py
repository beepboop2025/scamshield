import tempfile
import types
import unittest
from asyncio import Lock
from pathlib import Path
from unittest.mock import patch

from scamshield.dragon_den import Destination, DragonDenOutbox

try:
    import dragon_den_bot
    from telegram.error import BadRequest
except ModuleNotFoundError:
    dragon_den_bot = None
    BadRequest = None


@unittest.skipIf(dragon_den_bot is None, "python-telegram-bot is not installed")
class DragonDenDeliveryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.box = DragonDenOutbox(Path(self.temp.name) / "dragon-den.db")
        self.destination = Destination("all", "@dragon_den_feed", "All")

    async def asyncTearDown(self):
        self.box.close()
        self.temp.cleanup()

    def batch(self, *, album=False):
        message_ids = (10, 11) if album else (10,)
        for message_id in message_ids:
            self.box.enqueue(
                source="@public_source",
                source_chat_id="-1009876543210",
                source_message_id=message_id,
                revision="",
                media_group_id="album" if album else "",
                observed_at="2026-08-15T12:00:00Z",
                destinations=(self.destination,),
                now=100,
                album_wait_seconds=0,
            )
        claimed = self.box.claim(now=100)
        self.assertIsNotNone(claimed)
        return claimed

    async def test_warning_precedes_native_single_forward_and_records_result(self):
        calls = []

        class Bot:
            async def send_message(_self, **kwargs):
                calls.append(("warning", kwargs))
                return types.SimpleNamespace(message_id=200)

            async def forward_message(_self, **kwargs):
                calls.append(("forward", kwargs))
                return types.SimpleNamespace(message_id=201)

        batch = self.batch()
        runtime = types.SimpleNamespace(outbox=self.box)
        await dragon_den_bot._deliver(Bot(), runtime, batch)

        self.assertEqual([name for name, _ in calls], ["warning", "forward"])
        self.assertIn("UNVERIFIED RAW FORWARD", calls[0][1]["text"])
        self.assertEqual(calls[1][1]["from_chat_id"], "-1009876543210")
        self.assertTrue(calls[1][1]["protect_content"])
        self.assertEqual(self.box.status_counts(), {"COMPLETE": 1})
        row = self.box.conn.execute(
            "SELECT header_message_id, forwarded_message_ids_json FROM deliveries"
        ).fetchone()
        self.assertEqual(row, (200, "[201]"))

    async def test_album_uses_bulk_forward_in_strict_message_order(self):
        calls = []

        class Bot:
            async def send_message(_self, **kwargs):
                return types.SimpleNamespace(message_id=300)

            async def forward_messages(_self, **kwargs):
                calls.append(kwargs)
                return [
                    types.SimpleNamespace(message_id=301),
                    types.SimpleNamespace(message_id=302),
                ]

        batch = self.batch(album=True)
        await dragon_den_bot._deliver(
            Bot(), types.SimpleNamespace(outbox=self.box), batch
        )
        self.assertEqual(calls[0]["message_ids"], [10, 11])
        self.assertEqual(self.box.status_counts(), {"COMPLETE": 2})

    async def test_unavailable_source_post_creates_tombstone_without_copying(self):
        calls = []

        class Bot:
            async def send_message(_self, **kwargs):
                calls.append(kwargs["text"])
                return types.SimpleNamespace(message_id=400 + len(calls))

            async def forward_message(_self, **kwargs):
                raise BadRequest("Message to forward not found")

        batch = self.batch()
        await dragon_den_bot._deliver(
            Bot(), types.SimpleNamespace(outbox=self.box), batch
        )
        self.assertEqual(self.box.status_counts(), {"UNFORWARDABLE": 1})
        self.assertEqual(len(calls), 2)
        self.assertIn("UNVERIFIED RAW FORWARD", calls[0])
        self.assertIn("RAW FORWARD UNAVAILABLE", calls[1])

    async def test_analysis_initialization_failure_never_gates_and_is_throttled(self):
        runtime = types.SimpleNamespace(
            analyzer=None,
            analysis_init_lock=Lock(),
            analysis_retry_at=0.0,
        )
        with patch.object(
            dragon_den_bot.AnalysisService,
            "from_environment",
            side_effect=RuntimeError("broken optional bridge"),
        ) as initialize:
            first = await dragon_den_bot._analysis_service(runtime)
            second = await dragon_den_bot._analysis_service(runtime)
        self.assertIsNone(first)
        self.assertIsNone(second)
        initialize.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
