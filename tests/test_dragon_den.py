import json
import copy
import sqlite3
import tempfile
import types
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scamshield.dragon_den import (
    Destination,
    DragonDenError,
    DragonDenOutbox,
    canonical_observed_at,
    disclaimer_text,
    load_routes,
    normalize_public_source,
    source_from_chat,
)


class DragonDenRouteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "routes.json"
        self.value = {
            "schema_version": "scamshield-dragon-den-routes/v1",
            "destinations": [
                {"id": "all", "chat_id": "@dragon_den_feed", "label": "All"},
                {"id": "economy", "chat_id": "-1001234567890", "label": "Economy"},
            ],
            "catch_all_destination_ids": ["all"],
            "sources": [{
                "source": "https://t.me/Public_Source",
                "label": "Public source",
                "destination_ids": ["economy"],
                "enabled": True,
            }],
        }

    def tearDown(self):
        self.temp.cleanup()

    def write(self):
        self.path.write_text(json.dumps(self.value))
        return load_routes(self.path)

    def test_catch_all_and_topic_routes_fan_out(self):
        routes = self.write()
        destinations = routes.destinations_for("@PUBLIC_SOURCE")
        self.assertEqual([item.id for item in destinations], ["all", "economy"])
        self.assertEqual(routes.destinations_for("@not_configured"), ())

    def test_sources_must_be_public_usernames_not_numeric_or_invite_links(self):
        for source in ("-1001234567890", "https://t.me/+privateInvite", "public_source"):
            with self.subTest(source=source):
                self.value["sources"][0]["source"] = source
                with self.assertRaises(DragonDenError):
                    self.write()

    def test_unknown_routes_duplicates_and_policy_extensions_fail_closed(self):
        mutations = [
            lambda value: value["sources"][0]["destination_ids"].append("missing"),
            lambda value: value["catch_all_destination_ids"].clear(),
            lambda value: value["destinations"].append(dict(value["destinations"][0])),
            lambda value: value.update({"allow_private": True}),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                value = copy.deepcopy(self.value)
                mutate(value)
                self.path.write_text(json.dumps(value))
                with self.assertRaises(DragonDenError):
                    load_routes(self.path)

    def test_duplicate_json_keys_and_destination_chats_fail_closed(self):
        self.path.write_text(
            '{"schema_version":"scamshield-dragon-den-routes/v1",'
            '"schema_version":"scamshield-dragon-den-routes/v1",'
            '"destinations":[],"catch_all_destination_ids":[],"sources":[]}'
        )
        with self.assertRaisesRegex(DragonDenError, "repeats JSON key"):
            load_routes(self.path)

        self.value["destinations"][1]["chat_id"] = "@DRAGON_DEN_FEED"
        with self.assertRaisesRegex(DragonDenError, "chat_id is duplicated"):
            self.write()

    def test_incoming_chat_requires_a_public_username(self):
        self.assertEqual(
            source_from_chat(types.SimpleNamespace(username="Public_Source")),
            "@public_source",
        )
        with self.assertRaises(DragonDenError):
            source_from_chat(types.SimpleNamespace(username=None))

    def test_normalizer_rejects_paths_queries_and_non_telegram_hosts(self):
        self.assertEqual(normalize_public_source("@Source_Name"), "@source_name")
        for source in (
            "https://t.me/source/42",
            "https://t.me/source?single=1",
            "https://telegram.me/source",
        ):
            with self.assertRaises(DragonDenError):
                normalize_public_source(source)


class DragonDenOutboxTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "dragon-den.db"
        self.box = DragonDenOutbox(self.path)
        self.all = Destination("all", "@dragon_den_feed", "All")
        self.economy = Destination("economy", "-1001234567890", "Economy")
        self.observed = "2026-08-15T12:00:00Z"

    def tearDown(self):
        self.box.close()
        self.temp.cleanup()

    def enqueue(self, message_id=10, **kwargs):
        values = {
            "source": "@public_source",
            "source_chat_id": "-1009876543210",
            "source_message_id": message_id,
            "revision": "",
            "media_group_id": "",
            "observed_at": self.observed,
            "destinations": (self.all, self.economy),
            "now": 100,
        }
        values.update(kwargs)
        return self.box.enqueue(**values)

    def test_duplicate_updates_are_idempotent_and_destinations_are_independent(self):
        first = self.enqueue()
        second = self.enqueue()
        self.assertEqual(first, second)
        self.assertEqual(self.box.status_counts(), {"PENDING": 2})

        batch = self.box.claim(now=100)
        self.assertIsNotNone(batch)
        self.assertEqual(len(batch.deliveries), 1)
        self.box.record_header(batch, 50, now=100)
        self.box.complete(batch, [51], now=100)
        self.assertEqual(self.box.status_counts(), {"COMPLETE": 1, "PENDING": 1})

    def test_album_waits_for_members_then_claims_them_in_order(self):
        self.enqueue(
            12, media_group_id="album-1", destinations=(self.all,), now=100,
        )
        self.enqueue(
            11, media_group_id="album-1", destinations=(self.all,), now=101,
        )
        self.assertIsNone(self.box.claim(now=102))
        batch = self.box.claim(now=103)
        self.assertEqual(
            [item.source_message_id for item in batch.deliveries], [11, 12]
        )
        warning = disclaimer_text(batch)
        self.assertIn("2-POST ALBUM", warning)
        self.assertIn("UNVERIFIED RAW FORWARD", warning)
        self.assertIn("ScamShield analysis runs separately", warning)

    def test_edit_is_a_distinct_receipt_and_is_visibly_labeled(self):
        original = self.enqueue(destinations=(self.all,))
        edited = self.enqueue(
            destinations=(self.all,), revision="2026-08-15T12:05:00Z",
        )
        self.assertNotEqual(original, edited)
        first = self.box.claim(now=100)
        self.box.record_header(first, 1, now=100)
        self.box.complete(first, [2], now=100)
        revision = self.box.claim(now=100)
        self.assertIn("SOURCE EDIT", disclaimer_text(revision))

    def test_expired_claim_retries_and_completed_rows_do_not_replay(self):
        self.enqueue(destinations=(self.all,))
        abandoned = self.box.claim(now=100, lease_seconds=10)
        self.assertIsNotNone(abandoned)
        self.assertIsNone(self.box.claim(now=109, lease_seconds=10))
        retried = self.box.claim(now=110, lease_seconds=10)
        self.assertEqual(retried.first.receipt_id, abandoned.first.receipt_id)
        self.assertEqual(retried.first.attempts, 2)
        self.box.record_header(retried, 20, now=110)
        self.box.complete(retried, [21], now=110)
        self.assertIsNone(self.box.claim(now=10_000))

    def test_transient_retry_backoff_and_permanent_failure_are_distinct(self):
        self.enqueue(destinations=(self.all,))
        batch = self.box.claim(now=100)
        self.box.retry(batch, "RetryAfter", retry_after=30, now=100)
        self.assertEqual(self.box.status_counts(), {"RETRY": 1})
        self.assertIsNone(self.box.claim(now=129))
        retried = self.box.claim(now=130)
        self.box.unforwardable(retried, "BadRequest", now=130)
        self.assertEqual(self.box.status_counts(), {"UNFORWARDABLE": 1})

    def test_queue_contains_references_but_never_raw_message_content(self):
        raw_message = "send funds to secret-wallet-and-click-bad-link"
        self.enqueue(destinations=(self.all,))
        self.box.close()
        self.assertNotIn(raw_message.encode(), self.path.read_bytes())
        connection = sqlite3.connect(self.path)
        try:
            columns = {
                row[1] for row in connection.execute("PRAGMA table_info(deliveries)")
            }
        finally:
            connection.close()
        self.assertFalse({"raw_text", "message_text", "caption", "media"} & columns)
        self.box = DragonDenOutbox(self.path)

    def test_timestamp_contract_rejects_timezone_free_values(self):
        with self.assertRaises(DragonDenError):
            canonical_observed_at(datetime(2026, 8, 15, 12, 0))
        self.assertEqual(
            canonical_observed_at(datetime(2026, 8, 15, 12, 0, tzinfo=timezone.utc)),
            "2026-08-15T12:00:00Z",
        )


if __name__ == "__main__":
    unittest.main()
