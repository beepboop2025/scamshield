import tempfile
import unittest
from pathlib import Path

from manage_sources import append_public_source, auto_promote_sources
from scamshield.iocstore import IocStore
from scamshield.telegram_sources import (
    MAX_CONFIGURED_SOURCES,
    MonitorSettings,
    discovery_candidates,
    normalize_source_reference,
    parse_source_registry,
)


class TelegramSourceRegistryTests(unittest.TestCase):
    def test_normalizes_public_references_and_numeric_authorized_ids(self):
        self.assertEqual(normalize_source_reference("falconfeedsio"), "@falconfeedsio")
        self.assertEqual(
            normalize_source_reference("https://t.me/s/vx_underground"),
            "@vx_underground",
        )
        self.assertEqual(normalize_source_reference("-1001234567890"), "-1001234567890")

    def test_rejects_invites_paths_and_non_telegram_urls(self):
        for value in (
            "https://t.me/+privateInvite",
            "https://t.me/joinchat/privateInvite",
            "https://t.me/public/123",
            "http://t.me/publicchannel",
            "https://example.test/publicchannel",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_source_reference(value)

    def test_registry_keeps_valid_rows_deduplicated_and_reports_bad_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "channels.txt"
            path.write_text(
                "# configured sources\n"
                "falconfeedsio\n"
                "@FalconFeedsIo\n"
                "https://t.me/+privateInvite\n"
                "-1001234567890\n"
            )
            registry = parse_source_registry(path)

        self.assertEqual(registry.references, ("@falconfeedsio", "-1001234567890"))
        self.assertEqual(len(registry.issues), 1)
        self.assertEqual(registry.issues[0].line_number, 4)

    def test_discovery_is_review_only_and_excludes_invites(self):
        values = discovery_candidates({
            "channels": ["t.me/public_watch", "t.me/+invite"],
            "handles": ["@public_watch", "@PossibleVendor"],
        })
        self.assertEqual(values, ("@public_watch", "@possiblevendor"))

    def test_monitor_settings_are_bounded(self):
        settings = MonitorSettings.from_environment({
            "SCAMSHIELD_INITIAL_HISTORY": "25",
            "SCAMSHIELD_BACKFILL_BATCH": "50",
            "SCAMSHIELD_RECONCILE_SECONDS": "60",
            "SCAMSHIELD_RECONCILE_CONCURRENCY": "3",
            "SCAMSHIELD_SOURCE_REFRESH_SECONDS": "45",
            "SCAMSHIELD_CANDIDATE_VERIFY_SECONDS": "120",
            "SCAMSHIELD_CLAIM_LEASE_SECONDS": "120",
            "SCAMSHIELD_ANALYSIS_CONCURRENCY": "2",
            "SCAMSHIELD_LIVE_WORKERS": "6",
            "SCAMSHIELD_LIVE_QUEUE_SIZE": "256",
            "SCAMSHIELD_FLOOD_SLEEP_THRESHOLD": "30",
            "SCAMSHIELD_AUTO_JOIN_PUBLIC": "0",
            "SCAMSHIELD_DISCOVERY_VERIFY_ENABLED": "1",
            "SCAMSHIELD_DISCOVERY_VERIFY_BATCH": "7",
            "SCAMSHIELD_DISCOVERY_VERIFY_MIN_HITS": "2",
            "SCAMSHIELD_DISCOVERY_VERIFY_MIN_SOURCES": "2",
            "SCAMSHIELD_DISCOVERY_RECHECK_SECONDS": "7200",
            "SCAMSHIELD_DISCOVERY_RETRY_SECONDS": "600",
        })
        self.assertEqual(settings.initial_history, 25)
        self.assertFalse(settings.auto_join_public)
        self.assertEqual(settings.max_reconcile_concurrency, 3)
        self.assertEqual(settings.source_refresh_seconds, 45)
        self.assertEqual(settings.candidate_verify_seconds, 120)
        self.assertEqual(settings.live_worker_count, 6)
        self.assertEqual(settings.live_queue_size, 256)
        self.assertEqual(settings.discovery_verify_batch, 7)
        self.assertEqual(settings.discovery_verify_min_sources, 2)
        with self.assertRaisesRegex(ValueError, "SCAMSHIELD_BACKFILL_BATCH"):
            MonitorSettings.from_environment({"SCAMSHIELD_BACKFILL_BATCH": "1001"})
        with self.assertRaisesRegex(ValueError, "SCAMSHIELD_LIVE_QUEUE_SIZE"):
            MonitorSettings.from_environment({"SCAMSHIELD_LIVE_QUEUE_SIZE": "99"})

    def test_operator_append_is_locked_normalized_and_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "channels.txt"
            path.write_text("# reviewed\n@existing_source")
            self.assertTrue(append_public_source(path, "https://t.me/new_public_source"))
            self.assertFalse(append_public_source(path, "@NEW_PUBLIC_SOURCE"))
            registry = parse_source_registry(path)
        self.assertEqual(
            registry.references,
            ("@existing_source", "@new_public_source"),
        )

    def test_operator_append_enforces_registry_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "channels.txt"
            path.write_text(
                "\n".join(
                    f"@bounded_source_{index:03d}"
                    for index in range(MAX_CONFIGURED_SOURCES)
                )
            )
            with self.assertRaisesRegex(ValueError, "limited to 500"):
                append_public_source(path, "@one_source_too_many")

    def test_auto_promotion_requires_fresh_verification_and_distinct_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "channels.txt"
            path.write_text("# protected registry\n@existing_source\n")
            store = IocStore(root / "scamshield.db")
            try:
                with store.conn:
                    store.conn.execute(
                        """INSERT INTO source_candidates (
                               candidate, first_seen, last_seen, hits,
                               status, referrer_source_key, families_json
                           ) VALUES ('@verified_public', 100, 150, 3, 'PENDING', ?, '[\"sales\"]')""",
                        ("a" * 24,),
                    )
                    for key in ("a" * 24, "b" * 24):
                        store.conn.execute(
                            """INSERT INTO source_candidate_sources (
                                   candidate, source_key, first_seen, last_seen, hits
                               ) VALUES ('@verified_public', ?, 100, 150, 1)""",
                            (key,),
                        )
                self.assertTrue(store.record_source_candidate_verification(
                    "@verified_public",
                    "VERIFIED_PUBLIC_CHANNEL",
                    canonical_reference="@Verified_Public",
                    checked_at=150,
                    next_check=300,
                ))
                self.assertEqual(
                    store.source_candidates_for_verification(now=200),
                    [],
                )
                added = auto_promote_sources(
                    store,
                    path,
                    min_hits=2,
                    min_sources=2,
                    max_configured=10,
                    verification_max_age=100,
                    now=200,
                )
                self.assertEqual(added, ("@verified_public",))
                self.assertEqual(
                    parse_source_registry(path).references,
                    ("@existing_source", "@verified_public"),
                )
            finally:
                store.close()

    def test_auto_promotion_honors_registry_cap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "channels.txt"
            path.write_text("@existing_source\n")
            store = IocStore(root / "scamshield.db")
            try:
                self.assertEqual(
                    auto_promote_sources(store, path, max_configured=1),
                    (),
                )
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
