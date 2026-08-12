import tempfile
import unittest
from pathlib import Path

from manage_sources import append_public_source
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
            "SCAMSHIELD_CLAIM_LEASE_SECONDS": "120",
            "SCAMSHIELD_ANALYSIS_CONCURRENCY": "2",
            "SCAMSHIELD_FLOOD_SLEEP_THRESHOLD": "30",
            "SCAMSHIELD_AUTO_JOIN_PUBLIC": "0",
        })
        self.assertEqual(settings.initial_history, 25)
        self.assertFalse(settings.auto_join_public)
        with self.assertRaisesRegex(ValueError, "SCAMSHIELD_BACKFILL_BATCH"):
            MonitorSettings.from_environment({"SCAMSHIELD_BACKFILL_BATCH": "1001"})

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


if __name__ == "__main__":
    unittest.main()
