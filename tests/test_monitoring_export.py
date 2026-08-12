import sqlite3
import tempfile
import unittest
from datetime import date
from pathlib import Path

from scamshield.analysis import AnalysisService, ObservationContext
from scamshield.iocstore import IocStore
from scamshield.monitoring_export import (
    MonitoringExportPolicy,
    build_monitoring_summary,
    serialize_monitoring_summary,
)
from scamshield.provenance import ProvenanceEngine
from scamshield.rates import MarketRateOracle, RateObservation


PACK = Path(__file__).resolve().parents[1] / "scamshield" / "data" / "intelligence-pack-v1.json"


class _FixedRate:
    name = "fixed"

    def fetch(self):
        return RateObservation("fixed", 92.0, "2026-08-08T00:00:00Z", "https://example.test")


class MonitoringExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = IocStore(Path(self.temp.name) / "scamshield.db")
        self.service = AnalysisService(
            rate_oracle=MarketRateOracle([_FixedRate()]),
            provenance_engine=ProvenanceEngine.from_path(PACK),
        )

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def _record(self, source_key, message_id, text):
        self.store.register_collector_source(
            source_key,
            configured_ref_sha256=("a" if message_id == 1 else "b") * 24,
            surface="public_channel",
            authorization="public",
        )
        observed_at = f"2026-08-08T12:0{message_id}:00Z"
        self.store.claim_telegram_message(
            source_key, message_id, observed_at=observed_at,
        )
        context = ObservationContext(
            surface="public_channel",
            authorization="public",
            source_pseudonym=source_key,
            script_hints=("latin",),
            observed_at=observed_at,
        )
        result = self.service.analyze(text, collection=context)
        self.store.record_telegram_result(source_key, message_id, result)
        return result

    def test_eligible_summary_contains_aggregates_but_no_private_evidence(self):
        secret_text = "Crystal meth stock available. Home delivery, USDT. DM @privatelead"
        result = self._record("1" * 24, 1, secret_text)
        self._record("2" * 24, 2, "ordinary public-channel update")
        summary = build_monitoring_summary(
            self.store,
            date(2026, 8, 8),
            policy=MonitoringExportPolicy(min_messages=2, min_sources=2),
            today=date(2026, 8, 9),
        )
        encoded = serialize_monitoring_summary(summary)

        self.assertEqual(summary["detections"]["status"], "AVAILABLE_FOR_REVIEW")
        self.assertEqual(summary["coverage"]["messages_observed"], 2)
        self.assertEqual(summary["coverage"]["sources_observed"], 2)
        self.assertEqual(summary["detections"]["family_counts"]["NARCOTICS"], 1)
        self.assertTrue(summary["window"]["complete"])
        for private_value in (
            "1" * 24,
            "2" * 24,
            "@privatelead",
            secret_text,
            result.provenance.assessment_id,
        ):
            self.assertNotIn(private_value, encoded)

    def test_sparse_summary_exposes_missing_coverage_not_detection_counts(self):
        self._record("3" * 24, 1, "ordinary public-channel update")
        summary = build_monitoring_summary(
            self.store,
            date(2026, 8, 8),
            policy=MonitoringExportPolicy(min_messages=20, min_sources=2),
            today=date(2026, 8, 8),
        )
        self.assertEqual(summary["coverage"]["messages_observed"], 1)
        self.assertEqual(summary["detections"]["status"], "INSUFFICIENT_COVERAGE")
        self.assertEqual(summary["detections"]["tier_counts"], {})
        self.assertFalse(summary["window"]["complete"])

    def test_export_policy_is_bounded(self):
        with self.assertRaises(ValueError):
            MonitoringExportPolicy(min_messages=0)
        with self.assertRaises(ValueError):
            MonitoringExportPolicy(min_sources=0)

    def test_read_only_store_can_render_without_mutating_schema(self):
        path = Path(self.temp.name) / "scamshield.db"
        read_only = IocStore(path, read_only=True)
        try:
            summary = build_monitoring_summary(
                read_only,
                date(2026, 8, 8),
                policy=MonitoringExportPolicy(min_messages=1, min_sources=1),
            )
            self.assertEqual(summary["coverage"]["messages_observed"], 0)
            with self.assertRaises(sqlite3.OperationalError):
                read_only.record({"handles": ["@cannotwrite"]}, sample="")
        finally:
            read_only.close()


if __name__ == "__main__":
    unittest.main()
