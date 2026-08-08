import tempfile
import unittest
from datetime import date
from pathlib import Path

from scamshield.analysis import AnalysisService, ObservationContext
from scamshield.iocstore import IocStore
from scamshield.liquidity import MonetaryObservation, PublicationPolicy
from scamshield.provenance import ProvenanceEngine
from scamshield.rates import MarketRateOracle, RateObservation

PACK = Path(__file__).resolve().parents[1] / "scamshield" / "data" / "intelligence-pack-v1.json"


class _FixedRate:
    name = "fixed"

    def fetch(self):
        return RateObservation("fixed", 92.0, "2026-08-08T00:00:00Z", "https://example.test")


class TestIocStore(unittest.TestCase):
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

    def test_records_assessment_iocs_and_coverage_without_raw_message(self):
        secret = "private raw message crystal meth stock available now"
        text = f"{secret}. Home delivery, USDT. DM @fastdrop"
        context = ObservationContext.create(
            text, surface="public_channel", authorization="public",
            raw_source="@source", pseudonym_key="local-test-secret",
        )
        result = self.service.analyze(text, collection=context)
        self.store.record(result.iocs, sample="")
        self.store.record_analysis(result)

        assessment = self.store.recent_assessments(1)[0]
        self.assertNotIn(secret, str(assessment))
        self.assertEqual(self.store.digest()[0][:2], ("handle", "@fastdrop"))
        coverage = self.store.coverage_digest()[0]
        self.assertEqual(coverage[0], "public_channel")
        self.assertEqual(coverage[2:5], (1, 1, 0))

    def test_collection_errors_are_counted_separately(self):
        self.store.record_collection_error(
            "public_channel", "abc", observed_at="2026-08-08T12:00:00Z",
        )
        row = self.store.coverage_digest()[0]
        self.assertEqual(row[2:5], (0, 0, 1))

        pulse = self.store.daily_liquidity_pulse(date(2026, 8, 8))
        self.assertEqual(pulse["coverage"]["collection_errors"], 1)

    def test_reviewed_observation_is_bound_to_daily_coverage(self):
        text = (
            "Crystal meth stock available now. Door-to-door delivery, "
            "USDT accepted. DM @reviewme"
        )
        context = ObservationContext.create(
            text,
            surface="private_submission",
            authorization="user_submitted",
            raw_source="telegram-user:42",
            pseudonym_key="local-test-secret",
            observed_at="2026-08-08T12:30:00Z",
        )
        result = self.service.analyze(text, collection=context)
        self.assertNotEqual(result.overall_tier, "CLEAN")
        self.store.record_analysis(result)

        review = self.store.assessment_review_context(
            result.provenance.message_sha256,
            surface="private_submission",
            source_pseudonym=context.source_pseudonym,
        )
        self.assertIsNotNone(review)
        self.assertEqual(
            self.store.assessment_review_context_by_id(review["assessment_id"]),
            review,
        )
        observation = MonetaryObservation(
            observation_id=f"review:{review['assessment_id']}:victim_reported_loss",
            event_key=f"assessment:{review['assessment_id']}",
            measure_type="victim_reported_loss",
            event_at=review["event_at"],
            source_pseudonym=review["source_pseudonym"],
            currency="USD",
            amount_low="125",
            rail="bank_transfer",
            verification="victim_report",
            attribution_confidence="low",
            evidence_refs=(review["assessment_id"],),
        )
        self.store.record_monetary_observation(
            observation, assessment_id=review["assessment_id"],
        )
        pulse = self.store.daily_liquidity_pulse(
            date(2026, 8, 8),
            policy=PublicationPolicy(
                min_messages=1,
                min_sources=1,
                min_events_per_value=1,
                max_source_event_share="1",
                max_source_value_share="1",
            ),
        )
        self.assertEqual(pulse["coverage"]["messages_observed"], 1)
        self.assertEqual(pulse["coverage"]["messages_flagged"], 1)
        bucket = pulse["monetary_observations"]["victim_reported_loss"]
        self.assertEqual(bucket["usd_sum"], "125")
        self.assertNotIn(context.source_pseudonym, str(pulse))

    def test_review_context_requires_the_same_pseudonymized_source(self):
        text = (
            "Crystal meth stock available now. Door-to-door delivery, "
            "USDT accepted. DM @reviewme"
        )
        context = ObservationContext.create(
            text,
            surface="private_submission",
            authorization="user_submitted",
            raw_source="telegram-user:42",
            pseudonym_key="local-test-secret",
            observed_at="2026-08-08T12:30:00Z",
        )
        result = self.service.analyze(text, collection=context)
        self.store.record_analysis(result)
        review = self.store.assessment_review_context(
            result.provenance.message_sha256,
            surface="private_submission",
            source_pseudonym="different-source",
        )
        self.assertIsNone(review)

        with self.assertRaisesRegex(ValueError, "24 lowercase hex"):
            self.store.assessment_review_context_by_id("not-an-assessment")


if __name__ == "__main__":
    unittest.main()
