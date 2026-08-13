import tempfile
import unittest
from datetime import date, datetime, timezone
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

    def test_product_events_are_aggregate_bounded_and_recent(self):
        self.store.record_product_event(
            "start", "palimpsest_guide", observed_at="2026-08-13T02:00:00Z",
        )
        self.store.record_product_event(
            "start", "palimpsest_guide", observed_at="2026-08-13T03:00:00Z",
        )
        self.store.record_product_event(
            "unsupported_input", "photo", observed_at="2026-08-12T03:00:00Z",
        )
        now = datetime(2026, 8, 13, 12, tzinfo=timezone.utc)
        self.assertEqual(
            self.store.product_event_digest("start", now=now),
            [("palimpsest_guide", 2)],
        )
        self.assertEqual(
            self.store.product_event_digest("unsupported_input", days=1, now=now),
            [],
        )
        database_text = str(self.store.conn.execute(
            "SELECT * FROM product_events_daily"
        ).fetchall())
        self.assertNotIn("telegram-user", database_text)

        with self.assertRaisesRegex(ValueError, "unknown product event"):
            self.store.record_product_event("raw_message", "photo")
        with self.assertRaisesRegex(ValueError, "event_value"):
            self.store.record_product_event("start", "Bad Campaign / user:42")

    def test_monitor_state_is_aggregate_bounded_and_replaceable(self):
        self.store.record_monitor_state(
            started_at=900,
            resolved_sources=12,
            unresolved_sources=1,
            live_queue_depth=3,
            live_queue_capacity=1000,
            live_enqueued=20,
            live_completed=15,
            live_failed=1,
            live_deferred=2,
            last_reconciled=7,
            last_candidates_checked=4,
            now=1000,
        )
        state = self.store.monitor_state()
        self.assertEqual(state["updated_at"], 1000)
        self.assertEqual(state["resolved_sources"], 12)
        self.assertEqual(state["live_queue_depth"], 3)
        self.assertEqual(state["live_deferred"], 2)
        self.assertNotIn("source_key", state)

        with self.assertRaisesRegex(ValueError, "cannot exceed capacity"):
            self.store.record_monitor_state(
                started_at=900,
                resolved_sources=12,
                unresolved_sources=0,
                live_queue_depth=101,
                live_queue_capacity=100,
                live_enqueued=0,
                live_completed=0,
                live_failed=0,
                live_deferred=0,
                last_reconciled=0,
                last_candidates_checked=0,
                now=1000,
            )

    def test_feedback_is_one_privacy_safe_choice_per_assessment(self):
        digest_now = datetime(2026, 8, 13, 12, tzinfo=timezone.utc)
        current_epoch = int(digest_now.timestamp())
        old_epoch = int(datetime(2026, 7, 1, tzinfo=timezone.utc).timestamp())
        assessment_id = "a" * 24
        self.store.record_assessment_feedback(
            assessment_id,
            original_tier="CLEAN",
            response="disagree",
            now=current_epoch - 20,
        )
        self.store.record_assessment_feedback(
            assessment_id,
            original_tier="CLEAN",
            response="unsure",
            now=current_epoch - 10,
        )
        self.store.record_assessment_feedback(
            "b" * 24,
            original_tier="CONFIRMED_PATTERN",
            response="agree",
            now=current_epoch - 5,
        )
        self.store.record_assessment_feedback(
            "d" * 24,
            original_tier="WATCH",
            response="agree",
            now=old_epoch,
        )
        self.assertEqual(
            self.store.assessment_feedback_digest(now=digest_now),
            [
                ("CLEAN", "unsure", 1),
                ("CONFIRMED_PATTERN", "agree", 1),
            ],
        )
        row = self.store.conn.execute(
            "SELECT first_seen, last_seen FROM assessment_feedback WHERE assessment_id = ?",
            (assessment_id,),
        ).fetchone()
        self.assertEqual(row, (current_epoch - 20, current_epoch - 10))

        with self.assertRaisesRegex(ValueError, "assessment_id"):
            self.store.record_assessment_feedback(
                "telegram-user:42", original_tier="CLEAN", response="agree",
            )
        with self.assertRaisesRegex(ValueError, "feedback response"):
            self.store.record_assessment_feedback(
                "c" * 24, original_tier="CLEAN", response="raw-message",
            )
        with self.assertRaisesRegex(ValueError, "tier does not match"):
            self.store.record_assessment_feedback(
                assessment_id,
                original_tier="WATCH",
                response="agree",
            )

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

    def test_monitor_receipts_are_idempotent_and_cursor_is_history_only(self):
        source_key = "a" * 24
        self.store.register_collector_source(
            source_key,
            configured_ref_sha256="b" * 24,
            surface="public_channel",
            authorization="public",
            now=100,
        )
        self.assertEqual(self.store.source_cursor(source_key), (False, 0))
        self.assertTrue(self.store.initialize_source_cursor(source_key, 40))
        self.assertFalse(self.store.initialize_source_cursor(source_key, 5))

        observed_at = "2026-08-08T12:30:00Z"
        self.assertEqual(
            self.store.claim_telegram_message(
                source_key, 42, observed_at=observed_at, now=200,
            ),
            "CLAIMED",
        )
        self.assertEqual(
            self.store.claim_telegram_message(
                source_key, 42, observed_at=observed_at, now=201,
            ),
            "BUSY",
        )
        text = "Crystal meth stock available now. Home delivery, USDT. DM @nextwatch"
        context = ObservationContext(
            surface="public_channel",
            authorization="public",
            source_pseudonym=source_key,
            script_hints=("latin",),
            observed_at=observed_at,
        )
        result = self.service.analyze(text, collection=context)
        self.store.record_telegram_result(
            source_key,
            42,
            result,
            candidates=("@nextwatch",),
            now=202,
        )

        self.assertEqual(
            self.store.claim_telegram_message(
                source_key, 42, observed_at=observed_at, now=300,
            ),
            "COMPLETE",
        )
        self.assertEqual(self.store.source_cursor(source_key), (True, 40))
        self.store.advance_source_cursor(source_key, 42)
        self.assertEqual(self.store.source_cursor(source_key), (True, 42))
        self.assertEqual(self.store.coverage_digest()[0][2:5], (1, 1, 0))
        self.assertEqual(self.store.source_candidates()[0][0], "@nextwatch")
        self.assertEqual(self.store.source_candidates()[0][4], 1)
        self.assertEqual(self.store.source_candidate("@nextwatch")[0], "PENDING")
        self.assertTrue(
            self.store.set_source_candidate_status("@nextwatch", "APPROVED")
        )
        self.assertEqual(self.store.source_candidate("@nextwatch")[0], "APPROVED")

    def test_failed_monitor_claim_is_retryable_and_counted_once_per_failure(self):
        source_key = "c" * 24
        self.store.register_collector_source(
            source_key,
            configured_ref_sha256="d" * 24,
            surface="public_channel",
            authorization="public",
        )
        observed_at = "2026-08-08T12:30:00Z"
        self.assertEqual(
            self.store.claim_telegram_message(
                source_key, 7, observed_at=observed_at, now=100,
            ),
            "CLAIMED",
        )
        self.store.fail_telegram_message(
            source_key,
            7,
            surface="public_channel",
            observed_at=observed_at,
            error_code="RuntimeError",
        )
        self.assertEqual(
            self.store.claim_telegram_message(
                source_key, 7, observed_at=observed_at, now=101,
            ),
            "CLAIMED",
        )
        coverage = self.store.coverage_digest()[0]
        self.assertEqual(coverage[2:5], (0, 0, 1))

    def test_non_text_monitor_message_completes_without_coverage(self):
        source_key = "e" * 24
        self.store.register_collector_source(
            source_key,
            configured_ref_sha256="f" * 24,
            surface="public_channel",
            authorization="public",
        )
        observed_at = "2026-08-08T12:30:00Z"
        self.store.claim_telegram_message(
            source_key, 9, observed_at=observed_at, now=100,
        )
        self.store.complete_telegram_skip(
            source_key,
            9,
            reason="SKIPPED_NO_TEXT",
            observed_at=observed_at,
            now=101,
        )
        self.assertEqual(
            self.store.claim_telegram_message(
                source_key, 9, observed_at=observed_at, now=102,
            ),
            "COMPLETE",
        )
        self.assertEqual(self.store.coverage_digest(), [])

    def test_candidate_review_distinguishes_hits_from_distinct_sources(self):
        text = "Crystal meth stock available now. Home delivery, USDT. DM @crosssource"
        for index, source_key in enumerate(("6" * 24, "7" * 24), start=1):
            self.store.register_collector_source(
                source_key,
                configured_ref_sha256=("8" if index == 1 else "9") * 24,
                surface="public_channel",
                authorization="public",
            )
            observed_at = f"2026-08-08T12:0{index}:00Z"
            self.store.claim_telegram_message(
                source_key, index, observed_at=observed_at,
            )
            context = ObservationContext(
                surface="public_channel",
                authorization="public",
                source_pseudonym=source_key,
                script_hints=("latin",),
                observed_at=observed_at,
            )
            result = self.service.analyze(text, collection=context)
            self.store.record_telegram_result(
                source_key,
                index,
                result,
                candidates=("@crosssource",),
            )

        candidate = self.store.source_candidates()[0]
        self.assertEqual(candidate[0], "@crosssource")
        self.assertEqual(candidate[1], 2)
        self.assertEqual(candidate[4], 2)


if __name__ == "__main__":
    unittest.main()
