import unittest
from datetime import date

from scamshield.liquidity import CoverageWindow, PublicationPolicy, build_daily_pulse
from scamshield.liquidity_ui import (
    parse_pulse_day,
    parse_review_observation,
    render_liquidity_pulse,
    render_review_confirmation,
    review_id_from_alert,
)


CONTEXT = {
    "assessment_id": "a" * 24,
    "event_at": "2026-08-08T12:30:00Z",
    "source_pseudonym": "source-1",
    "surface": "private_submission",
}


class TestLiquidityUi(unittest.TestCase):
    def test_monitor_alert_exposes_only_an_opaque_review_id(self):
        alert = f"Flagged configured source\n\nReview ID: {'a' * 24}"
        self.assertEqual(review_id_from_alert(alert), "a" * 24)
        self.assertEqual(review_id_from_alert("ordinary bot reply"), "")

    def test_owner_review_parser_builds_a_bound_observation(self):
        observation = parse_review_observation(
            [
                "victim_reported_loss", "USD", "125", "bank_transfer",
                "victim_report", "low",
            ],
            CONTEXT,
        )
        self.assertEqual(observation.amount_low, "125")
        self.assertEqual(observation.event_key, f"assessment:{'a' * 24}")
        self.assertEqual(observation.evidence_refs, ("a" * 24,))

    def test_non_usd_normalization_requires_fx_provenance(self):
        with self.assertRaisesRegex(ValueError, "fx_rate_ref"):
            parse_review_observation(
                [
                    "victim_reported_loss", "INR", "8300", "bank_transfer",
                    "victim_report", "low", "usd=100",
                ],
                CONTEXT,
            )

    def test_parser_rejects_modeled_estimates_in_telegram(self):
        with self.assertRaisesRegex(ValueError, "not reviewable"):
            parse_review_observation(
                [
                    "estimated_proceeds", "USD", "100", "unknown",
                    "official_source", "low",
                ],
                CONTEXT,
            )

    def test_pulse_date_is_bounded_and_explicit(self):
        today = date(2026, 8, 8)
        self.assertEqual(parse_pulse_day([], today=today), today)
        self.assertEqual(parse_pulse_day(["2026-08-07"], today=today), date(2026, 8, 7))
        with self.assertRaisesRegex(ValueError, "future"):
            parse_pulse_day(["2026-08-09"], today=today)

    def test_renderer_names_empty_data_without_calling_it_zero_activity(self):
        pulse = build_daily_pulse(
            CoverageWindow(
                start="2026-08-08T00:00:00Z",
                end="2026-08-09T00:00:00Z",
                surface="authorized_telegram_surfaces",
                messages_observed=1,
                messages_flagged=1,
                source_pseudonyms=("source-1",),
                distinct_campaigns=0,
            ),
            [],
            policy=PublicationPolicy(min_messages=2, min_sources=2),
        )
        rendered = render_liquidity_pulse(pulse)
        self.assertIn("Insufficient Data", rendered)
        self.assertIn("No operator-reviewed monetary observations", rendered)
        self.assertIn("No population extrapolation", rendered)

    def test_confirmation_does_not_expose_source_pseudonym(self):
        observation = parse_review_observation(
            [
                "payment_requested", "INR", "8300", "bank_transfer",
                "unverified", "unverified",
            ],
            CONTEXT,
        )
        rendered = render_review_confirmation(observation)
        self.assertNotIn("source-1", rendered)
        self.assertIn("sum will remain withheld", rendered)


if __name__ == "__main__":
    unittest.main()
