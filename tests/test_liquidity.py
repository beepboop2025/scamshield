import json
import sys
import unittest
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scamshield.liquidity import (
    CoverageWindow,
    MonetaryObservation,
    PublicationPolicy,
    build_daily_pulse,
)
from scamshield.liquidity_policy import may_publish_value


START = "2026-08-08T00:00:00Z"
END = "2026-08-09T00:00:00Z"
EVENT_AT = "2026-08-08T12:00:00Z"


def _coverage(
    *, messages=100, sources=5, flagged=40, errors=0, sampling_frame_known=False,
):
    return CoverageWindow(
        start=START,
        end=END,
        surface="configured_telegram_sources",
        messages_observed=messages,
        messages_flagged=flagged,
        source_pseudonyms=tuple(f"source-{index}" for index in range(sources)),
        distinct_campaigns=messages,
        collection_errors=errors,
        sampling_frame_known=sampling_frame_known,
    )


def _observation(
    index,
    *,
    measure_type="victim_reported_loss",
    amount="10",
    source_index=None,
    event_key=None,
    currency="USD",
    usd_low=None,
    rail="bank_transfer",
    verification=None,
    observation_id=None,
    event_at=EVENT_AT,
):
    if source_index is None:
        source_index = index % 5
    if verification is None:
        verification = {
            "victim_reported_loss": "victim_report",
            "verified_transfer": "independent_label_agreement",
        }.get(measure_type, "unverified")
    evidence_refs = (
        () if measure_type in {"amount_mentioned", "payment_requested"}
        else (f"evidence-{index}",)
    )
    return MonetaryObservation(
        observation_id=observation_id or f"observation-{index}",
        event_key=event_key or f"event-{index}",
        measure_type=measure_type,
        event_at=event_at,
        source_pseudonym=f"source-{source_index}",
        currency=currency,
        amount_low=amount,
        usd_low=usd_low,
        rail=rail,
        verification=verification,
        attribution_confidence=(
            "high" if measure_type in {"victim_reported_loss", "verified_transfer"}
            else "unverified"
        ),
        evidence_refs=evidence_refs,
        fx_rate_ref=("urn:fx:test" if currency != "USD" and usd_low else ""),
    )


class TestMonetaryObservation(unittest.TestCase):
    def test_verified_transfer_requires_independent_attribution(self):
        with self.assertRaisesRegex(ValueError, "independent attribution"):
            _observation(1, measure_type="verified_transfer", verification="unverified")

    def test_verified_transfer_requires_high_attribution_confidence(self):
        observation = _observation(1, measure_type="verified_transfer")
        with self.assertRaisesRegex(ValueError, "high or direct"):
            replace(observation, attribution_confidence="medium")

    def test_victim_loss_requires_a_report_source(self):
        with self.assertRaisesRegex(ValueError, "report-source verification"):
            _observation(1, verification="official_attribution")

    def test_estimate_requires_a_range_and_evidence(self):
        with self.assertRaisesRegex(ValueError, "amount_high"):
            MonetaryObservation(
                observation_id="estimate-1",
                event_key="estimate-event-1",
                measure_type="estimated_proceeds",
                event_at=EVENT_AT,
                source_pseudonym="source-1",
                currency="USD",
                amount_low="100",
                verification="official_source",
                evidence_refs=("model-1",),
            )

    def test_nonfinite_and_nonpositive_amounts_fail_closed(self):
        for amount in ("NaN", "Infinity", "0", "-1"):
            with self.subTest(amount=amount):
                with self.assertRaisesRegex(ValueError, "finite and positive"):
                    _observation(1, amount=amount)

    def test_non_usd_normalization_requires_fx_provenance(self):
        with self.assertRaisesRegex(ValueError, "fx_rate_ref"):
            MonetaryObservation(
                observation_id="loss-1",
                event_key="loss-event-1",
                measure_type="victim_reported_loss",
                event_at=EVENT_AT,
                source_pseudonym="source-1",
                currency="INR",
                amount_low="1000",
                usd_low="12",
                verification="victim_report",
                evidence_refs=("report-1",),
            )

    def test_usd_normalization_cannot_change_the_native_value(self):
        with self.assertRaisesRegex(ValueError, "preserve"):
            _observation(1, amount="10", usd_low="11")

    def test_usd_estimate_normalization_cannot_change_the_high_bound(self):
        with self.assertRaisesRegex(ValueError, "preserve"):
            MonetaryObservation(
                observation_id="estimate-1",
                event_key="estimate-event-1",
                measure_type="estimated_proceeds",
                event_at=EVENT_AT,
                source_pseudonym="source-1",
                currency="USD",
                amount_low="100",
                amount_high="200",
                usd_low="100",
                usd_high="201",
                verification="official_source",
                attribution_confidence="high",
                evidence_refs=("model-1",),
            )

    def test_policy_seam_never_allows_claimed_or_modeled_values(self):
        self.assertTrue(may_publish_value("victim_reported_loss", "victim_report"))
        self.assertTrue(
            may_publish_value("verified_transfer", "independent_label_agreement")
        )
        self.assertFalse(may_publish_value("amount_mentioned", "official_source"))
        self.assertFalse(may_publish_value("payment_requested", "official_source"))
        self.assertFalse(may_publish_value("estimated_proceeds", "official_source"))
        self.assertFalse(may_publish_value("suspicious_activity", "official_source"))


class TestDailyPulse(unittest.TestCase):
    def test_current_scale_returns_insufficient_data_not_zero_activity(self):
        pulse = build_daily_pulse(
            _coverage(messages=3, sources=0, flagged=1),
            [],
        )
        self.assertEqual(pulse["publication_status"], "INSUFFICIENT_DATA")
        self.assertEqual(pulse["confidence"]["materiality"], "not_estimated")
        for bucket in pulse["monetary_observations"].values():
            self.assertIsNone(bucket["usd_sum"])
            self.assertEqual(bucket["value_status"], "INSUFFICIENT_DATA")

    def test_mentions_and_requests_are_never_summed(self):
        observations = [
            _observation(index, measure_type="amount_mentioned", amount="1000000")
            for index in range(20)
        ] + [
            _observation(
                index + 20,
                measure_type="payment_requested",
                amount="500000",
            )
            for index in range(20)
        ]
        pulse = build_daily_pulse(_coverage(), observations)
        for measure in ("amount_mentioned", "payment_requested"):
            bucket = pulse["monetary_observations"][measure]
            self.assertEqual(bucket["event_count"], 20)
            self.assertEqual(bucket["value_status"], "COUNT_ONLY")
            self.assertIsNone(bucket["usd_sum"])

    def test_diverse_victim_losses_publish_an_observed_sum(self):
        observations = [_observation(index) for index in range(20)]
        pulse = build_daily_pulse(_coverage(), observations)
        bucket = pulse["monetary_observations"]["victim_reported_loss"]
        self.assertEqual(pulse["publication_status"], "OBSERVATIONAL")
        self.assertEqual(bucket["value_status"], "PUBLISHED_OBSERVED_SUM")
        self.assertEqual(bucket["usd_sum"], "200")

    def test_verified_transfers_publish_separately_from_losses(self):
        observations = [
            _observation(index, measure_type="verified_transfer", rail="stablecoin")
            for index in range(20)
        ]
        pulse = build_daily_pulse(_coverage(), observations)
        transfer = pulse["monetary_observations"]["verified_transfer"]
        loss = pulse["monetary_observations"]["victim_reported_loss"]
        self.assertEqual(transfer["usd_sum"], "200")
        self.assertIsNone(loss["usd_sum"])
        self.assertEqual(pulse["rails"], [{"rail": "stablecoin", "event_count": 20}])

    def test_event_concentration_withholds_a_sum(self):
        observations = [
            _observation(index, source_index=(0 if index < 9 else 1 + index % 4))
            for index in range(20)
        ]
        pulse = build_daily_pulse(_coverage(), observations)
        bucket = pulse["monetary_observations"]["victim_reported_loss"]
        self.assertEqual(bucket["value_status"], "WITHHELD_SOURCE_DOMINANCE")
        self.assertIsNone(bucket["usd_sum"])

    def test_value_concentration_withholds_a_sum(self):
        observations = [
            _observation(
                index,
                amount=("100" if index < 4 else "1"),
                source_index=(0 if index < 4 else 1 + (index - 4) % 4),
            )
            for index in range(20)
        ]
        pulse = build_daily_pulse(_coverage(), observations)
        bucket = pulse["monetary_observations"]["victim_reported_loss"]
        self.assertEqual(bucket["value_status"], "WITHHELD_VALUE_DOMINANCE")
        self.assertIsNone(bucket["usd_sum"])

    def test_incomplete_currency_normalization_withholds_the_entire_bucket(self):
        observations = [
            _observation(
                index,
                currency="INR",
                amount="830",
                usd_low=(None if index == 19 else "10"),
            )
            for index in range(20)
        ]
        pulse = build_daily_pulse(_coverage(), observations)
        bucket = pulse["monetary_observations"]["victim_reported_loss"]
        self.assertEqual(bucket["value_status"], "WITHHELD_INCOMPLETE_NORMALIZATION")

    def test_missing_source_withholds_the_entire_bucket(self):
        observations = [_observation(index) for index in range(20)]
        observations[-1] = replace(observations[-1], source_pseudonym="")
        pulse = build_daily_pulse(_coverage(), observations)
        bucket = pulse["monetary_observations"]["victim_reported_loss"]
        self.assertEqual(bucket["value_status"], "WITHHELD_INCOMPLETE_SOURCE")
        self.assertIsNone(bucket["usd_sum"])

    def test_repeated_event_keys_are_deduplicated(self):
        observations = [_observation(index) for index in range(20)]
        observations.append(
            _observation(
                99,
                event_key="event-0",
                source_index=0,
                observation_id="observation-copy",
            )
        )
        pulse = build_daily_pulse(_coverage(), observations)
        self.assertEqual(pulse["coverage"]["duplicate_events_removed"], 1)
        self.assertEqual(
            pulse["monetary_observations"]["victim_reported_loss"]["usd_sum"],
            "200",
        )

    def test_conflicting_duplicate_event_fails_closed(self):
        observations = [
            _observation(1, event_key="same-event", amount="10"),
            _observation(2, event_key="same-event", amount="11"),
        ]
        with self.assertRaisesRegex(ValueError, "conflicting duplicate"):
            build_daily_pulse(_coverage(), observations)

    def test_out_of_window_observation_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "outside coverage window"):
            build_daily_pulse(
                _coverage(),
                [_observation(1, event_at="2026-08-09T00:00:00Z")],
            )

    def test_public_payload_contains_counts_not_source_pseudonyms(self):
        pulse = build_daily_pulse(
            _coverage(),
            [_observation(index) for index in range(20)],
        )
        encoded = json.dumps(pulse, sort_keys=True, allow_nan=False)
        for index in range(5):
            self.assertNotIn(f"source-{index}", encoded)
        self.assertEqual(pulse["coverage"]["active_source_pseudonyms"], 5)

    def test_unknown_sampling_frame_and_collection_errors_remain_visible(self):
        pulse = build_daily_pulse(_coverage(errors=2), [])
        self.assertEqual(pulse["confidence"]["coverage"], "unbounded")
        limitations = " ".join(pulse["limitations"])
        self.assertIn("not a Telegram-wide sample", limitations)
        self.assertIn("Collection errors", limitations)

    def test_invalid_policy_thresholds_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "positive integer"):
            PublicationPolicy(min_messages=0)
        with self.assertRaisesRegex(ValueError, r"\(0, 1\]"):
            PublicationPolicy(max_source_value_share="1.1")


if __name__ == "__main__":
    unittest.main()
