import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scamshield.detector import classify
from scamshield.provenance import (
    ExternalObservation,
    ProvenanceEngine,
    load_intelligence_pack,
)

PACK = Path(__file__).resolve().parents[1] / "scamshield" / "data" / "intelligence-pack-v1.json"
FIXED_TIME = datetime(2026, 8, 8, 12, 0, tzinfo=timezone.utc)


def _engine():
    return ProvenanceEngine.from_path(PACK, clock=lambda: FIXED_TIME)


def _assess(text, observations=()):
    verdict = classify(text, market_rate=92.0)
    return _engine().assess(
        text,
        verdict,
        market_rate={"rate": 92.0, "status": "CORROBORATED"},
        external_observations=observations,
    )


class TestIntelligencePack(unittest.TestCase):
    def test_pack_loads_and_has_all_three_dimensions(self):
        pack = load_intelligence_pack(PACK)
        self.assertEqual(pack.schema, "scamshield-intelligence-pack/v1")
        self.assertEqual(
            {item.dimension for item in pack.typologies},
            {"laundering_mechanism", "operating_ecosystem", "predicate_offence"},
        )
        self.assertEqual(len(pack.digest_sha256), 64)


class TestProvenanceAssessment(unittest.TestCase):
    def test_generic_mule_ad_does_not_invent_a_predicate_origin(self):
        result = _assess(
            "USDT to INR at 128, bank accounts on rent, 3% commission, UPI payout @cashout"
        )
        self.assertTrue(any(
            item.typology_id == "mule-crypto-cashout" for item in result.hypotheses
        ))
        self.assertFalse(any(
            item.dimension == "predicate_offence" for item in result.hypotheses
        ))
        self.assertIn("do not establish", result.origin_answer)

    def test_flying_money_is_a_mechanism_match_not_a_predicate_claim(self):
        result = _assess(
            "Feiqian mirror transaction with net settlement to bypass the foreign exchange quota"
        )
        hypothesis = next(
            item for item in result.hypotheses
            if item.typology_id == "china-underground-banking"
        )
        self.assertEqual(hypothesis.dimension, "laundering_mechanism")
        self.assertEqual(hypothesis.support_level, "TYPOLOGY_MATCH")
        self.assertIn("predicate_offence", result.abstentions)

    def test_golden_triangle_needs_specific_geography_and_a_second_indicator(self):
        result = _assess(
            "Golden Triangle SEZ casino junket offers online casino settlement in USDT"
        )
        self.assertTrue(any(
            item.typology_id == "golden-triangle-scam-casino"
            for item in result.hypotheses
        ))
        geography_only = _assess("I read an article about the Golden Triangle SEZ")
        self.assertFalse(any(
            item.typology_id == "golden-triangle-scam-casino"
            for item in geography_only.hypotheses
        ))

    def test_cartel_language_remains_a_typology_match_without_ioc_evidence(self):
        result = _assess(
            "Sinaloa cartel drug proceeds settled through a peso mirror transaction"
        )
        hypothesis = next(
            item for item in result.hypotheses
            if item.typology_id == "mexico-cartel-drug-proceeds"
        )
        self.assertEqual(hypothesis.support_level, "TYPOLOGY_MATCH")

    def test_wildlife_requires_product_plus_illegality(self):
        clean = _assess("Our museum exhibit explains elephant ivory conservation")
        self.assertFalse(any(
            item.typology_id == "illegal-wildlife-trade" for item in clean.hypotheses
        ))
        result = _assess("Elephant ivory shipment without CITES permit, payment in USDT")
        self.assertTrue(any(
            item.typology_id == "illegal-wildlife-trade" for item in result.hypotheses
        ))

    def test_two_independent_external_backers_make_a_corroborated_lead(self):
        observations = (
            ExternalObservation(
                typology_id="illegal-wildlife-trade",
                evidence_class="blockchain_cluster",
                source_id="analytics-a",
                source_group="analytics-a",
                source_kind="blockchain_analytics",
                match_type="behavior",
                reliability="derived",
                summary="Wallet cluster overlaps a reviewed wildlife-trafficking cluster.",
                artifact_uri="urn:test:cluster-a",
            ),
            ExternalObservation(
                typology_id="illegal-wildlife-trade",
                evidence_class="customs_case",
                source_id="agency-b",
                source_group="agency-b",
                source_kind="authoritative",
                match_type="entity",
                reliability="derived",
                summary="A public customs case names the same counterparty entity.",
                artifact_uri="https://example.test/case-b",
            ),
        )
        result = _assess("payment reference 77", observations)
        hypothesis = next(item for item in result.hypotheses
                          if item.typology_id == "illegal-wildlife-trade")
        self.assertEqual(hypothesis.support_level, "CORROBORATED_LEAD")
        self.assertEqual(hypothesis.independent_backers, 2)

    def test_many_rows_from_one_vendor_are_still_one_backer(self):
        observations = tuple(
            ExternalObservation(
                typology_id="mexico-cartel-drug-proceeds",
                evidence_class=f"behavior_{index}",
                source_id=f"vendor-row-{index}",
                source_group="one-vendor",
                source_kind="blockchain_analytics",
                match_type="behavior",
                reliability="derived",
                summary=f"Vendor observation {index}.",
            )
            for index in range(3)
        )
        hypothesis = _assess("opaque payment", observations).hypotheses[0]
        self.assertEqual(hypothesis.support_level, "TYPOLOGY_MATCH")
        self.assertEqual(hypothesis.independent_backers, 1)

    def test_authoritative_exact_ioc_can_create_a_direct_link(self):
        wallet = "0x" + "1" * 40
        observation = ExternalObservation(
            typology_id="mexico-cartel-drug-proceeds",
            evidence_class="official_case_record",
            source_id="official-case",
            source_group="official-case",
            source_kind="authoritative",
            match_type="exact_ioc",
            reliability="direct",
            summary="The exact wallet appears in an official public case record.",
            artifact_uri="https://example.test/official-case",
            matched_ioc_kind="wallets",
            matched_ioc_value=wallet,
        )
        text = (
            "USDT to INR at 128, bank accounts on rent, 3% commission "
            f"@cashout {wallet}"
        )
        hypothesis = _assess(text, (observation,)).hypotheses[0]
        self.assertEqual(hypothesis.support_level, "DIRECT_LINK")

    def test_exact_ioc_observation_must_bind_this_message(self):
        observation = ExternalObservation(
            typology_id="mexico-cartel-drug-proceeds",
            evidence_class="official_case_record",
            source_id="official-case",
            source_group="official-case",
            source_kind="authoritative",
            match_type="exact_ioc",
            reliability="direct",
            summary="An unrelated wallet appears in an official case record.",
            matched_ioc_kind="wallets",
            matched_ioc_value="0x" + "2" * 40,
        )
        text = (
            "USDT to INR at 128, bank accounts on rent, 3% commission "
            "@cashout 0x" + "1" * 40
        )
        with self.assertRaisesRegex(ValueError, "does not bind"):
            _assess(text, (observation,))

    def test_assessment_hashes_but_does_not_copy_unmatched_private_text(self):
        secret = "private-customer-token-ZXQ-918273"
        result = _assess(secret)
        encoded = json.dumps(result.to_dict(), ensure_ascii=False)
        self.assertNotIn(secret, encoded)
        self.assertEqual(len(result.message_sha256), 64)

    def test_fixed_inputs_produce_a_stable_assessment_id(self):
        first = _assess("Feiqian mirror transaction with net settlement")
        second = _assess("Feiqian mirror transaction with net settlement")
        self.assertEqual(first.assessment_id, second.assessment_id)


if __name__ == "__main__":
    unittest.main()
