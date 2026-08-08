import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scamshield.analysis import AnalysisService, ObservationContext
from scamshield.palimpsest import BridgeReceipt, PalimpsestBridge
from scamshield.provenance import ProvenanceEngine
from scamshield.rates import MarketRateOracle, RateObservation

PACK = Path(__file__).resolve().parents[1] / "scamshield" / "data" / "intelligence-pack-v1.json"


class _FixedRate:
    name = "fixed"

    def fetch(self):
        return RateObservation(
            provider=self.name,
            rate=92.0,
            observed_at="2026-08-08T00:00:00Z",
            source_url="https://example.test/rate",
        )


class _RecordingBridge:
    def __init__(self):
        self.assessment = None

    def publish(self, assessment):
        self.assessment = assessment
        return BridgeReceipt(status="STORED", capsule_sha256="a" * 64)


def _service(bridge=None):
    return AnalysisService(
        rate_oracle=MarketRateOracle([_FixedRate()]),
        provenance_engine=ProvenanceEngine.from_path(PACK),
        bridge=bridge,
    )


class TestAnalysisService(unittest.TestCase):
    def test_threat_only_message_is_promoted_without_rewriting_detector(self):
        text = (
            "Crystal meth stock available now. Door-to-door delivery, "
            "USDT accepted. DM @fastdrop"
        )
        result = _service().analyze(text)
        self.assertEqual(result.detector.tier, "CLEAN")
        self.assertEqual(result.overall_tier, "CONFIRMED_PATTERN")
        self.assertIn("narcotics_trade_offer", result.threats.signal_names)
        self.assertIn("@fastdrop", result.iocs["handles"])
        self.assertIn(
            "telegram-narcotics-market",
            {item.typology_id for item in result.provenance.hypotheses},
        )

    def test_private_source_is_hmac_pseudonymized(self):
        text = "Rating task job: recharge first, guaranteed return. @taskdesk"
        context = ObservationContext.create(
            text,
            surface="authorized_private_channel",
            authorization="operator_authorized",
            raw_source="private-channel-12345",
            pseudonym_key="a-long-local-test-secret",
        )
        encoded = json.dumps(context.to_dict())
        self.assertNotIn("private-channel-12345", encoded)
        self.assertRegex(context.source_pseudonym, r"^[0-9a-f]{24}$")

    def test_bridge_receives_structured_assessment_not_message_text(self):
        bridge = _RecordingBridge()
        secret = "do-not-copy-this-private-message-token"
        result = _service(bridge).analyze(
            secret + " Crystal meth stock available, home delivery, USDT. @seller"
        )
        self.assertEqual(result.bridge.status, "STORED")
        encoded = json.dumps(bridge.assessment)
        self.assertNotIn(secret, encoded)
        self.assertIn("message_sha256", bridge.assessment)
        self.assertIn("threat_assessment", bridge.assessment)
        self.assertIn("collection", bridge.assessment)

    def test_missing_palimpsest_is_nonfatal(self):
        bridge = PalimpsestBridge("/definitely/not/a/palimpsest/repository")
        result = _service(bridge).analyze(
            "Crystal meth stock available, home delivery, USDT. @seller"
        )
        self.assertEqual(result.bridge.status, "FAILED")
        self.assertIn("missing", result.bridge.error)

    def test_clean_messages_are_not_exported(self):
        bridge = _RecordingBridge()
        result = _service(bridge).analyze("ordinary conversation about lunch")
        self.assertEqual(result.bridge.status, "SKIPPED")
        self.assertIsNone(bridge.assessment)


if __name__ == "__main__":
    unittest.main()
