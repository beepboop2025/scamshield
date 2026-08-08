import unittest
from pathlib import Path

from scamshield.analysis import AnalysisService, ObservationContext
from scamshield.provenance import ProvenanceEngine
from scamshield.rates import MarketRateOracle, RateObservation
from scamshield.rendering import render_analysis

PACK = Path(__file__).resolve().parents[1] / "scamshield" / "data" / "intelligence-pack-v1.json"


class _FixedRate:
    name = "fixed"

    def fetch(self):
        return RateObservation("fixed", 92.0, "2026-08-08T00:00:00Z", "https://example.test")


class TestRendering(unittest.TestCase):
    def setUp(self):
        self.service = AnalysisService(
            rate_oracle=MarketRateOracle([_FixedRate()]),
            provenance_engine=ProvenanceEngine.from_path(PACK),
        )

    def test_private_typology_is_caveated_and_group_withholds_it(self):
        text = "Crystal meth stock available now, home delivery, USDT. DM @fastdrop"
        private = self.service.analyze(text)
        private_html = render_analysis(private, surface="private_submission")
        self.assertIn("TYPOLOGY_MATCH", private_html)
        self.assertIn("do not establish", private_html)

        group_context = ObservationContext.create(
            text, surface="guardian_group", authorization="administrator_authorized",
        )
        group = self.service.analyze(text, collection=group_context)
        group_html = render_analysis(group, surface="guardian_group")
        self.assertNotIn("Telegram-mediated narcotics-market activity", group_html)
        self.assertNotIn("TYPOLOGY_MATCH", group_html)

    def test_renderer_does_not_echo_matched_illicit_terms(self):
        secret_phrase = "crystal meth"
        result = self.service.analyze(
            f"{secret_phrase} stock available now, courier, USDT. @seller"
        )
        rendered = render_analysis(result, surface="private_submission").lower()
        self.assertNotIn(secret_phrase, rendered)
        self.assertIn("possible narcotics-market solicitation", rendered)


if __name__ == "__main__":
    unittest.main()
