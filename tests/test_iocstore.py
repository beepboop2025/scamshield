import tempfile
import unittest
from pathlib import Path

from scamshield.analysis import AnalysisService, ObservationContext
from scamshield.iocstore import IocStore
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
        self.store.record_collection_error("public_channel", "abc")
        row = self.store.coverage_digest()[0]
        self.assertEqual(row[2:5], (0, 0, 1))


if __name__ == "__main__":
    unittest.main()
