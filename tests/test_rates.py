import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scamshield.detector import classify
from scamshield.rates import (
    MarketRateOracle,
    RateObservation,
    RateProviderError,
    _fetch_json,
)


class _Provider:
    def __init__(self, name, rate=None, error=None):
        self.name = name
        self.rate = rate
        self.error = error

    def fetch(self):
        if self.error:
            raise RateProviderError(self.error)
        return RateObservation(
            provider=self.name,
            rate=self.rate,
            observed_at="2026-08-08T00:00:00Z",
            source_url=f"https://example.test/{self.name}",
        )


class _Response:
    def __init__(self, final_url):
        self.final_url = final_url
        self.headers = {}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def geturl(self):
        return self.final_url

    def read(self, _limit):
        return b'{"rate": 92}'


class TestMarketRateOracle(unittest.TestCase):
    def test_fetch_rejects_cross_origin_redirects(self):
        response = _Response("https://attacker.example/rate")
        with patch("scamshield.rates.urllib.request.urlopen", return_value=response):
            with self.assertRaisesRegex(RateProviderError, "redirected"):
                _fetch_json("https://rates.example/rate")

    def test_two_agreeing_sources_publish_median(self):
        oracle = MarketRateOracle([
            _Provider("a", 91.0),
            _Provider("b", 93.0),
        ])
        quote = oracle.quote()
        self.assertEqual(quote.status, "CORROBORATED")
        self.assertEqual(quote.rate, 92.0)
        self.assertEqual(quote.sources, ("a", "b"))
        self.assertTrue(quote.numeric_detection_allowed)

    def test_divergence_uses_higher_rate_conservatively(self):
        oracle = MarketRateOracle([
            _Provider("a", 86.0),
            _Provider("b", 96.0),
        ], max_spread_pct=0.05)
        quote = oracle.quote()
        self.assertEqual(quote.status, "DIVERGENT")
        self.assertEqual(quote.rate, 96.0)
        self.assertTrue(any("higher rate" in warning for warning in quote.warnings))

    def test_one_source_is_visible_not_mislabeled_corroborated(self):
        oracle = MarketRateOracle([
            _Provider("good", 92.5),
            _Provider("down", error="offline"),
        ])
        quote = oracle.quote()
        self.assertEqual(quote.status, "SINGLE_SOURCE")
        self.assertEqual(quote.rate, 92.5)
        self.assertTrue(any("only one" in warning for warning in quote.warnings))

    def test_last_success_becomes_stale_when_refresh_fails(self):
        now = [1000.0]
        provider = _Provider("changing", 92.0)
        oracle = MarketRateOracle(
            [provider], ttl_seconds=10, max_stale_seconds=100,
            clock=lambda: now[0],
        )
        self.assertEqual(oracle.quote().status, "SINGLE_SOURCE")
        provider.error = "offline"
        now[0] += 11
        stale = oracle.quote()
        self.assertEqual(stale.status, "STALE")
        self.assertEqual(stale.rate, 92.0)

    def test_total_failure_uses_non_evidentiary_fallback(self):
        oracle = MarketRateOracle([_Provider("down", error="offline")])
        quote = oracle.quote()
        self.assertEqual(quote.status, "FALLBACK")
        self.assertFalse(quote.numeric_detection_allowed)

    def test_numeric_rate_signal_can_be_disabled_without_disabling_detector(self):
        text = "USDT to INR at 128, bank accounts on rent, 3% commission @cashout"
        live = classify(text, market_rate=92.0, allow_rate=True)
        fallback = classify(text, market_rate=92.0, allow_rate=False)
        self.assertIn("above_market_rate", live.names())
        self.assertNotIn("above_market_rate", fallback.names())
        self.assertIn("account_rental_offer", fallback.names())


if __name__ == "__main__":
    unittest.main()
