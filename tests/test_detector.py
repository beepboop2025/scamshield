"""Offline detector suite. Run: python3 -m unittest discover tests -v

Fixtures are drawn from the 2026-07 'Crypto Library Discussion' screenshot
corpus (paraphrased/truncated but signal-preserving).
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[0].parent))

from scamshield.detector import classify, extract_iocs

INR_WORK_AD = """
🇮🇳INR Work🇮🇳
‼️ Unlimited purchase of USDT!
🇮🇳 Our company has a strong trading team.
🇮🇳 Mixed funds
🇮🇳 Stock funds ?? Imps Instant Payment of Funds
⚡1USDT=110-130++INR⚡
Hybrid Fund‼️1USDT=117-121 INR
Hacker Fund‼️1USDT=128-131 INR
Stock Fund‼️ 1USDT=108-111INR
Game Fund‼️ 1USDT=102-105INR
‼️ Work requires prepayment of USDT!‼️
🎉We will start working after receiving the deposit!!!
⬆️ If you have a large amount of UPI IMPSPSPS ⬆️
Note: Do not request P2P, do not waste time
✈️Telegram: @GJpay_01 (Boss)
✈️Telegram: @GJpay_02 (Boss)
WhatsAPP:+1 (410) 908-5835
Company channel:https://t.me/GJpay012
"""

FAKE_NOTES_AD = "假钞可过验钞机可面交可快递 +98 936 645 6019"

GAMBLING_AD = "赛车.六合彩.PC28.世界杯内幕分享 +972 52 927 0792"

LEGIT_TRADE = """
Hey, I'm looking to buy about 500 USDT on Binance P2P, seeing offers
around 1USDT=89 INR right now. Is WazirX withdrawal working for anyone?
"""

LEGIT_CHAT = "Anyone read the new ERC-7730 clear-signing spec? Thoughts?"


class TestClassify(unittest.TestCase):
    def test_inr_work_ad_is_confirmed(self):
        v = classify(INR_WORK_AD)
        self.assertEqual(v.tier, "CONFIRMED_PATTERN")
        names = {s.name for s in v.signals}
        self.assertIn("above_market_rate", names)
        self.assertIn("tiered_fund_menu", names)
        self.assertIn("upi_usdt_bridge", names)
        self.assertIn("prepaid_demand", names)

    def test_fake_notes_ad_is_confirmed(self):
        self.assertEqual(classify(FAKE_NOTES_AD).tier, "CONFIRMED_PATTERN")

    def test_gambling_ad_flagged(self):
        self.assertIn(classify(GAMBLING_AD).tier,
                      ("LIKELY_SCAM", "CONFIRMED_PATTERN"))

    def test_legit_p2p_trade_not_confirmed(self):
        # Market-rate P2P chatter must never be CONFIRMED even though it
        # mentions USDT, INR, and a rate.
        v = classify(LEGIT_TRADE)
        self.assertIn(v.tier, ("CLEAN", "WATCH"))
        self.assertNotIn("above_market_rate", {s.name for s in v.signals})

    def test_plain_chat_clean(self):
        v = classify(LEGIT_CHAT)
        self.assertEqual(v.tier, "CLEAN")
        self.assertEqual(v.score, 0)


class TestIocs(unittest.TestCase):
    def test_extraction(self):
        iocs = extract_iocs(INR_WORK_AD)
        self.assertIn("@GJpay_01", iocs["handles"])
        self.assertIn("@GJpay_02", iocs["handles"])
        self.assertIn("t.me/GJpay012", iocs["channels"])
        self.assertTrue(any("410" in p for p in iocs["phones"]))

    def test_wallets(self):
        text = "send to TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t or 0x" + "a" * 40
        iocs = extract_iocs(text)
        self.assertEqual(len(iocs["wallets"]), 2)


if __name__ == "__main__":
    unittest.main()
