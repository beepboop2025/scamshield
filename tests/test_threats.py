import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scamshield.detector import classify, extract_iocs
from scamshield.threats import ThreatEngine


class TestThreatEngine(unittest.TestCase):
    def setUp(self):
        self.engine = ThreatEngine()

    def assess(self, text):
        return self.engine.assess(text, classify(text, allow_rate=False))

    def test_narcotics_offer_needs_transactional_evidence(self):
        result = self.assess(
            "Crystal meth stock available now. Door-to-door delivery, "
            "USDT accepted. DM @fastdrop"
        )
        self.assertEqual(result.tier, "CONFIRMED_PATTERN")
        finding = result.findings[0]
        self.assertEqual(finding.rule_id, "narcotics_trade_offer")
        self.assertTrue({"subject", "offer", "payment", "fulfilment", "contact"}
                        <= set(finding.evidence_classes))

    def test_drug_news_or_health_topic_is_not_an_offer(self):
        for text in (
            "Police seized crystal meth from a dealer; this is a warning.",
            "A public-health seminar discusses fentanyl overdose prevention.",
        ):
            with self.subTest(text=text):
                self.assertEqual(self.assess(text).tier, "CLEAN")

    def test_wildlife_lead_is_capped_below_confirmation(self):
        result = self.assess(
            "Raw elephant ivory stock ready, no CITES, discreet courier, "
            "USDT accepted. Contact @raretrade"
        )
        self.assertEqual(result.tier, "LIKELY_SCAM")
        self.assertEqual(result.findings[0].rule_id, "wildlife_trade_offer")

    def test_museum_wildlife_context_is_clean(self):
        self.assertEqual(
            self.assess("Museum exhibition on elephant ivory conservation and CITES rules.").tier,
            "CLEAN",
        )

    def test_task_and_impersonation_scam_patterns(self):
        task = self.assess(
            "Rating task job: recharge first, guaranteed daily commission. "
            "Contact @taskdesk"
        )
        self.assertIn(task.tier, {"LIKELY_SCAM", "CONFIRMED_PATTERN"})
        self.assertIn("task_scam_pattern", task.signal_names)

        phishing = self.assess(
            "Digital arrest: share OTP and install AnyDesk from "
            "https://verify-account.example/login"
        )
        self.assertEqual(phishing.tier, "LIKELY_SCAM")
        self.assertIn("impersonation_phishing_pattern", phishing.signal_names)

    def test_security_research_is_not_stolen_data_offer(self):
        result = self.assess(
            "Cybersecurity research paper studying CVV dumps and phishing kits."
        )
        self.assertEqual(result.tier, "CLEAN")

    def test_forced_labour_recruitment_is_safeguarding_lead(self):
        result = self.assess(
            "Casino job in Myawaddy. Passport held, visa arranged. "
            "Contact @jobdesk"
        )
        self.assertEqual(result.tier, "LIKELY_SCAM")
        self.assertIn("forced_labour_recruitment_risk", result.signal_names)

    def test_chinese_narcotics_offer(self):
        result = self.assess("冰毒现货，支持快递，比特币付款，联系 @seller_cn")
        self.assertIn(result.tier, {"LIKELY_SCAM", "CONFIRMED_PATTERN"})
        self.assertIn("narcotics_trade_offer", result.signal_names)


class TestExpandedIocs(unittest.TestCase):
    def test_urls_emails_and_bitcoin_are_extracted(self):
        address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
        iocs = extract_iocs(
            f"Visit https://bad.example/path, mail fraud@example.org, pay {address}."
        )
        self.assertEqual(iocs["urls"], ["https://bad.example/path"])
        self.assertEqual(iocs["emails"], ["fraud@example.org"])
        self.assertIn(address, iocs["wallets"])


if __name__ == "__main__":
    unittest.main()
