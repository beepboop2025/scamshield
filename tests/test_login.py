import unittest

from login import monitoring_phone


class MonitoringPhoneTests(unittest.TestCase):
    def test_uses_configured_e164_phone_without_prompting(self):
        phone = monitoring_phone(
            {"SCAMSHIELD_PHONE": " +919876543210 "},
            lambda _message: self.fail("prompt should not run"),
        )
        self.assertEqual(phone, "+919876543210")

    def test_prompts_once_when_phone_is_not_persisted(self):
        prompts = []
        phone = monitoring_phone({}, lambda message: prompts.append(message) or "+15551234567")
        self.assertEqual(phone, "+15551234567")
        self.assertEqual(len(prompts), 1)

    def test_rejects_non_e164_phone(self):
        with self.assertRaisesRegex(SystemExit, "E.164"):
            monitoring_phone({}, lambda _message: "555-1234")


if __name__ == "__main__":
    unittest.main()
