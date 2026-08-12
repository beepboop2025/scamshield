import unittest

from scamshield.service_health import notify_systemd, watchdog_interval


class ServiceHealthTests(unittest.TestCase):
    def test_non_systemd_process_is_a_noop(self):
        self.assertFalse(notify_systemd("READY=1", {}))
        self.assertIsNone(watchdog_interval({}))

    def test_watchdog_uses_half_the_systemd_interval(self):
        self.assertEqual(watchdog_interval({"WATCHDOG_USEC": "120000000"}), 60.0)
        self.assertIsNone(watchdog_interval({"WATCHDOG_USEC": "not-a-number"}))


if __name__ == "__main__":
    unittest.main()
