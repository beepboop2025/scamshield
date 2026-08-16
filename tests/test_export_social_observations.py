import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import export_social_observations
from scamshield.social_observation_spool import SocialObservationError


class SocialExportCommandTests(unittest.TestCase):
    def test_hmac_loader_reads_until_eof_after_short_reads(self):
        key = b"bounded-dedicated-test-key-material-0123456789"
        real_read = os.read
        with tempfile.TemporaryDirectory() as directory:
            credential = Path(directory) / "social_export_hmac"
            credential.write_bytes(key + b"\n")
            with (
                patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": directory}),
                patch.object(
                    export_social_observations.os,
                    "read",
                    side_effect=lambda descriptor, size: real_read(
                        descriptor, min(size, 7)
                    ),
                ),
            ):
                loaded = export_social_observations._load_hmac_key()

        self.assertEqual(loaded, key)

    def test_safe_domain_error_message_is_diagnostic(self):
        output = io.StringIO()
        with (
            patch.object(sys, "argv", ["export_social_observations.py"]),
            patch.dict(
                os.environ,
                {"SCAMSHIELD_SOCIAL_OBSERVATIONS_ENABLED": "1"},
            ),
            patch.object(
                export_social_observations,
                "_load_hmac_key",
                return_value=b"x" * 32,
            ),
            patch.object(
                export_social_observations,
                "SocialObservationSpool",
                side_effect=SocialObservationError("social spool is stale"),
            ),
            redirect_stdout(output),
        ):
            status = export_social_observations.main()

        self.assertEqual(status, 1)
        self.assertIn("social spool is stale", output.getvalue())


if __name__ == "__main__":
    unittest.main()
