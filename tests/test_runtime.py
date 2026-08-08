import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scamshield.runtime import channels_file_path, session_base_path, session_file_path


class RuntimePathTests(unittest.TestCase):
    def test_development_defaults_remain_repository_local(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(session_base_path().name, "scamshield_monitor")
            self.assertEqual(session_file_path().name, "scamshield_monitor.session")
            self.assertEqual(channels_file_path().name, "channels.txt")

    def test_server_paths_are_independent_of_release_directory(self):
        root = Path(tempfile.mkdtemp())
        with patch.dict(
            os.environ,
            {
                "SCAMSHIELD_SESSION": str(root / "telegram" / "monitor"),
                "SCAMSHIELD_CHANNELS_FILE": str(root / "config" / "channels.txt"),
            },
            clear=True,
        ):
            self.assertEqual(session_base_path(), root / "telegram" / "monitor")
            self.assertEqual(
                session_file_path(), root / "telegram" / "monitor.session"
            )
            self.assertEqual(channels_file_path(), root / "config" / "channels.txt")

    def test_explicit_session_extension_is_not_duplicated(self):
        with patch.dict(
            os.environ,
            {"SCAMSHIELD_SESSION": "/var/lib/scamshield/monitor.session"},
            clear=True,
        ):
            self.assertEqual(
                session_file_path(), Path("/var/lib/scamshield/monitor.session")
            )


if __name__ == "__main__":
    unittest.main()
