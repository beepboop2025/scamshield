import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DeploymentContractTests(unittest.TestCase):
    def test_source_expansion_has_only_the_required_writable_paths(self):
        unit = (
            ROOT / "deploy/hetzner/scamshield-source-expansion.service"
        ).read_text()
        writable = {
            path
            for line in unit.splitlines()
            if line.startswith("ReadWritePaths=")
            for path in line.removeprefix("ReadWritePaths=").split()
        }
        self.assertEqual(writable, {"/etc/scamshield/channels.txt"})
        directives = unit.splitlines()
        self.assertEqual(
            {line for line in directives if line.startswith("BindReadOnlyPaths=")},
            {
                "BindReadOnlyPaths=/var/lib/scamshield/scamshield.db:"
                "/run/scamshield-source-expansion/scamshield.db",
                "BindReadOnlyPaths=/var/lib/scamshield/scamshield.db-wal:"
                "/run/scamshield-source-expansion/scamshield.db-wal",
            },
        )
        self.assertEqual(
            {line for line in directives if line.startswith("BindPaths=")},
            {
                "BindPaths=/var/lib/scamshield/scamshield.db-shm:"
                "/run/scamshield-source-expansion/scamshield.db-shm",
            },
        )
        self.assertEqual(
            {line for line in directives if line.startswith("InaccessiblePaths=")},
            {
                "InaccessiblePaths=/etc/scamshield/scamshield.env",
                "InaccessiblePaths=/var/lib/scamshield",
            },
        )
        self.assertIn("Requires=scamshield-monitor.service", directives)

    def test_deploy_wrapper_runs_the_verified_target_updater(self):
        wrapper = (ROOT / "deploy/hetzner/deploy-wrapper.sh").read_text()
        self.assertIn('merge-base --is-ancestor "$target" origin/master', wrapper)
        self.assertIn('show "${target}:deploy/hetzner/update.sh"', wrapper)
        self.assertNotIn(
            "/opt/scamshield/current/deploy/hetzner/update.sh",
            wrapper,
        )


if __name__ == "__main__":
    unittest.main()
