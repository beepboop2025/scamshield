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
        self.assertEqual(writable, {
            "/etc/scamshield/channels.txt",
            "-/var/lib/scamshield/scamshield.db-shm",
        })
        for inaccessible in (
            "/etc/scamshield/scamshield.env",
            "/var/lib/scamshield/telegram",
            "/var/lib/scamshield/review",
            "/var/lib/scamshield/handoffs",
        ):
            self.assertIn(inaccessible, unit)

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
