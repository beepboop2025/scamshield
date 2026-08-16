import os
import subprocess
import sys
import tempfile
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

    def test_social_projection_validator_imports_from_unrelated_cwd(self):
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONPATH": str(ROOT),
        }
        with tempfile.TemporaryDirectory() as directory:
            completed = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "from scamshield.social_observation_spool import "
                    "validate_public_registry_projection",
                ],
                cwd=directory,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_social_export_deployment_preserves_operator_authorization(self):
        installer = (ROOT / "deploy/hetzner/install.sh").read_text()
        updater = (ROOT / "deploy/hetzner/update.sh").read_text()
        registry = "/etc/scamshield/palimpsest-social-sources.json"

        self.assertIn("/var/lib/scamshield/social-export", installer)
        self.assertIn("/var/lib/scamshield/social-export", updater)
        self.assertIn("/var/lib/scamshield/social/social-observations.db", updater)
        self.assertIn("-g caddy -m 2750", installer)
        self.assertIn("-g scamshield-runtime -m 0700", installer)
        self.assertIn("-o root -g scamshield -m 3771 /var/lib/scamshield", installer)
        self.assertIn("chown root:scamshield /var/lib/scamshield", updater)
        self.assertIn("chmod 3771 /var/lib/scamshield", updater)
        self.assertIn(f"social_registry={registry}", updater)
        self.assertIn('elif [[ ! -e "$social_registry" ]]', updater)
        self.assertIn(
            '"$scam_release/palimpsest-social-sources.example.json"',
            updater,
        )
        self.assertIn('chown root:scamshield-runtime "$social_registry"', updater)
        self.assertIn('chmod 0640 "$social_registry"', updater)
        self.assertNotIn("SCAMSHIELD_SOCIAL_OBSERVATIONS_ENABLED=1", installer)
        self.assertNotIn("SCAMSHIELD_SOCIAL_OBSERVATIONS_ENABLED=1", updater)
        self.assertNotIn("SCAMSHIELD_SOCIAL_EXPORT_HMAC_KEY=", installer)
        self.assertNotIn("SCAMSHIELD_SOCIAL_EXPORT_HMAC_KEY=", updater)
        self.assertIn("social-export-hmac.key", installer)
        self.assertIn("dedicated signing credential", updater)
        self.assertIn("validate_public_registry_projection", updater)
        self.assertIn(
            'PYTHONPATH="$scam_release" "$scam_release/.venv/bin/python" -',
            updater,
        )
        self.assertLess(
            updater.index("validate_public_registry_projection"),
            updater.index("quarantined legacy social export tree"),
        )
        self.assertIn("trap rollback ERR", updater)
        self.assertLess(
            updater.index("chmod 3751 /var/lib/scamshield"),
            updater.index("quarantined legacy social export tree"),
        )
        self.assertIn('chown root:root "$social_output"', updater)
        rollback = updater[
            updater.index("rollback() {") : updater.index(
                "# The old monitor-owned public tree"
            )
        ]
        self.assertLess(
            rollback.index("chmod 3751 /var/lib/scamshield"),
            rollback.index('mv "$social_output" "$failed_output"'),
        )
        self.assertIn(
            "trap 'chmod 3771 /var/lib/scamshield >/dev/null 2>&1 || true' EXIT",
            rollback,
        )
        self.assertNotIn("quarantined legacy social export tree", installer)
        self.assertNotIn("chown -R", updater)
        self.assertNotIn("chmod -R 0750", updater)
        self.assertIn(
            'install -d -o scamshield-social-export -g caddy -m 2750 '
            '"$social_generations"',
            updater,
        )
        preflight = (ROOT / "deploy/hetzner/preflight.sh").read_text()
        self.assertIn('"$component" == "monitor"', preflight)
        self.assertIn(
            "social_db=/var/lib/scamshield/social/social-observations.db",
            preflight,
        )
        self.assertIn("/var/lib/scamshield/social-observations.db", preflight)
        self.assertIn("validate_public_registry_projection", preflight)

    def test_social_exporter_has_a_separate_uid_and_monitor_cannot_write_its_tree(self):
        exporter = (
            ROOT / "deploy/hetzner/scamshield-social-export.service"
        ).read_text()
        monitor = (ROOT / "deploy/hetzner/scamshield-monitor.service").read_text()
        installer = (ROOT / "deploy/hetzner/install.sh").read_text()
        updater = (ROOT / "deploy/hetzner/update.sh").read_text()

        self.assertIn("User=scamshield-social-export", exporter)
        self.assertIn("Group=scamshield-social", exporter)
        self.assertIn("SupplementaryGroups=scamshield-runtime", exporter)
        self.assertIn(
            "ReadOnlyPaths=/var/lib/scamshield/social-export",
            monitor,
        )
        self.assertNotIn("SupplementaryGroups=scamshield-runtime caddy", monitor)
        self.assertIn("useradd --system --home-dir /nonexistent", installer)
        self.assertIn("scamshield-social-export:caddy", updater)
        self.assertIn("640:scamshield:scamshield-social", (
            ROOT / "deploy/hetzner/preflight.sh"
        ).read_text())

    def test_hostile_input_services_cannot_replace_public_export_tree(self):
        read_only_unit = (
            ROOT / "deploy/hetzner/scamshield-monitor.service"
        ).read_text()
        self.assertIn(
            "ReadOnlyPaths=/var/lib/scamshield/social-export",
            read_only_unit,
        )
        for unit_name in (
            "scamshield-bot.service",
            "scamshield-dragon-den.service",
            "scamshield-feed.service",
        ):
            unit = (ROOT / "deploy/hetzner" / unit_name).read_text()
            self.assertIn(
                "InaccessiblePaths=/var/lib/scamshield/social-export",
                unit,
                unit_name,
            )

        preflight = (ROOT / "deploy/hetzner/preflight.sh").read_text()
        self.assertIn("3771:root:scamshield", preflight)

    def test_palimpsest_bridge_is_pinned_to_merged_social_contract(self):
        revision = (ROOT / "deploy/hetzner/palimpsest.rev").read_text().strip()

        self.assertEqual(revision, "b2e768b27005f1153d1f6fa0c42629567f09a0ae")

    def test_social_export_timer_is_installed_without_enabling_service(self):
        updater = (ROOT / "deploy/hetzner/update.sh").read_text()

        self.assertIn('"$scam_release/export_social_observations.py"', updater)
        self.assertIn("scamshield-social-export.service", updater)
        self.assertIn("scamshield-social-export.timer", updater)
        self.assertIn(
            "systemctl enable --now scamshield-social-export.timer",
            updater,
        )
        self.assertNotIn(
            "systemctl enable --now scamshield-social-export.service",
            updater,
        )
        self.assertIn(
            "systemctl disable --now scamshield-social-export.timer",
            updater,
        )
        installer = (ROOT / "deploy/hetzner/install.sh").read_text()
        self.assertIn(
            "systemctl enable --now scamshield-social-export.timer",
            installer,
        )

    def test_social_caddy_fragment_exposes_only_fixed_aliases(self):
        fragment = (
            ROOT / "deploy/hetzner/palimpsest-social-observations.caddy"
        ).read_text()

        self.assertIn("/palimpsest/social-observations/latest.json", fragment)
        self.assertIn("/palimpsest/social-observations/versions.jsonl", fragment)
        self.assertIn("/palimpsest/social-observations/hmac.json", fragment)
        self.assertIn("/var/lib/scamshield/social-export/current", fragment)
        self.assertIn("api.seiche.info", fragment)
        self.assertIn("(palimpsest_social_observations)", fragment)
        self.assertIn("route {", fragment)
        self.assertEqual(fragment.count("method GET HEAD"), 3)
        self.assertIn("respond 404", fragment)
        self.assertNotIn("generations/*", fragment)


if __name__ == "__main__":
    unittest.main()
