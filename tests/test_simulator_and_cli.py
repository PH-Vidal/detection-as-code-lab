"""End-to-end tests for the Purple Team attack simulator and `dac-lab` CLI."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from detection_engine.cli import main


class TestEndToEndLabAndCLI(unittest.TestCase):
    def test_validate_rules_cli_succeeds(self) -> None:
        exit_code = main(["validate-rules"])
        self.assertEqual(exit_code, 0)

    def test_run_lab_end_to_end_generates_expected_alerts_incidents_and_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir) / "lab_out"
            exit_code = main(["run-lab", "--scenario", "all", "--output-dir", str(out_dir)])
            self.assertEqual(exit_code, 0)

            json_path = out_dir / "alerts.json"
            md_path = out_dir / "incident_triage.md"
            html_path = out_dir / "soc_dashboard.html"
            layer_path = out_dir / "attack_layer.json"
            siem_dir = out_dir / "siem_queries"

            for artifact in (
                json_path,
                md_path,
                html_path,
                layer_path,
                siem_dir / "splunk_queries.spl",
                siem_dir / "elastic_queries.kql",
                siem_dir / "sentinel_queries.kql",
            ):
                self.assertTrue(artifact.is_file(), f"Expected artifact missing: {artifact}")

            report = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(report["rules_loaded"], 11)
            self.assertGreaterEqual(report["events_processed"], 40)
            # All 11 Sigma rules should fire cleanly on the full Purple Team multi-domain chain
            self.assertEqual(report["total_alerts"], 11)
            # 3 attacker entities: 198.51.100.77 (SSH+Linux+DNS), 203.0.113.45 (Web), 192.0.2.55 (AWS)
            self.assertEqual(report["total_incidents"], 3)

            observed = set(report["mitre_techniques_observed"])
            for expected_technique in (
                "T1110.001",
                "T1078",
                "T1190",
                "T1595.003",
                "T1059.004",
                "T1003.008",
                "T1136.001",
                "T1098.001",
                "T1562.008",
                "T1071.004",
                "T1048.003",
            ):
                self.assertIn(expected_technique, observed)

            md_text = md_path.read_text(encoding="utf-8")
            self.assertIn("NIST SP 800-61", md_text)
            self.assertIn("Correlated Kill-Chain Incidents", md_text)
            self.assertIn("198.51.100.77", md_text)
            self.assertIn("192.0.2.55", md_text)

            html_text = html_path.read_text(encoding="utf-8")
            self.assertIn("SOC Operations Dashboard", html_text)
            self.assertIn("Correlated Kill-Chain Incidents", html_text)

            layer = json.loads(layer_path.read_text(encoding="utf-8"))
            self.assertEqual(layer["domain"], "enterprise-attack")
            self.assertGreaterEqual(len(layer["techniques"]), 11)

    def test_detect_fail_on_alert_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            logs_dir = Path(tmpdir) / "logs"
            self.assertEqual(
                main(["simulate", "--scenario", "cloud_iam_abuse", "--output", str(logs_dir)]),
                0,
            )
            exit_code = main(["detect", "--logs", str(logs_dir), "--fail-on-alert"])
            self.assertEqual(exit_code, 2)

    def test_standalone_export_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            layer_out = Path(tmpdir) / "coverage.json"
            siem_out = Path(tmpdir) / "siem"
            self.assertEqual(main(["export-attack-layer", "--output", str(layer_out)]), 0)
            self.assertEqual(
                main(["export-siem", "--target", "splunk", "--output-dir", str(siem_out)]), 0
            )
            self.assertTrue(layer_out.is_file())
            self.assertTrue((siem_out / "splunk_queries.spl").is_file())


if __name__ == "__main__":
    unittest.main()
