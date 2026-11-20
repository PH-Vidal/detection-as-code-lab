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

    def test_run_lab_end_to_end_generates_expected_alerts_and_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir) / "lab_out"
            exit_code = main(["run-lab", "--scenario", "all", "--output-dir", str(out_dir)])
            self.assertEqual(exit_code, 0)

            json_path = out_dir / "alerts.json"
            md_path = out_dir / "incident_triage.md"
            self.assertTrue(json_path.is_file())
            self.assertTrue(md_path.is_file())

            report = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(report["rules_loaded"], 8)
            self.assertGreaterEqual(report["events_processed"], 25)
            # All 8 Sigma rules should fire cleanly on the full Purple Team attack chain
            self.assertEqual(report["total_alerts"], 8)

            observed = set(report["mitre_techniques_observed"])
            for expected_technique in (
                "T1110.001",
                "T1078",
                "T1190",
                "T1595.003",
                "T1059.004",
                "T1003.008",
                "T1136.001",
            ):
                self.assertIn(expected_technique, observed)

            md_text = md_path.read_text(encoding="utf-8")
            self.assertIn("NIST SP 800-61", md_text)
            self.assertIn("198.51.100.77", md_text)

    def test_detect_fail_on_alert_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            logs_dir = Path(tmpdir) / "logs"
            self.assertEqual(
                main(["simulate", "--scenario", "web_attacks", "--output", str(logs_dir)]),
                0,
            )
            exit_code = main(["detect", "--logs", str(logs_dir), "--fail-on-alert"])
            self.assertEqual(exit_code, 2)


if __name__ == "__main__":
    unittest.main()
