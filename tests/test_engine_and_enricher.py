"""Unit tests for YAML loader, log normalizers, IOC enricher, and webhook URL validation."""

from __future__ import annotations

import unittest
from pathlib import Path

from detection_engine.enricher import IOCEnricher, classify_ip
from detection_engine.models import Alert
from detection_engine.normalizer import parse_log_line
from detection_engine.reporter import validate_discord_webhook_url
from detection_engine.yaml_loader import parse_yaml_stdlib

TI_FEED_PATH = Path(__file__).resolve().parent.parent / "threat_intel" / "ioc_feed.json"


class TestYamlAndNormalizer(unittest.TestCase):
    def test_stdlib_yaml_parser_handles_sigma_structures(self) -> None:
        sample = """
        title: Test Rule # inline comment
        level: high
        tags:
          - attack.t1190
          - attack.initial_access
        detection:
          correlation:
            group_by: source.ip
            stages:
              - ref: failed_attempts
                min_count: 5
              - ref: successful_login
                min_count: 1
          condition: correlation
        """
        parsed = parse_yaml_stdlib(sample)
        self.assertEqual(parsed["title"], "Test Rule")
        self.assertEqual(parsed["tags"], ["attack.t1190", "attack.initial_access"])
        stages = parsed["detection"]["correlation"]["stages"]
        self.assertEqual(stages[0]["ref"], "failed_attempts")
        self.assertEqual(stages[0]["min_count"], 5)

    def test_auto_normalizer_parses_all_three_sources(self) -> None:
        ssh_line = (
            "Nov 20 14:12:01 web-prod-01 sshd[4102]: "
            "Failed password for invalid user admin from 198.51.100.77 port 51234 ssh2"
        )
        ssh = parse_log_line(ssh_line, year=2026)
        self.assertIsNotNone(ssh)
        assert ssh is not None
        self.assertEqual(ssh.source_type, "sshd")
        self.assertEqual(ssh.get("event.action"), "ssh_login_failed")
        self.assertEqual(ssh.get("user.name"), "admin")
        self.assertEqual(ssh.get("source.ip"), "198.51.100.77")

        web = parse_log_line(
            '203.0.113.45 - - [20/Nov/2026:14:15:10 +0000] "GET /.env HTTP/1.1" 404 312 "-" "curl/8.7"'
        )
        self.assertIsNotNone(web)
        assert web is not None
        self.assertEqual(web.source_type, "webserver")
        self.assertEqual(web.get("url.original"), "/.env")
        self.assertEqual(web.get("http.response.status_code"), 404)

        audit = parse_log_line(
            '{"timestamp":"2026-11-20T14:12:45+00:00","host":"web-prod-01","user":"deploy",'
            '"source_ip":"198.51.100.77","process":"bash","command_line":"cat /etc/shadow","pid":4822}'
        )
        self.assertIsNotNone(audit)
        assert audit is not None
        self.assertEqual(audit.source_type, "linux_audit")
        self.assertEqual(audit.get("process.command_line"), "cat /etc/shadow")


class TestEnricherAndSecurityValidation(unittest.TestCase):
    def test_ip_classification(self) -> None:
        self.assertEqual(classify_ip("10.0.1.15"), "private")
        self.assertEqual(classify_ip("127.0.0.1"), "loopback")
        self.assertEqual(classify_ip("198.51.100.77"), "documentation")
        self.assertEqual(classify_ip("1.1.1.1"), "public")
        self.assertEqual(classify_ip("not-an-ip"), "invalid")

    def test_enricher_matches_ti_and_escalates_severity(self) -> None:
        enricher = IOCEnricher.from_file(TI_FEED_PATH)
        alert = Alert(
            alert_id="ALT-TEST01",
            rule_id="rule-1",
            rule_title="Web Scan",
            severity="medium",
            original_severity="medium",
            description="Test",
            first_seen="2026-11-20T14:11:10+00:00",
            last_seen="2026-11-20T14:11:22+00:00",
            event_count=4,
            entity="203.0.113.45",
            mitre_techniques=["T1595.003"],
            mitre_tactics=["Reconnaissance"],
            playbook_id="PB-003",
            evidence=["203.0.113.45 GET /.env"],
            matched_fields={"source.ip": "203.0.113.45"},
        )
        enriched = enricher.enrich_alert(alert)
        self.assertEqual(enriched.severity, "high")
        self.assertTrue(any(i.is_malicious and i.value == "203.0.113.45" for i in enriched.iocs))
        self.assertTrue(any("escalated" in note.lower() for note in enriched.enrichment_notes))

    def test_discord_webhook_validation_blocks_ssrf_and_http(self) -> None:
        host, path = validate_discord_webhook_url("https://discord.com/api/webhooks/12345/abcdef")
        self.assertEqual(host, "discord.com")
        self.assertEqual(path, "/api/webhooks/12345/abcdef")

        for bad_url in (
            "http://discord.com/api/webhooks/12345/abcdef",
            "https://evil.example/api/webhooks/12345/abcdef",
            "https://discord.com/other/path",
            "file:///etc/passwd",
        ):
            with self.assertRaises(ValueError):
                validate_discord_webhook_url(bad_url)


if __name__ == "__main__":
    unittest.main()
