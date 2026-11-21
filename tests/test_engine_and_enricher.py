"""Unit tests for YAML loader, normalizers, enricher, correlator, SIEM transpiler, and dashboard."""

from __future__ import annotations

import unittest
from pathlib import Path

from detection_engine.correlator import correlate_incidents
from detection_engine.dashboard import render_html_dashboard
from detection_engine.enricher import IOCEnricher, classify_ip
from detection_engine.mitre_navigator import build_attack_navigator_layer
from detection_engine.models import Alert, DetectionReport, EnrichedIOC
from detection_engine.normalizer import parse_log_line
from detection_engine.reporter import validate_discord_webhook_url
from detection_engine.siem_exporter import transpile_rule
from detection_engine.sigma_engine import load_rules_from_dir
from detection_engine.yaml_loader import parse_yaml_stdlib

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TI_FEED_PATH = PROJECT_ROOT / "threat_intel" / "ioc_feed.json"
RULES_DIR = PROJECT_ROOT / "rules"


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

    def test_auto_normalizer_parses_all_five_sources(self) -> None:
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

        cloudtrail = parse_log_line(
            '{"eventTime":"2026-11-20T14:14:00Z","eventSource":"iam.amazonaws.com",'
            '"eventName":"AttachUserPolicy","awsRegion":"us-east-1","sourceIPAddress":"192.0.2.55",'
            '"userIdentity":{"userName":"compromised-dev"},'
            '"requestParameters":{"policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}}'
        )
        self.assertIsNotNone(cloudtrail)
        assert cloudtrail is not None
        self.assertEqual(cloudtrail.source_type, "aws_cloudtrail")
        self.assertEqual(cloudtrail.get("event.action"), "AttachUserPolicy")
        self.assertEqual(cloudtrail.get("user.name"), "compromised-dev")

        dns = parse_log_line(
            '{"timestamp":"2026-11-20T14:14:20Z","source_ip":"198.51.100.77",'
            '"query":"4a9f8c2d7e6b1a0f3c5d8e9a7b2c4d6e.exfil.tunnel-lab.example","qtype":"TXT"}'
        )
        self.assertIsNotNone(dns)
        assert dns is not None
        self.assertEqual(dns.source_type, "dns")
        self.assertEqual(dns.get("dns.question.type"), "TXT")
        self.assertGreater(dns.get("dns.question.entropy"), 3.0)


class TestEnricherAndSecurityValidation(unittest.TestCase):
    def test_ip_classification(self) -> None:
        self.assertEqual(classify_ip("10.0.1.15"), "private")
        self.assertEqual(classify_ip("127.0.0.1"), "loopback")
        self.assertEqual(classify_ip("198.51.100.77"), "documentation")
        self.assertEqual(classify_ip("1.1.1.1"), "public")
        self.assertEqual(classify_ip("not-an-ip"), "invalid")

    def test_enricher_matches_ti_subdomain_and_escalates_severity(self) -> None:
        enricher = IOCEnricher.from_file(TI_FEED_PATH)
        alert = Alert(
            alert_id="ALT-DNS01",
            rule_id="rule-dns",
            rule_title="DNS Tunneling",
            severity="high",
            original_severity="high",
            description="Test DNS tunneling",
            first_seen="2026-11-20T14:13:40+00:00",
            last_seen="2026-11-20T14:14:04+00:00",
            event_count=5,
            entity="198.51.100.77",
            mitre_techniques=["T1071.004", "T1048.003"],
            mitre_tactics=["Command And Control", "Exfiltration"],
            playbook_id="PB-009",
            evidence=["4a9f8c2d.exfil.tunnel-lab.example"],
            matched_fields={
                "source.ip": "10.0.1.50",
                "dns.question.name": "4a9f8c2d7e6b1a0f3c5d8e9a7b2c4d6e.exfil.tunnel-lab.example",
            },
        )
        enriched = enricher.enrich_alert(alert)
        self.assertEqual(enriched.severity, "critical")
        self.assertTrue(
            any(i.is_malicious and i.value == "exfil.tunnel-lab.example" for i in enriched.iocs)
        )

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


class TestCorrelatorNavigatorSiemAndDashboard(unittest.TestCase):
    def test_kill_chain_correlator_groups_entity_and_scores_risk(self) -> None:
        alerts = [
            Alert(
                alert_id="ALT-1",
                rule_id="r1",
                rule_title="SSH Compromise",
                severity="critical",
                original_severity="critical",
                description="SSH breach",
                first_seen="2026-11-20T14:11:00+00:00",
                last_seen="2026-11-20T14:12:15+00:00",
                event_count=8,
                entity="198.51.100.77",
                mitre_techniques=["T1110", "T1078"],
                mitre_tactics=["Credential Access", "Initial Access"],
                playbook_id="PB-001",
                evidence=["Failed password"],
                iocs=[
                    EnrichedIOC(
                        value="198.51.100.77",
                        ioc_type="ip",
                        classification="documentation",
                        is_malicious=True,
                    )
                ],
            ),
            Alert(
                alert_id="ALT-2",
                rule_id="r2",
                rule_title="DNS Exfiltration",
                severity="critical",
                original_severity="high",
                description="DNS exfil",
                first_seen="2026-11-20T14:13:40+00:00",
                last_seen="2026-11-20T14:14:04+00:00",
                event_count=5,
                entity="198.51.100.77",
                mitre_techniques=["T1071.004", "T1048.003"],
                mitre_tactics=["Command And Control", "Exfiltration"],
                playbook_id="PB-009",
                evidence=["exfil.tunnel-lab.example"],
            ),
        ]
        incidents = correlate_incidents(alerts)
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertTrue(inc.incident_id.startswith("INC-"))
        self.assertEqual(inc.entity, "198.51.100.77")
        self.assertGreaterEqual(inc.risk_score, 90)
        # Initial Access should precede Exfiltration in Kill-Chain order
        self.assertLess(
            inc.kill_chain_stages.index("Initial Access"),
            inc.kill_chain_stages.index("Exfiltration"),
        )

    def test_mitre_navigator_and_siem_transpiler_and_xss_safe_dashboard(self) -> None:
        rules = load_rules_from_dir(RULES_DIR)
        layer = build_attack_navigator_layer(rules)
        self.assertEqual(layer["domain"], "enterprise-attack")
        self.assertEqual(layer["versions"]["layer"], "4.5")
        tech_ids = {t["techniqueID"] for t in layer["techniques"]}
        self.assertIn("T1562.008", tech_ids)
        self.assertIn("T1071.004", tech_ids)

        for rule in rules:
            spl = transpile_rule(rule, "splunk")
            ekql = transpile_rule(rule, "elastic")
            skql = transpile_rule(rule, "sentinel")
            self.assertTrue(spl.strip())
            self.assertTrue(ekql.strip())
            self.assertTrue(skql.strip())

        # Verify XSS escaping in HTML dashboard
        xss_alert = Alert(
            alert_id="ALT-XSS",
            rule_id="r-xss",
            rule_title="<script>alert(1)</script>",
            severity="high",
            original_severity="high",
            description="Test XSS escaping",
            first_seen="2026-11-20T14:00:00+00:00",
            last_seen="2026-11-20T14:00:01+00:00",
            event_count=1,
            entity="<b>evil</b>",
            mitre_techniques=["T1190"],
            mitre_tactics=["Initial Access"],
            playbook_id="PB-002",
            evidence=['GET /?q=<img src=x onerror="alert(1)">'],
        )
        report = DetectionReport(
            generated_at="2026-11-20T14:00:00+00:00",
            rules_loaded=len(rules),
            events_processed=1,
            alerts=[xss_alert],
            incidents=correlate_incidents([xss_alert]),
        )
        html_out = render_html_dashboard(report)
        self.assertNotIn("<script>alert(1)</script>", html_out)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html_out)
        self.assertNotIn('<img src=x onerror="alert(1)">', html_out)


if __name__ == "__main__":
    unittest.main()
