"""SOC alert reporters: terminal summary, JSON export, NIST Markdown report, and Discord webhook."""

from __future__ import annotations

import http.client
import json
from pathlib import Path
from urllib.parse import urlparse

from detection_engine.models import DetectionReport

ALLOWED_DISCORD_HOSTS = {"discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com"}


def format_terminal_report(report: DetectionReport) -> str:
    """Render a concise SOC console summary of detection findings."""
    sev = report.severity_counts()
    lines = [
        "=" * 78,
        " DETECTION-AS-CODE LAB — SOC ALERT SUMMARY",
        "=" * 78,
        f" Generated At    : {report.generated_at}",
        f" Rules Loaded    : {report.rules_loaded}",
        f" Events Parsed   : {report.events_processed}",
        f" Alerts Triggered: {len(report.alerts)} "
        f"(CRITICAL={sev['critical']} | HIGH={sev['high']} | "
        f"MEDIUM={sev['medium']} | LOW={sev['low']})",
        f" MITRE ATT&CK    : {', '.join(report.mitre_summary()) or 'None'}",
        "-" * 78,
    ]

    if not report.alerts:
        lines.append(" [OK] No security alerts triggered. Telemetry appears benign.")
        lines.append("=" * 78)
        return "\n".join(lines)

    for idx, alert in enumerate(report.alerts, start=1):
        mitre = ", ".join(alert.mitre_techniques) or "N/A"
        malicious_iocs = [i.value for i in alert.iocs if i.is_malicious]
        lines.extend(
            [
                f" #{idx} [{alert.severity.upper()}] {alert.rule_title}",
                f"     Alert ID : {alert.alert_id} | Playbook: {alert.playbook_id or 'N/A'} "
                f"| MITRE: {mitre}",
                f"     Entity   : {alert.entity} | Events: {alert.event_count} "
                f"| Window: {alert.first_seen} -> {alert.last_seen}",
            ]
        )
        if malicious_iocs:
            lines.append(f"     TI Hits  : {', '.join(malicious_iocs)}")
        for note in alert.enrichment_notes:
            lines.append(f"     Enriched : {note}")
        if alert.evidence:
            sample = alert.evidence[0]
            if len(sample) > 110:
                sample = sample[:107] + "..."
            lines.append(f"     Evidence : {sample}")
        lines.append("-" * 78)

    return "\n".join(lines)


def format_markdown_report(report: DetectionReport) -> str:
    """Generate a NIST SP 800-61 aligned Markdown detection & triage summary."""
    sev = report.severity_counts()
    lines = [
        "# Detection-as-Code Lab — Automated Incident Triage Report",
        "",
        f"- **Generated At (UTC):** `{report.generated_at}`",
        f"- **Sigma Rules Evaluated:** `{report.rules_loaded}`",
        f"- **Normalized Events Processed:** `{report.events_processed}`",
        f"- **Total Alerts:** `{len(report.alerts)}` "
        f"(Critical: `{sev['critical']}`, High: `{sev['high']}`, "
        f"Medium: `{sev['medium']}`, Low: `{sev['low']}`)",
        f"- **MITRE ATT&CK Techniques Observed:** "
        f"{', '.join(f'`{t}`' for t in report.mitre_summary()) or 'None'}",
        "",
        "## Executive Summary (NIST SP 800-61 — Detection & Analysis)",
        "",
        "| Alert ID | Severity | Rule Title | Entity | Events | MITRE ATT&CK | Playbook |",
        "| :--- | :--- | :--- | :--- | :---: | :--- | :--- |",
    ]

    for alert in report.alerts:
        mitre = ", ".join(alert.mitre_techniques) or "N/A"
        lines.append(
            f"| `{alert.alert_id}` | **{alert.severity.upper()}** | {alert.rule_title} | "
            f"`{alert.entity}` | {alert.event_count} | `{mitre}` | `{alert.playbook_id or 'N/A'}` |"
        )

    lines.extend(["", "## Detailed Findings & Threat Intelligence Enrichment", ""])
    for alert in report.alerts:
        lines.extend(
            [
                f"### {alert.alert_id} — {alert.rule_title} (`{alert.severity.upper()}`)",
                "",
                f"- **Rule ID:** `{alert.rule_id}`",
                f"- **Tactics / Techniques:** {', '.join(alert.mitre_tactics)} / "
                f"{', '.join(alert.mitre_techniques)}",
                f"- **Time Window:** `{alert.first_seen}` → `{alert.last_seen}` "
                f"({alert.event_count} events)",
                f"- **Recommended Playbook:** `{alert.playbook_id or 'N/A'}` (see `docs/playbooks.md`)",
                f"- **Description:** {alert.description}",
            ]
        )
        if alert.enrichment_notes:
            lines.append("- **Threat Intelligence Notes:**")
            for note in alert.enrichment_notes:
                lines.append(f"  - {note}")
        if alert.evidence:
            lines.append("- **Sample Evidence:**")
            lines.append("```text")
            lines.extend(alert.evidence[:3])
            lines.append("```")
        lines.append("")

    return "\n".join(lines)


def write_json_report(report: DetectionReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    return path


def write_markdown_report(report: DetectionReport, output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(format_markdown_report(report), encoding="utf-8")
    return path


def validate_discord_webhook_url(webhook_url: str) -> tuple[str, str]:
    """Strictly validate Discord webhook URL to prevent SSRF or non-HTTPS requests."""
    parsed = urlparse(webhook_url.strip())
    if parsed.scheme != "https":
        raise ValueError("Discord webhook URL must use HTTPS.")
    if parsed.hostname not in ALLOWED_DISCORD_HOSTS:
        raise ValueError(f"Unsupported webhook host: {parsed.hostname!r}")
    if not parsed.path.startswith("/api/webhooks/"):
        raise ValueError("Discord webhook URL path must start with '/api/webhooks/'.")
    request_path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    return parsed.hostname, request_path


def send_discord_alert(report: DetectionReport, webhook_url: str, *, timeout: int = 10) -> int:
    """Send a sanitized SOC alert summary to a Discord webhook over HTTPS."""
    host, path = validate_discord_webhook_url(webhook_url)
    sev = report.severity_counts()
    top_alerts = "\n".join(
        f"- **[{a.severity.upper()}]** {a.rule_title} (`{a.entity}`, {', '.join(a.mitre_techniques)})"
        for a in report.alerts[:5]
    ) or "No alerts triggered."

    payload = {
        "username": "Detection-as-Code SOC Bot",
        "embeds": [
            {
                "title": f"SOC Detection Summary ({len(report.alerts)} alerts)",
                "color": 15158332 if (sev["critical"] or sev["high"]) else 3066993,
                "description": top_alerts[:1800],
                "fields": [
                    {"name": "Critical", "value": str(sev["critical"]), "inline": True},
                    {"name": "High", "value": str(sev["high"]), "inline": True},
                    {"name": "Medium", "value": str(sev["medium"]), "inline": True},
                    {
                        "name": "MITRE ATT&CK",
                        "value": ", ".join(report.mitre_summary()) or "None",
                        "inline": False,
                    },
                ],
            }
        ],
    }

    body = json.dumps(payload).encode("utf-8")
    conn = http.client.HTTPSConnection(host, timeout=timeout)
    try:
        conn.request(
            "POST",
            path,
            body=body,
            headers={"Content-Type": "application/json", "User-Agent": "detection-as-code-lab/1.0"},
        )
        response = conn.getresponse()
        response.read()
        return response.status
    finally:
        conn.close()
