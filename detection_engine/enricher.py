"""Threat Intelligence IOC enrichment and dynamic alert severity escalation."""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any

from detection_engine.models import Alert, EnrichedIOC, escalate_severity

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:example|invalid|com|net|org|io)\b",
    re.I,
)
RFC5737_NETS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)


def classify_ip(ip_str: str) -> str:
    """Classify an IP address into public, private, loopback, documentation, or reserved."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return "invalid"
    if isinstance(addr, ipaddress.IPv4Address) and any(addr in net for net in RFC5737_NETS):
        return "documentation"
    if addr.is_loopback:
        return "loopback"
    if addr.is_private:
        return "private"
    if addr.is_reserved or addr.is_multicast:
        return "reserved"
    return "public"


class IOCEnricher:
    """Enriches alerts using a local JSON Threat Intelligence feed and IP classification."""

    def __init__(self, feed_data: dict[str, Any] | None = None) -> None:
        data = feed_data or {}
        self.feed_name = str(data.get("feed_name", "default-empty-feed"))
        self.malicious_ips: dict[str, dict[str, Any]] = dict(data.get("malicious_ips", {}))
        self.suspicious_users: set[str] = {str(u).lower() for u in data.get("suspicious_users", [])}
        self.suspicious_domains: set[str] = {str(d).lower() for d in data.get("suspicious_domains", [])}

    @classmethod
    def from_file(cls, path: str | Path) -> IOCEnricher:
        file_path = Path(path)
        data = json.loads(file_path.read_text(encoding="utf-8"))
        return cls(data)

    def _extract_candidates(self, alert: Alert) -> tuple[set[str], set[str], set[str]]:
        ips: set[str] = set()
        users: set[str] = set()
        domains: set[str] = set()

        def _collect_field(val: Any) -> list[str]:
            if isinstance(val, list):
                return [str(v) for v in val if v]
            return [str(val)] if val else []

        for ip_val in _collect_field(alert.matched_fields.get("source.ip")):
            ips.add(ip_val)
        for user_val in _collect_field(alert.matched_fields.get("user.name")):
            users.add(user_val)

        # Also extract embedded IPs/domains from command lines or evidence (e.g., C2 callback IP)
        text_blobs = [
            *_collect_field(alert.matched_fields.get("process.command_line")),
            *alert.evidence,
        ]
        for blob in text_blobs:
            for found_ip in IPV4_RE.findall(blob):
                try:
                    ipaddress.ip_address(found_ip)
                    ips.add(found_ip)
                except ValueError:
                    continue
            for found_domain in DOMAIN_RE.findall(blob):
                domains.add(found_domain.lower())
            lower_blob = blob.lower()
            for sus_user in self.suspicious_users:
                if re.search(rf"\b{re.escape(sus_user)}\b", lower_blob):
                    users.add(sus_user)

        return ips, users, domains

    def enrich_alert(self, alert: Alert) -> Alert:
        """Enrich an alert in-place with IOC intelligence and escalate severity if malicious."""
        ips, users, domains = self._extract_candidates(alert)
        enriched: list[EnrichedIOC] = []
        notes: list[str] = []
        should_escalate = False

        for ip_str in sorted(ips):
            classification = classify_ip(ip_str)
            ti_hit = self.malicious_ips.get(ip_str)
            if ti_hit:
                should_escalate = True
                ioc = EnrichedIOC(
                    value=ip_str,
                    ioc_type="ip",
                    classification=classification,
                    is_malicious=True,
                    threat_category=str(ti_hit.get("category", "malicious_ip")),
                    confidence=str(ti_hit.get("confidence", "high")),
                    threat_actor=str(ti_hit.get("threat_actor", "")),
                    tags=[str(t) for t in ti_hit.get("tags", [])],
                )
                notes.append(
                    f"TI match ({self.feed_name}): IP {ip_str} flagged as "
                    f"{ioc.threat_category} ({ioc.threat_actor or 'known threat'}, "
                    f"confidence={ioc.confidence})."
                )
            else:
                ioc = EnrichedIOC(
                    value=ip_str,
                    ioc_type="ip",
                    classification=classification,
                    is_malicious=False,
                )
            enriched.append(ioc)

        for user in sorted(users):
            if user.lower() in self.suspicious_users:
                should_escalate = True
                enriched.append(
                    EnrichedIOC(
                        value=user,
                        ioc_type="user",
                        classification="account",
                        is_malicious=True,
                        threat_category="suspicious_account_name",
                        confidence="medium",
                        tags=["persistence", "unauthorized-account"],
                    )
                )
                notes.append(f"TI match ({self.feed_name}): suspicious account '{user}' observed.")

        for domain in sorted(domains):
            if domain in self.suspicious_domains:
                should_escalate = True
                enriched.append(
                    EnrichedIOC(
                        value=domain,
                        ioc_type="domain",
                        classification="domain",
                        is_malicious=True,
                        threat_category="malicious_domain",
                        confidence="high",
                        tags=["c2", "dropper"],
                    )
                )
                notes.append(
                    f"TI match ({self.feed_name}): known malicious domain '{domain}' observed."
                )

        alert.iocs = enriched
        alert.enrichment_notes = notes
        if should_escalate:
            new_sev = escalate_severity(alert.severity)
            if new_sev != alert.severity:
                alert.enrichment_notes.append(
                    f"Severity escalated from '{alert.severity}' to '{new_sev}' "
                    "due to Threat Intel match."
                )
                alert.severity = new_sev
        return alert

    def enrich_alerts(self, alerts: list[Alert]) -> list[Alert]:
        return [self.enrich_alert(alert) for alert in alerts]
