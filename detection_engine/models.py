"""Core data models for normalized events, Sigma rules, enriched IOCs, and alerts."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

SEVERITY_ORDER = ("informational", "low", "medium", "high", "critical")


def escalate_severity(level: str) -> str:
    """Increase severity by one tier up to critical."""
    normalized = level.lower()
    if normalized not in SEVERITY_ORDER:
        return "high"
    idx = SEVERITY_ORDER.index(normalized)
    return SEVERITY_ORDER[min(idx + 1, len(SEVERITY_ORDER) - 1)]


@dataclass(slots=True)
class NormalizedEvent:
    """ECS-inspired normalized telemetry event."""

    timestamp: datetime
    source_type: str  # "sshd", "webserver", "linux_audit"
    logsource: dict[str, str]
    fields: dict[str, Any]
    raw: str
    line_number: int = 0
    source_file: str = ""

    def get(self, key: str, default: Any = None) -> Any:
        return self.fields.get(key, default)


@dataclass(slots=True)
class SigmaRule:
    """Parsed Sigma detection rule."""

    id: str
    title: str
    description: str
    level: str
    logsource: dict[str, str]
    detection: dict[str, Any]
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    author: str = ""
    status: str = "experimental"
    date: str = ""
    playbook_id: str = ""
    file_path: str = ""

    @property
    def mitre_techniques(self) -> list[str]:
        techniques: list[str] = []
        for tag in self.tags:
            lower = tag.lower()
            if lower.startswith("attack.t"):
                techniques.append(lower.removeprefix("attack.").upper())
        return techniques

    @property
    def mitre_tactics(self) -> list[str]:
        tactics: list[str] = []
        for tag in self.tags:
            lower = tag.lower()
            if lower.startswith("attack.") and not lower.startswith("attack.t"):
                tactics.append(lower.removeprefix("attack.").replace("_", " ").title())
        return tactics


@dataclass(slots=True)
class EnrichedIOC:
    """Indicator of Compromise enriched with network classification and Threat Intelligence."""

    value: str
    ioc_type: str  # "ip", "user", "domain"
    classification: str  # e.g., "public", "private", "loopback", "account", "domain"
    is_malicious: bool = False
    threat_category: str = ""
    confidence: str = ""
    threat_actor: str = ""
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Alert:
    """Actionable SOC alert produced by a Sigma rule match."""

    alert_id: str
    rule_id: str
    rule_title: str
    severity: str
    original_severity: str
    description: str
    first_seen: str
    last_seen: str
    event_count: int
    entity: str
    mitre_techniques: list[str]
    mitre_tactics: list[str]
    playbook_id: str
    evidence: list[str]
    iocs: list[EnrichedIOC] = field(default_factory=list)
    enrichment_notes: list[str] = field(default_factory=list)
    matched_fields: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "rule_title": self.rule_title,
            "severity": self.severity,
            "original_severity": self.original_severity,
            "description": self.description,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "event_count": self.event_count,
            "entity": self.entity,
            "mitre_techniques": self.mitre_techniques,
            "mitre_tactics": self.mitre_tactics,
            "playbook_id": self.playbook_id,
            "evidence": self.evidence,
            "iocs": [ioc.to_dict() for ioc in self.iocs],
            "enrichment_notes": self.enrichment_notes,
            "matched_fields": self.matched_fields,
        }


@dataclass(slots=True)
class DetectionReport:
    """Complete output of a detection run."""

    generated_at: str
    rules_loaded: int
    events_processed: int
    alerts: list[Alert]
    log_files: list[str] = field(default_factory=list)

    def severity_counts(self) -> dict[str, int]:
        counts = {lvl: 0 for lvl in reversed(SEVERITY_ORDER)}
        for alert in self.alerts:
            sev = alert.severity.lower()
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def mitre_summary(self) -> list[str]:
        seen: set[str] = set()
        for alert in self.alerts:
            seen.update(alert.mitre_techniques)
        return sorted(seen)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "rules_loaded": self.rules_loaded,
            "events_processed": self.events_processed,
            "total_alerts": len(self.alerts),
            "severity_counts": self.severity_counts(),
            "mitre_techniques_observed": self.mitre_summary(),
            "log_files": self.log_files,
            "alerts": [alert.to_dict() for alert in self.alerts],
        }
