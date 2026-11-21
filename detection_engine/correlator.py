"""Cross-source Kill-Chain Incident Correlator grouping alerts into unified SOC incidents."""

from __future__ import annotations

import hashlib
from collections import defaultdict

from detection_engine.models import SEVERITY_ORDER, Alert, CorrelatedIncident

KILL_CHAIN_ORDER = (
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command And Control",
    "Exfiltration",
    "Impact",
)

SEVERITY_BASE_SCORE = {
    "informational": 5,
    "low": 10,
    "medium": 20,
    "high": 35,
    "critical": 48,
}


def _build_incident_id(entity: str, first_seen: str) -> str:
    digest = hashlib.sha256(f"incident|{entity}|{first_seen}".encode()).hexdigest()[:10]
    return f"INC-{digest.upper()}"


def _order_tactics(tactics: set[str]) -> list[str]:
    rank = {name.lower(): idx for idx, name in enumerate(KILL_CHAIN_ORDER)}
    return sorted(tactics, key=lambda t: (rank.get(t.lower(), 999), t))


def correlate_incidents(alerts: list[Alert]) -> list[CorrelatedIncident]:
    """Correlate individual alerts by entity into multi-stage Kill-Chain incidents."""
    if not alerts:
        return []

    by_entity: dict[str, list[Alert]] = defaultdict(list)
    for alert in alerts:
        key = alert.entity or "unknown"
        by_entity[key].append(alert)

    sev_rank = {lvl: idx for idx, lvl in enumerate(SEVERITY_ORDER)}
    incidents: list[CorrelatedIncident] = []

    for entity, entity_alerts in by_entity.items():
        ordered = sorted(entity_alerts, key=lambda a: a.first_seen)
        first_seen = ordered[0].first_seen
        last_seen = max(a.last_seen for a in ordered)

        max_sev = max((a.severity.lower() for a in ordered), key=lambda s: sev_rank.get(s, 0))
        tactics_set = {t for a in ordered for t in a.mitre_tactics}
        ordered_stages = _order_tactics(tactics_set)
        techniques = sorted({t for a in ordered for t in a.mitre_techniques})
        malicious_iocs = sorted({ioc.value for a in ordered for ioc in a.iocs if ioc.is_malicious})
        playbooks = sorted({a.playbook_id for a in ordered if a.playbook_id})
        rule_titles = [a.rule_title for a in ordered]

        # Transparent risk score (0-100) combining severity, kill-chain breadth, techniques, and TI
        score = SEVERITY_BASE_SCORE.get(max_sev, 15)
        score += min(len(ordered_stages) * 8, 32)
        score += min(len(techniques) * 3, 12)
        if malicious_iocs:
            score += 8
        risk_score = min(score, 100)

        chain_text = " -> ".join(ordered_stages) if ordered_stages else "Single-Stage Activity"
        summary = (
            f"Entity '{entity}' triggered {len(ordered)} alert(s) across "
            f"{len(ordered_stages)} MITRE tactic(s) ({chain_text}) with risk score {risk_score}/100."
        )

        incidents.append(
            CorrelatedIncident(
                incident_id=_build_incident_id(entity, first_seen),
                entity=entity,
                severity=max_sev,
                risk_score=risk_score,
                first_seen=first_seen,
                last_seen=last_seen,
                alert_ids=[a.alert_id for a in ordered],
                rule_titles=rule_titles,
                kill_chain_stages=ordered_stages,
                mitre_techniques=techniques,
                mitre_tactics=ordered_stages,
                malicious_iocs=malicious_iocs,
                playbooks=playbooks,
                summary=summary,
            )
        )

    incidents.sort(key=lambda inc: (inc.risk_score, len(inc.alert_ids)), reverse=True)
    return incidents
