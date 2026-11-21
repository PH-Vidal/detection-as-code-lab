"""Sigma-to-SIEM transpiler generating Splunk SPL, Elasticsearch KQL, and Microsoft Sentinel KQL."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from detection_engine.models import SigmaRule
from detection_engine.sigma_engine import AGG_CONDITION_RE, TOKEN_RE

SUPPORTED_SIEM_TARGETS = ("splunk", "elastic", "sentinel")

SPLUNK_SOURCETYPES = {
    ("linux", "sshd"): 'index=linux sourcetype="linux_secure"',
    ("linux", "process_creation"): 'index=linux sourcetype="linux:audit"',
    ("aws", "cloudtrail"): 'index=aws sourcetype="aws:cloudtrail"',
    ("", "webserver"): 'index=web sourcetype="nginx:plus:access"',
    ("", "dns"): 'index=network sourcetype="dns:query"',
}

SENTINEL_TABLES = {
    ("linux", "sshd"): "Syslog",
    ("linux", "process_creation"): "LinuxAuditLog",
    ("aws", "cloudtrail"): "AWSCloudTrail",
    ("", "webserver"): "CommonSecurityLog",
    ("", "dns"): "DnsEvents",
}

SENTINEL_FIELD_MAP = {
    "source.ip": "SourceIP",
    "user.name": "UserName",
    "host.name": "Computer",
    "event.action": "EventAction",
    "url.original": "RequestURL",
    "process.name": "ProcessName",
    "process.command_line": "CommandLine",
    "dns.question.name": "Name",
    "dns.question.type": "QueryType",
    "cloud.service.name": "EventSource",
    "aws.cloudtrail.request_parameters": "RequestParameters",
}


def _escape_splunk(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _escape_kql_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _logsource_key(logsource: dict[str, str]) -> tuple[str, str]:
    product = logsource.get("product", "").lower()
    service_or_cat = (logsource.get("service") or logsource.get("category") or "").lower()
    return product, service_or_cat


def _render_splunk_matcher(field: str, val: str, modifiers: list[str]) -> str:
    esc = _escape_splunk(val)
    if "re" in modifiers:
        return f'match(\'{field}\', "{esc}")'
    if "contains" in modifiers:
        return f'{field}="*{esc}*"'
    if "startswith" in modifiers:
        return f'{field}="{esc}*"'
    if "endswith" in modifiers:
        return f'{field}="*{esc}"'
    return f'{field}="{esc}"'


def _render_elastic_matcher(field: str, val: str, modifiers: list[str]) -> str:
    esc = _escape_kql_string(val)
    if "re" in modifiers:
        return f'{field}: /{val}/'
    if "contains" in modifiers:
        return f'{field}: "*{esc}*"'
    if "startswith" in modifiers:
        return f'{field}: "{esc}*"'
    if "endswith" in modifiers:
        return f'{field}: "*{esc}"'
    return f'{field}: "{esc}"'


def _render_sentinel_matcher(field: str, val: str, modifiers: list[str]) -> str:
    mapped = SENTINEL_FIELD_MAP.get(field, field.replace(".", "_"))
    esc = _escape_kql_string(val)
    if "re" in modifiers:
        return f'{mapped} matches regex @"{val.replace(chr(34), chr(34) * 2)}"'
    if "contains" in modifiers:
        return f'{mapped} contains "{esc}"'
    if "startswith" in modifiers:
        return f'{mapped} startswith "{esc}"'
    if "endswith" in modifiers:
        return f'{mapped} endswith "{esc}"'
    return f'{mapped} =~ "{esc}"'


def _compile_selection(selection: Any, target: str) -> str:
    if isinstance(selection, list):
        parts = [_compile_selection(item, target) for item in selection]
        joiner = " OR " if target in {"splunk", "elastic"} else " or "
        return "(" + joiner.join(parts) + ")"
    if not isinstance(selection, dict):
        return "true"

    and_op = " AND " if target in {"splunk", "elastic"} else " and "
    or_op = " OR " if target in {"splunk", "elastic"} else " or "
    clauses: list[str] = []

    for field_spec, expected in selection.items():
        parts = str(field_spec).split("|")
        field_name = parts[0]
        modifiers = [m.lower() for m in parts[1:]]
        values = [str(v) for v in expected] if isinstance(expected, list) else [str(expected)]

        rendered: list[str] = []
        for val in values:
            if target == "splunk":
                rendered.append(_render_splunk_matcher(field_name, val, modifiers))
            elif target == "elastic":
                rendered.append(_render_elastic_matcher(field_name, val, modifiers))
            else:
                rendered.append(_render_sentinel_matcher(field_name, val, modifiers))

        if len(rendered) == 1:
            clauses.append(rendered[0])
        else:
            inner_join = and_op if "all" in modifiers else or_op
            clauses.append("(" + inner_join.join(rendered) + ")")

    return "(" + and_op.join(clauses) + ")" if len(clauses) > 1 else (clauses[0] if clauses else "true")


def _substitute_condition(expr: str, selection_queries: dict[str, str], target: str) -> str:
    tokens = TOKEN_RE.findall(expr)
    out: list[str] = []
    for tok in tokens:
        low = tok.lower()
        if low in {"and", "or", "not"}:
            if target == "sentinel":
                out.append(low)
            else:
                out.append(low.upper())
        elif tok in {"(", ")"}:
            out.append(tok)
        elif tok in selection_queries:
            out.append(selection_queries[tok])
        else:
            out.append(tok)
    rendered = " ".join(out)
    # Clean Sentinel `not (expr)` -> `not(expr)` spacing
    if target == "sentinel":
        rendered = re.sub(r"\bnot\s+\(", "not(", rendered)
    return rendered


def transpile_rule(rule: SigmaRule, target: str) -> str:
    """Transpile a single SigmaRule to Splunk SPL, Elasticsearch KQL, or Sentinel KQL."""
    if target not in SUPPORTED_SIEM_TARGETS:
        raise ValueError(
            f"Unsupported SIEM target: {target!r}. Expected one of {SUPPORTED_SIEM_TARGETS}."
        )

    reserved = {"condition", "timeframe", "correlation"}
    selection_queries = {
        key: _compile_selection(val, target)
        for key, val in rule.detection.items()
        if key not in reserved
    }
    condition = str(rule.detection["condition"]).strip()
    ls_key = _logsource_key(rule.logsource)

    if target == "splunk":
        prefix = SPLUNK_SOURCETYPES.get(ls_key, "index=*")
        if condition.lower() == "correlation" and "correlation" in rule.detection:
            corr = rule.detection["correlation"]
            group_by = corr["group_by"]
            tf = corr.get("timeframe", "10m")
            s0 = corr["stages"][0]
            s1 = corr["stages"][1]
            q0 = selection_queries[s0["ref"]]
            q1 = selection_queries[s1["ref"]]
            return (
                f"{prefix} ({q0} OR {q1})\n"
                f'| eval stage=if({q0}, "stage0", "stage1")\n'
                f"| transaction {group_by} maxspan={tf}\n"
                f'| stats count(eval(stage=="stage0")) as s0_count, '
                f'count(eval(stage=="stage1")) as s1_count by {group_by}\n'
                f'| where s0_count >= {s0.get("min_count", 1)} AND s1_count >= {s1.get("min_count", 1)}'
            )
        if agg := AGG_CONDITION_RE.match(condition):
            where_expr = _substitute_condition(agg.group("expr"), selection_queries, "splunk")
            tf = rule.detection.get("timeframe", "5m")
            return (
                f"{prefix} {where_expr}\n"
                f"| bin _time span={tf}\n"
                f'| stats count by _time, {agg.group("group_by")}\n'
                f'| where count {agg.group("op")} {agg.group("threshold")}'
            )
        where_expr = _substitute_condition(condition, selection_queries, "splunk")
        return f"{prefix} {where_expr}"

    if target == "elastic":
        if condition.lower() == "correlation" and "correlation" in rule.detection:
            corr = rule.detection["correlation"]
            refs = " OR ".join(selection_queries[st["ref"]] for st in corr["stages"])
            return (
                f"# EQL / Kibana Correlation (group_by={corr['group_by']}, "
                f"timeframe={corr.get('timeframe', '10m')})\n{refs}"
            )
        if agg := AGG_CONDITION_RE.match(condition):
            expr = _substitute_condition(agg.group("expr"), selection_queries, "elastic")
            tf = rule.detection.get("timeframe", "5m")
            return (
                f"# Threshold Rule: count() by {agg.group('group_by')} "
                f"{agg.group('op')} {agg.group('threshold')} within {tf}\n{expr}"
            )
        return _substitute_condition(condition, selection_queries, "elastic")

    # Microsoft Sentinel KQL
    table = SENTINEL_TABLES.get(ls_key, "SecurityEvent")
    if condition.lower() == "correlation" and "correlation" in rule.detection:
        corr = rule.detection["correlation"]
        group_field = SENTINEL_FIELD_MAP.get(corr["group_by"], corr["group_by"].replace(".", "_"))
        tf = corr.get("timeframe", "10m")
        s0, s1 = corr["stages"][0], corr["stages"][1]
        q0 = selection_queries[s0["ref"]]
        q1 = selection_queries[s1["ref"]]
        return (
            f"{table}\n"
            f"| where ({q0}) or ({q1})\n"
            f"| summarize Stage0Count = countif({q0}), Stage1Count = countif({q1}) "
            f"by {group_field}, bin(TimeGenerated, {tf})\n"
            f"| where Stage0Count >= {s0.get('min_count', 1)} "
            f"and Stage1Count >= {s1.get('min_count', 1)}"
        )
    if agg := AGG_CONDITION_RE.match(condition):
        where_expr = _substitute_condition(agg.group("expr"), selection_queries, "sentinel")
        group_field = SENTINEL_FIELD_MAP.get(
            agg.group("group_by"), agg.group("group_by").replace(".", "_")
        )
        tf = rule.detection.get("timeframe", "5m")
        return (
            f"{table}\n"
            f"| where {where_expr}\n"
            f"| summarize EventCount = count() by {group_field}, bin(TimeGenerated, {tf})\n"
            f"| where EventCount {agg.group('op')} {agg.group('threshold')}"
        )
    where_expr = _substitute_condition(condition, selection_queries, "sentinel")
    return f"{table}\n| where {where_expr}"


def export_rules_to_siem(
    rules: list[SigmaRule],
    output_dir: str | Path,
    *,
    target: str = "all",
) -> dict[str, Path]:
    """Export all loaded Sigma rules into production SIEM query bundles."""
    targets = SUPPORTED_SIEM_TARGETS if target == "all" else (target,)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}

    for siem in targets:
        ext = "spl" if siem == "splunk" else "kql"
        header = (
            f"# Detection-as-Code Lab — Exported {siem.upper()} Queries ({len(rules)} rules)\n"
            "# Auto-transpiled from versioned Sigma YAML rules in rules/\n\n"
        )
        sections: list[str] = [header]
        manifest: list[dict[str, Any]] = []
        for rule in rules:
            query = transpile_rule(rule, siem)
            mitre = ", ".join(rule.mitre_techniques)
            sections.append(
                f"# ============================================================================\n"
                f"# Rule     : {rule.title}\n"
                f"# Rule ID  : {rule.id} | Severity: {rule.level.upper()} | MITRE: {mitre}\n"
                f"# Playbook : {rule.playbook_id or 'N/A'}\n"
                f"# ============================================================================\n"
                f"{query}\n\n"
            )
            manifest.append(
                {
                    "rule_id": rule.id,
                    "title": rule.title,
                    "severity": rule.level,
                    "mitre_techniques": rule.mitre_techniques,
                    "playbook_id": rule.playbook_id,
                    "target": siem,
                    "query": query,
                }
            )

        query_file = out / f"{siem}_queries.{ext}"
        query_file.write_text("".join(sections), encoding="utf-8")
        json_file = out / f"{siem}_queries.json"
        json_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        written[siem] = query_file

    return written
