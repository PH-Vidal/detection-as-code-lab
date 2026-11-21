"""Sigma rule loader, schema validator, matcher, aggregation, and temporal correlation engine."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from datetime import timedelta
from pathlib import Path
from typing import Any

from detection_engine.models import SEVERITY_ORDER, Alert, NormalizedEvent, SigmaRule
from detection_engine.yaml_loader import load_yaml_file

TIMEFRAME_RE = re.compile(r"^(?P<value>\d+)(?P<unit>[smhd])$")
AGG_CONDITION_RE = re.compile(
    r"^(?P<expr>.+?)\s*\|\s*count\(\)\s+by\s+(?P<group_by>[a-zA-Z0-9_.]+)\s*"
    r"(?P<op>>=|<=|>|<|==)\s*(?P<threshold>\d+)$"
)
TOKEN_RE = re.compile(r"\(|\)|[A-Za-z_][A-Za-z0-9_]*")


class SigmaValidationError(ValueError):
    """Raised when a Sigma rule YAML fails schema validation."""


def parse_timeframe(value: str | None) -> timedelta:
    """Convert Sigma timeframe strings like '5m', '30s', '1h' into timedelta."""
    if not value:
        return timedelta(minutes=5)
    match = TIMEFRAME_RE.match(value.strip().lower())
    if not match:
        raise SigmaValidationError(f"Invalid timeframe format: {value!r}")
    amount = int(match.group("value"))
    unit = match.group("unit")
    if unit == "s":
        return timedelta(seconds=amount)
    if unit == "m":
        return timedelta(minutes=amount)
    if unit == "h":
        return timedelta(hours=amount)
    return timedelta(days=amount)


def validate_rule_dict(data: dict[str, Any], source: str = "<memory>") -> list[str]:
    """Validate Sigma rule dictionary structure and return a list of errors (empty if valid)."""
    errors: list[str] = []
    for required in ("title", "id", "level", "logsource", "detection"):
        if required not in data or not data[required]:
            errors.append(f"{source}: missing required field '{required}'")

    level = str(data.get("level", "")).lower()
    if level and level not in SEVERITY_ORDER:
        errors.append(f"{source}: invalid level '{level}' (expected one of {SEVERITY_ORDER})")

    logsource = data.get("logsource")
    if logsource is not None and not isinstance(logsource, dict):
        errors.append(f"{source}: 'logsource' must be a mapping")

    detection = data.get("detection")
    if isinstance(detection, dict):
        if "condition" not in detection or not detection["condition"]:
            errors.append(f"{source}: detection block missing 'condition'")
        if "timeframe" in detection:
            try:
                parse_timeframe(str(detection["timeframe"]))
            except SigmaValidationError as exc:
                errors.append(f"{source}: {exc}")
        if "correlation" in detection:
            corr = detection["correlation"]
            if not isinstance(corr, dict):
                errors.append(f"{source}: 'correlation' must be a mapping")
            else:
                for req_key in ("group_by", "stages"):
                    if req_key not in corr:
                        errors.append(f"{source}: correlation missing '{req_key}'")
                if "timeframe" in corr:
                    try:
                        parse_timeframe(str(corr["timeframe"]))
                    except SigmaValidationError as exc:
                        errors.append(f"{source}: {exc}")
    elif detection is not None:
        errors.append(f"{source}: 'detection' must be a mapping")

    return errors


def load_rule_from_file(path: str | Path) -> SigmaRule:
    """Load and validate a single Sigma YAML rule file."""
    file_path = Path(path)
    data = load_yaml_file(file_path)
    errors = validate_rule_dict(data, source=str(file_path))
    if errors:
        raise SigmaValidationError("; ".join(errors))

    return SigmaRule(
        id=str(data["id"]),
        title=str(data["title"]),
        description=str(data.get("description", "")),
        level=str(data["level"]).lower(),
        logsource={str(k): str(v) for k, v in data["logsource"].items()},
        detection=dict(data["detection"]),
        tags=[str(t) for t in data.get("tags", [])],
        references=[str(r) for r in data.get("references", [])],
        falsepositives=[str(fp) for fp in data.get("falsepositives", [])],
        author=str(data.get("author", "")),
        status=str(data.get("status", "experimental")),
        date=str(data.get("date", "")),
        playbook_id=str(data.get("playbook_id", "")),
        file_path=str(file_path),
    )


def load_rules_from_dir(rules_dir: str | Path) -> list[SigmaRule]:
    """Load all `.yml` / `.yaml` Sigma rules from a directory."""
    directory = Path(rules_dir)
    if not directory.is_dir():
        raise FileNotFoundError(f"Rules directory not found: {directory}")

    rules: list[SigmaRule] = []
    for path in sorted(directory.iterdir()):
        if path.is_file() and path.suffix.lower() in {".yml", ".yaml"}:
            rules.append(load_rule_from_file(path))
    return rules


def _matches_logsource(rule: SigmaRule, event: NormalizedEvent) -> bool:
    for key, expected in rule.logsource.items():
        actual = event.logsource.get(key)
        if actual is None or actual.lower() != expected.lower():
            return False
    return True


def _match_single_value(actual: Any, expected: Any, modifiers: list[str]) -> bool:
    if actual is None:
        return False
    actual_str = str(actual)
    expected_str = str(expected)

    if "re" in modifiers:
        return re.search(expected_str, actual_str) is not None
    if "contains" in modifiers:
        return expected_str.lower() in actual_str.lower()
    if "startswith" in modifiers:
        return actual_str.lower().startswith(expected_str.lower())
    if "endswith" in modifiers:
        return actual_str.lower().endswith(expected_str.lower())
    return actual_str.lower() == expected_str.lower()


def _match_selection(selection: Any, event: NormalizedEvent) -> bool:
    """Evaluate a Sigma selection (dict of field conditions, or list of alternative dicts)."""
    if isinstance(selection, list):
        return any(_match_selection(item, event) for item in selection)
    if not isinstance(selection, dict):
        return False

    for field_spec, expected in selection.items():
        parts = str(field_spec).split("|")
        field_name = parts[0]
        modifiers = [m.lower() for m in parts[1:]]
        actual = event.get(field_name)

        if isinstance(expected, list):
            if "all" in modifiers:
                if not all(_match_single_value(actual, val, modifiers) for val in expected):
                    return False
            else:
                if not any(_match_single_value(actual, val, modifiers) for val in expected):
                    return False
        else:
            if not _match_single_value(actual, expected, modifiers):
                return False
    return True


class _ConditionEvaluator:
    """Safe recursive-descent boolean parser for Sigma condition expressions."""

    def __init__(self, tokens: list[str], bindings: dict[str, bool]) -> None:
        self.tokens = tokens
        self.bindings = bindings
        self.pos = 0

    def parse(self) -> bool:
        value = self._parse_or()
        if self.pos != len(self.tokens):
            raise SigmaValidationError(f"Unexpected token in condition: {self.tokens[self.pos]!r}")
        return value

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _consume(self) -> str:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def _parse_or(self) -> bool:
        left = self._parse_and()
        while (tok := self._peek()) is not None and tok.lower() == "or":
            self._consume()
            right = self._parse_and()
            left = left or right
        return left

    def _parse_and(self) -> bool:
        left = self._parse_not()
        while (tok := self._peek()) is not None and tok.lower() == "and":
            self._consume()
            right = self._parse_not()
            left = left and right
        return left

    def _parse_not(self) -> bool:
        if (tok := self._peek()) is not None and tok.lower() == "not":
            self._consume()
            return not self._parse_not()
        return self._parse_primary()

    def _parse_primary(self) -> bool:
        tok = self._peek()
        if tok is None:
            raise SigmaValidationError("Unexpected end of Sigma condition expression")
        if tok == "(":
            self._consume()
            val = self._parse_or()
            if self._peek() != ")":
                raise SigmaValidationError("Missing closing ')' in Sigma condition")
            self._consume()
            return val
        self._consume()
        if tok not in self.bindings:
            raise SigmaValidationError(f"Unknown selection identifier in condition: {tok!r}")
        return self.bindings[tok]


def evaluate_condition_expr(expr: str, bindings: dict[str, bool]) -> bool:
    """Safely evaluate a boolean Sigma condition expression without eval()."""
    tokens = TOKEN_RE.findall(expr)
    if not tokens:
        raise SigmaValidationError(f"Empty Sigma condition: {expr!r}")
    return _ConditionEvaluator(tokens, bindings).parse()


def _compare(count: int, op: str, threshold: int) -> bool:
    if op == ">=":
        return count >= threshold
    if op == ">":
        return count > threshold
    if op == "<=":
        return count <= threshold
    if op == "<":
        return count < threshold
    return count == threshold


def _build_alert_id(rule_id: str, entity: str, first_seen: str) -> str:
    digest = hashlib.sha256(f"{rule_id}|{entity}|{first_seen}".encode()).hexdigest()[:10]
    return f"ALT-{digest.upper()}"


def _extract_entity(events: list[NormalizedEvent], preferred_field: str | None = None) -> str:
    for evt in events:
        if preferred_field and evt.get(preferred_field):
            return str(evt.get(preferred_field))
    for fallback in ("source.ip", "user.name", "host.name"):
        for evt in events:
            val = evt.get(fallback)
            if val:
                return str(val)
    return "unknown"


def _collect_matched_fields(events: list[NormalizedEvent]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for key in (
        "source.ip",
        "user.name",
        "host.name",
        "event.action",
        "url.original",
        "process.name",
        "process.command_line",
        "dns.question.name",
        "dns.question.type",
        "cloud.service.name",
        "aws.cloudtrail.policy_arn",
        "aws.cloudtrail.target_user",
        "aws.cloudtrail.trail_name",
    ):
        values: list[str] = []
        for evt in events:
            val = evt.get(key)
            if val and str(val) not in values:
                values.append(str(val))
        if values:
            summary[key] = values[0] if len(values) == 1 else values[:5]
    return summary


class SigmaDetectionEngine:
    """Evaluates normalized telemetry against loaded Sigma rules."""

    def __init__(self, rules: list[SigmaRule]) -> None:
        self.rules = rules

    def evaluate(self, events: list[NormalizedEvent]) -> list[Alert]:
        """Run all loaded Sigma rules against normalized events and return alerts."""
        alerts: list[Alert] = []
        ordered_events = sorted(events, key=lambda e: e.timestamp)

        for rule in self.rules:
            scoped_events = [e for e in ordered_events if _matches_logsource(rule, e)]
            if not scoped_events:
                continue

            condition = str(rule.detection["condition"]).strip()
            if condition.lower() == "correlation" and "correlation" in rule.detection:
                alerts.extend(self._evaluate_correlation(rule, scoped_events))
            elif agg_match := AGG_CONDITION_RE.match(condition):
                alerts.extend(self._evaluate_aggregation(rule, scoped_events, agg_match))
            else:
                alerts.extend(self._evaluate_stateless(rule, scoped_events, condition))

        severity_rank = {lvl: idx for idx, lvl in enumerate(SEVERITY_ORDER)}
        alerts.sort(
            key=lambda a: (severity_rank.get(a.severity, 0), a.event_count),
            reverse=True,
        )
        return alerts

    def _selection_bindings(self, rule: SigmaRule, event: NormalizedEvent) -> dict[str, bool]:
        reserved = {"condition", "timeframe", "correlation"}
        bindings: dict[str, bool] = {}
        for key, value in rule.detection.items():
            if key in reserved:
                continue
            bindings[key] = _match_selection(value, event)
        return bindings

    def _evaluate_stateless(
        self,
        rule: SigmaRule,
        events: list[NormalizedEvent],
        condition: str,
    ) -> list[Alert]:
        matched: list[NormalizedEvent] = []
        for event in events:
            bindings = self._selection_bindings(rule, event)
            if evaluate_condition_expr(condition, bindings):
                matched.append(event)

        if not matched:
            return []

        # Group stateless matches by primary entity to keep alerts clean and actionable
        grouped: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for evt in matched:
            entity = _extract_entity([evt])
            grouped[entity].append(evt)

        alerts: list[Alert] = []
        for entity, group_events in grouped.items():
            first_ts = group_events[0].timestamp.isoformat()
            last_ts = group_events[-1].timestamp.isoformat()
            alerts.append(
                Alert(
                    alert_id=_build_alert_id(rule.id, entity, first_ts),
                    rule_id=rule.id,
                    rule_title=rule.title,
                    severity=rule.level,
                    original_severity=rule.level,
                    description=rule.description,
                    first_seen=first_ts,
                    last_seen=last_ts,
                    event_count=len(group_events),
                    entity=entity,
                    mitre_techniques=rule.mitre_techniques,
                    mitre_tactics=rule.mitre_tactics,
                    playbook_id=rule.playbook_id,
                    evidence=[e.raw for e in group_events[:5]],
                    matched_fields=_collect_matched_fields(group_events),
                )
            )
        return alerts

    def _evaluate_aggregation(
        self,
        rule: SigmaRule,
        events: list[NormalizedEvent],
        agg_match: re.Match[str],
    ) -> list[Alert]:
        expr = agg_match.group("expr").strip()
        group_by = agg_match.group("group_by").strip()
        op = agg_match.group("op")
        threshold = int(agg_match.group("threshold"))
        window = parse_timeframe(rule.detection.get("timeframe"))

        by_entity: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for event in events:
            bindings = self._selection_bindings(rule, event)
            if evaluate_condition_expr(expr, bindings):
                key = str(event.get(group_by) or "unknown")
                by_entity[key].append(event)

        alerts: list[Alert] = []
        for entity, entity_events in by_entity.items():
            # Sliding window check for the densest matching burst
            best_window: list[NormalizedEvent] = []
            start = 0
            for end, evt in enumerate(entity_events):
                while evt.timestamp - entity_events[start].timestamp > window:
                    start += 1
                current = entity_events[start : end + 1]
                if len(current) > len(best_window):
                    best_window = current

            if _compare(len(best_window), op, threshold) and best_window:
                first_ts = best_window[0].timestamp.isoformat()
                last_ts = best_window[-1].timestamp.isoformat()
                alerts.append(
                    Alert(
                        alert_id=_build_alert_id(rule.id, entity, first_ts),
                        rule_id=rule.id,
                        rule_title=rule.title,
                        severity=rule.level,
                        original_severity=rule.level,
                        description=rule.description,
                        first_seen=first_ts,
                        last_seen=last_ts,
                        event_count=len(best_window),
                        entity=entity,
                        mitre_techniques=rule.mitre_techniques,
                        mitre_tactics=rule.mitre_tactics,
                        playbook_id=rule.playbook_id,
                        evidence=[e.raw for e in best_window[:5]],
                        matched_fields=_collect_matched_fields(best_window),
                    )
                )
        return alerts

    def _evaluate_correlation(
        self,
        rule: SigmaRule,
        events: list[NormalizedEvent],
    ) -> list[Alert]:
        corr = rule.detection["correlation"]
        group_by = str(corr["group_by"])
        window = parse_timeframe(corr.get("timeframe", "10m"))
        stages = list(corr["stages"])
        if len(stages) < 2:
            return []

        stage_events_by_entity: dict[str, dict[int, list[NormalizedEvent]]] = defaultdict(
            lambda: defaultdict(list)
        )
        for event in events:
            bindings = self._selection_bindings(rule, event)
            entity = str(event.get(group_by) or "")
            if not entity:
                continue
            for idx, stage in enumerate(stages):
                ref = str(stage["ref"])
                if bindings.get(ref, False):
                    stage_events_by_entity[entity][idx].append(event)

        alerts: list[Alert] = []
        for entity, stage_map in stage_events_by_entity.items():
            # Verify temporal ordering across stages within the correlation window
            stage0_min = int(stages[0].get("min_count", 1))
            stage1_min = int(stages[1].get("min_count", 1))
            s0_events = stage_map.get(0, [])
            s1_events = stage_map.get(1, [])
            if len(s0_events) < stage0_min or len(s1_events) < stage1_min:
                continue

            matched_chain: list[NormalizedEvent] = []
            for success_evt in s1_events:
                prior_failures = [
                    e
                    for e in s0_events
                    if timedelta(0) <= (success_evt.timestamp - e.timestamp) <= window
                ]
                if len(prior_failures) >= stage0_min:
                    matched_chain = [*prior_failures, success_evt]
                    break

            if matched_chain:
                first_ts = matched_chain[0].timestamp.isoformat()
                last_ts = matched_chain[-1].timestamp.isoformat()
                alerts.append(
                    Alert(
                        alert_id=_build_alert_id(rule.id, entity, first_ts),
                        rule_id=rule.id,
                        rule_title=rule.title,
                        severity=rule.level,
                        original_severity=rule.level,
                        description=rule.description,
                        first_seen=first_ts,
                        last_seen=last_ts,
                        event_count=len(matched_chain),
                        entity=entity,
                        mitre_techniques=rule.mitre_techniques,
                        mitre_tactics=rule.mitre_tactics,
                        playbook_id=rule.playbook_id,
                        evidence=[matched_chain[0].raw, matched_chain[-2].raw, matched_chain[-1].raw],
                        matched_fields=_collect_matched_fields(matched_chain),
                    )
                )
        return alerts
