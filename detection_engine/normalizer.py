"""Multi-source log normalizer converting raw logs into ECS-inspired NormalizedEvent objects."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from detection_engine.models import NormalizedEvent

# Example SSH auth.log line:
# Nov 20 14:12:01 web-prod-01 sshd[4102]: Failed password for invalid user admin from 198.51.100.77 ...
SSH_SYSLOG_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<message>.+)$"
)
SSH_FAILED_RE = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)
SSH_ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)

# Example Nginx/Apache combined access.log line:
# 203.0.113.45 - - [20/Nov/2026:14:15:10 +0000] "GET /api/users?id=1 HTTP/1.1" 200 512 "-" "Mozilla/5.0"
WEB_ACCESS_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<url>\S+)\s+HTTP/[\d.]+"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"$'
)


def _parse_iso_timestamp(value: str) -> datetime:
    cleaned = value.strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    dt = datetime.fromisoformat(cleaned)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def parse_ssh_line(
    line: str,
    *,
    year: int | None = None,
    line_number: int = 0,
    source_file: str = "",
) -> NormalizedEvent | None:
    """Normalize a Linux sshd syslog line."""
    match = SSH_SYSLOG_RE.match(line.strip())
    if not match:
        return None

    ref_year = year or datetime.now(UTC).year
    ts_str = f"{ref_year} {match.group('month')} {int(match.group('day')):02d} {match.group('time')}"
    timestamp = datetime.strptime(ts_str, "%Y %b %d %H:%M:%S").replace(tzinfo=UTC)
    host = match.group("host")
    message = match.group("message")

    fields: dict[str, Any] = {
        "event.category": "authentication",
        "host.name": host,
        "message": message,
    }

    if failed := SSH_FAILED_RE.search(message):
        fields["event.action"] = "ssh_login_failed"
        fields["event.outcome"] = "failure"
        fields["user.name"] = failed.group("user")
        fields["source.ip"] = failed.group("ip")
        fields["source.port"] = int(failed.group("port"))
    elif accepted := SSH_ACCEPTED_RE.search(message):
        fields["event.action"] = "ssh_login_success"
        fields["event.outcome"] = "success"
        fields["user.name"] = accepted.group("user")
        fields["source.ip"] = accepted.group("ip")
        fields["source.port"] = int(accepted.group("port"))
        fields["ssh.auth_method"] = accepted.group("method")
    else:
        fields["event.action"] = "ssh_other"
        fields["event.outcome"] = "unknown"

    return NormalizedEvent(
        timestamp=timestamp,
        source_type="sshd",
        logsource={"product": "linux", "service": "sshd"},
        fields=fields,
        raw=line.strip(),
        line_number=line_number,
        source_file=source_file,
    )


def parse_web_line(
    line: str,
    *,
    line_number: int = 0,
    source_file: str = "",
) -> NormalizedEvent | None:
    """Normalize an Nginx/Apache combined access log line."""
    match = WEB_ACCESS_RE.match(line.strip())
    if not match:
        return None

    timestamp = datetime.strptime(match.group("ts"), "%d/%b/%Y:%H:%M:%S %z").astimezone(UTC)
    user = match.group("user")
    status_code = int(match.group("status"))

    fields: dict[str, Any] = {
        "event.category": "web",
        "event.action": "http_request",
        "event.outcome": "success" if status_code < 400 else "failure",
        "source.ip": match.group("ip"),
        "user.name": "" if user == "-" else user,
        "http.request.method": match.group("method"),
        "url.original": match.group("url"),
        "http.response.status_code": status_code,
        "user_agent.original": match.group("ua"),
    }

    return NormalizedEvent(
        timestamp=timestamp,
        source_type="webserver",
        logsource={"category": "webserver"},
        fields=fields,
        raw=line.strip(),
        line_number=line_number,
        source_file=source_file,
    )


def parse_linux_audit_line(
    line: str,
    *,
    line_number: int = 0,
    source_file: str = "",
) -> NormalizedEvent | None:
    """Normalize a Linux process execution / audit JSONL event."""
    stripped = line.strip()
    if not stripped.startswith("{"):
        return None
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict) or "command_line" not in payload:
        return None

    ts_raw = str(payload.get("timestamp", ""))
    timestamp = _parse_iso_timestamp(ts_raw) if ts_raw else datetime.now(UTC)
    command_line = str(payload.get("command_line", ""))
    process_name = str(payload.get("process") or (command_line.split()[0] if command_line else ""))

    fields: dict[str, Any] = {
        "event.category": "process",
        "event.action": str(payload.get("event_action", "process_exec")),
        "event.outcome": "success",
        "host.name": str(payload.get("host", "unknown-host")),
        "user.name": str(payload.get("user", "unknown")),
        "source.ip": str(payload.get("source_ip", "")),
        "process.name": process_name,
        "process.command_line": command_line,
        "process.pid": int(payload.get("pid", 0)),
    }

    return NormalizedEvent(
        timestamp=timestamp,
        source_type="linux_audit",
        logsource={"product": "linux", "category": "process_creation"},
        fields=fields,
        raw=stripped,
        line_number=line_number,
        source_file=source_file,
    )


def parse_log_line(
    line: str,
    *,
    log_type: str = "auto",
    year: int | None = None,
    line_number: int = 0,
    source_file: str = "",
) -> NormalizedEvent | None:
    """Parse a single raw log line with explicit or automatic format detection."""
    stripped = line.strip()
    if not stripped:
        return None

    if log_type == "sshd":
        return parse_ssh_line(stripped, year=year, line_number=line_number, source_file=source_file)
    if log_type == "webserver":
        return parse_web_line(stripped, line_number=line_number, source_file=source_file)
    if log_type == "linux_audit":
        return parse_linux_audit_line(stripped, line_number=line_number, source_file=source_file)

    # Auto-detection order: JSON audit -> Web access -> SSH syslog
    if stripped.startswith("{"):
        return parse_linux_audit_line(stripped, line_number=line_number, source_file=source_file)
    web_evt = parse_web_line(stripped, line_number=line_number, source_file=source_file)
    if web_evt is not None:
        return web_evt
    return parse_ssh_line(stripped, year=year, line_number=line_number, source_file=source_file)


def load_events_from_paths(
    paths: list[str | Path],
    *,
    log_type: str = "auto",
    year: int | None = None,
) -> tuple[list[NormalizedEvent], list[str]]:
    """Load and normalize events from files or directories, sorted chronologically."""
    resolved_files: list[Path] = []
    for raw_path in paths:
        path = Path(raw_path)
        if path.is_dir():
            for child in sorted(path.iterdir()):
                if child.is_file() and child.suffix.lower() in {".log", ".jsonl", ".json", ".txt"}:
                    resolved_files.append(child)
        elif path.is_file():
            resolved_files.append(path)
        else:
            raise FileNotFoundError(f"Log path not found: {path}")

    events: list[NormalizedEvent] = []
    for file_path in resolved_files:
        text = file_path.read_text(encoding="utf-8", errors="replace")
        for idx, line in enumerate(text.splitlines(), start=1):
            event = parse_log_line(
                line,
                log_type=log_type,
                year=year,
                line_number=idx,
                source_file=file_path.name,
            )
            if event is not None:
                events.append(event)

    events.sort(key=lambda e: e.timestamp)
    return events, [str(p) for p in resolved_files]
