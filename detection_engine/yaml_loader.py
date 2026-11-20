"""Safe YAML loader supporting PyYAML when installed with a zero-dependency stdlib fallback."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

try:
    import yaml as _pyyaml  # type: ignore[import-not-found]
except ImportError:
    _pyyaml = None


class YAMLParseError(ValueError):
    """Raised when a YAML document cannot be safely parsed."""


def _strip_comment(line: str) -> str:
    """Strip inline YAML comments outside single or double quotes."""
    in_single = False
    in_double = False
    escaped = False
    for idx, ch in enumerate(line):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_double:
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if idx == 0 or line[idx - 1].isspace():
                return line[:idx].rstrip()
    return line.rstrip()


def _parse_scalar(raw: str) -> Any:
    """Parse a YAML scalar value (string, int, float, bool, null, empty list/dict)."""
    val = raw.strip()
    if val == "" or val in ("null", "Null", "NULL", "~"):
        return None
    if val in ("true", "True", "TRUE"):
        return True
    if val in ("false", "False", "FALSE"):
        return False
    if val == "[]":
        return []
    if val == "{}":
        return {}
    if val.startswith('"') and val.endswith('"') and len(val) >= 2:
        try:
            return json.loads(val)
        except json.JSONDecodeError as exc:
            raise YAMLParseError(f"Invalid double-quoted YAML string: {val}") from exc
    if val.startswith("'") and val.endswith("'") and len(val) >= 2:
        return val[1:-1].replace("''", "'")
    if re.fullmatch(r"-?\d+", val):
        return int(val)
    if re.fullmatch(r"-?\d+\.\d+", val):
        return float(val)
    if val.startswith("[") and val.endswith("]"):
        inner = val[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(part) for part in inner.split(",")]
    return val


def _split_key_value(content: str) -> tuple[str, str | None]:
    """Split a YAML `key: value` pair while ignoring colons inside quotes."""
    in_single = False
    in_double = False
    escaped = False
    for idx, ch in enumerate(content):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_double:
            escaped = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == ":" and not in_single and not in_double:
            if idx + 1 == len(content) or content[idx + 1].isspace():
                key = content[:idx].strip()
                rest = content[idx + 1 :].strip()
                return key, (rest if rest != "" else None)
    raise YAMLParseError(f"Expected 'key: value' mapping entry, got: {content!r}")


def _prepare_lines(text: str) -> list[tuple[int, str]]:
    """Return non-empty, comment-stripped `(indent, content)` lines."""
    result: list[tuple[int, str]] = []
    for raw_line in text.splitlines():
        if raw_line.strip() in ("---", "..."):
            continue
        cleaned = _strip_comment(raw_line)
        if not cleaned.strip():
            continue
        indent = len(cleaned) - len(cleaned.lstrip(" "))
        result.append((indent, cleaned[indent:]))
    return result


def _parse_block(lines: list[tuple[int, str]], index: int, base_indent: int) -> tuple[Any, int]:
    """Recursively parse a YAML block mapping or sequence."""
    if index >= len(lines):
        return {}, index

    indent, content = lines[index]
    if indent < base_indent:
        return {}, index

    if content.startswith("- ") or content == "-":
        return _parse_sequence(lines, index, indent)
    return _parse_mapping(lines, index, indent)


def _parse_sequence(lines: list[tuple[int, str]], index: int, seq_indent: int) -> tuple[list[Any], int]:
    items: list[Any] = []
    while index < len(lines):
        indent, content = lines[index]
        if indent < seq_indent:
            break
        if indent > seq_indent or not (content.startswith("- ") or content == "-"):
            break

        item_text = content[2:].strip() if content.startswith("- ") else ""
        index += 1

        if not item_text:
            if index < len(lines) and lines[index][0] > seq_indent:
                value, index = _parse_block(lines, index, lines[index][0])
                items.append(value)
            else:
                items.append(None)
            continue

        # Check if sequence item is an inline mapping entry like `- ref: failed_attempts`
        has_inline_kv = False
        if not (item_text.startswith('"') or item_text.startswith("'")):
            try:
                _split_key_value(item_text)
                has_inline_kv = True
            except YAMLParseError:
                has_inline_kv = False

        if has_inline_kv:
            key, val_str = _split_key_value(item_text)
            entry: dict[str, Any] = {}
            if val_str is None:
                if index < len(lines) and lines[index][0] > seq_indent:
                    entry[key], index = _parse_block(lines, index, lines[index][0])
                else:
                    entry[key] = None
            else:
                entry[key] = _parse_scalar(val_str)

            # Merge any subsequent indented keys belonging to this list-item mapping
            if index < len(lines) and lines[index][0] > seq_indent:
                sub_indent = lines[index][0]
                if not (lines[index][1].startswith("- ") or lines[index][1] == "-"):
                    extra, index = _parse_mapping(lines, index, sub_indent)
                    entry.update(extra)
            items.append(entry)
        else:
            items.append(_parse_scalar(item_text))

    return items, index


def _parse_mapping(
    lines: list[tuple[int, str]], index: int, map_indent: int
) -> tuple[dict[str, Any], int]:
    mapping: dict[str, Any] = {}
    while index < len(lines):
        indent, content = lines[index]
        if indent < map_indent:
            break
        if indent > map_indent:
            raise YAMLParseError(f"Unexpected indentation at line: {content!r}")
        if content.startswith("- ") or content == "-":
            break

        key, val_str = _split_key_value(content)
        index += 1

        if val_str is not None:
            mapping[key] = _parse_scalar(val_str)
        else:
            if index < len(lines) and lines[index][0] > map_indent:
                value, index = _parse_block(lines, index, lines[index][0])
                mapping[key] = value
            else:
                mapping[key] = None

    return mapping, index


def parse_yaml_stdlib(text: str) -> Any:
    """Parse a Sigma-compatible YAML document using only the Python standard library."""
    lines = _prepare_lines(text)
    if not lines:
        return {}
    result, _ = _parse_block(lines, 0, lines[0][0])
    return result


def load_yaml_text(text: str) -> Any:
    """Load YAML safely via PyYAML if installed, else via built-in stdlib parser."""
    if _pyyaml is not None:
        try:
            loaded = _pyyaml.safe_load(text)
            return {} if loaded is None else loaded
        except Exception as exc:  # pragma: no cover - PyYAML error forwarding
            raise YAMLParseError(str(exc)) from exc
    return parse_yaml_stdlib(text)


def load_yaml_file(path: str | Path) -> dict[str, Any]:
    """Load a YAML file and ensure the root object is a dictionary."""
    file_path = Path(path)
    text = file_path.read_text(encoding="utf-8")
    data = load_yaml_text(text)
    if not isinstance(data, dict):
        raise YAMLParseError(f"Expected YAML mapping at root of {file_path}")
    return data
