from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any


DEFAULT_RULES: dict[str, Any] = {
    "checks": {},
    "severity_overrides": {},
    "thresholds": {
        "stale_release_days": 180,
    },
    "keywords": {
        "dangerous_tools": [
            "exec",
            "shell",
            "bash",
            "powershell",
            "terminal",
            "filesystem",
            "file write",
            "delete",
            "fetch",
            "http",
            "git_init",
        ]
    },
}


def default_rules() -> dict[str, Any]:
    return deepcopy(DEFAULT_RULES)


def load_rules(path: str | None) -> tuple[dict[str, Any], str | None]:
    if not path:
        return default_rules(), None

    raw = Path(path).read_text(encoding="utf-8")
    loaded = _parse_structured_text(raw)
    if not isinstance(loaded, dict):
        raise ValueError("Rules file must parse to an object/map")

    rules = default_rules()
    _deep_merge(rules, loaded)
    _validate_rules(rules)
    return rules, str(Path(path))


def _parse_structured_text(raw: str) -> Any:
    stripped = raw.strip()
    if not stripped:
        return {}

    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return _parse_simple_yaml(stripped)


def _parse_simple_yaml(raw: str) -> Any:
    lines = []
    for original in raw.splitlines():
        no_comment = original.split("#", 1)[0].rstrip()
        if not no_comment.strip():
            continue
        indent = len(no_comment) - len(no_comment.lstrip(" "))
        lines.append((indent, no_comment.strip()))

    if not lines:
        return {}

    root: dict[str, Any] = {}
    stack: list[tuple[int, Any]] = [(-1, root)]

    for idx, (indent, token) in enumerate(lines):
        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()

        parent = stack[-1][1]
        if token.startswith("- "):
            if not isinstance(parent, list):
                raise ValueError("Invalid YAML list placement")
            item_token = token[2:].strip()
            parent.append(_parse_scalar(item_token))
            continue

        if ":" not in token:
            raise ValueError(f"Invalid YAML line: {token}")

        key, value = token.split(":", 1)
        key = key.strip()
        value = value.strip()
        if not isinstance(parent, dict):
            raise ValueError("Invalid YAML mapping placement")

        if value:
            parent[key] = _parse_scalar(value)
            continue

        # determine nested container type using the next line
        next_container: Any = {}
        if idx + 1 < len(lines):
            next_indent, next_token = lines[idx + 1]
            if next_indent > indent and next_token.startswith("- "):
                next_container = []
        parent[key] = next_container
        stack.append((indent, next_container))

    return root


def _parse_scalar(value: str) -> Any:
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered in {"null", "none"}:
        return None

    # Strip simple quotes
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]

    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value


def _deep_merge(base: dict[str, Any], incoming: dict[str, Any]) -> None:
    for key, value in incoming.items():
        if (
            key in base
            and isinstance(base[key], dict)
            and isinstance(value, dict)
        ):
            _deep_merge(base[key], value)
        else:
            base[key] = value


def _validate_rules(rules: dict[str, Any]) -> None:
    thresholds = rules.get("thresholds", {})
    if not isinstance(thresholds, dict):
        raise ValueError("thresholds must be a map")

    stale_days = thresholds.get("stale_release_days", 180)
    if not isinstance(stale_days, (int, float)) or stale_days < 0:
        raise ValueError("thresholds.stale_release_days must be a non-negative number")

    checks = rules.get("checks", {})
    if not isinstance(checks, dict):
        raise ValueError("checks must be a map")

    sev = rules.get("severity_overrides", {})
    if not isinstance(sev, dict):
        raise ValueError("severity_overrides must be a map")

    keywords = rules.get("keywords", {})
    if not isinstance(keywords, dict):
        raise ValueError("keywords must be a map")
