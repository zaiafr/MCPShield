from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from .checks import known_check_ids

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None


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


def load_rules(
    path: str | None, extra_check_ids: set[str] | None = None
) -> tuple[dict[str, Any], str | None]:
    if not path:
        return default_rules(), None

    raw = Path(path).read_text(encoding="utf-8")
    loaded = _parse_structured_text(raw)
    if not isinstance(loaded, dict):
        raise ValueError("Rules file must parse to an object/map")

    rules = default_rules()
    _deep_merge(rules, loaded)
    _validate_rules(rules, extra_check_ids=extra_check_ids)
    return rules, str(Path(path))


def _parse_structured_text(raw: str) -> Any:
    stripped = raw.strip()
    if not stripped:
        return {}

    if yaml is not None:
        try:
            parsed = yaml.safe_load(stripped)
        except yaml.YAMLError as exc:  # type: ignore[union-attr]
            raise ValueError(f"Invalid YAML rules file: {exc}") from exc
        return {} if parsed is None else parsed

    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        raise ValueError("Rules file is neither valid YAML nor JSON")


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


def _validate_rules(rules: dict[str, Any], extra_check_ids: set[str] | None = None) -> None:
    thresholds = rules.get("thresholds", {})
    if not isinstance(thresholds, dict):
        raise ValueError("thresholds must be a map")

    stale_days = thresholds.get("stale_release_days", 180)
    if not isinstance(stale_days, (int, float)) or stale_days < 0:
        raise ValueError("thresholds.stale_release_days must be a non-negative number")

    checks = rules.get("checks", {})
    if not isinstance(checks, dict):
        raise ValueError("checks must be a map")
    known_ids = known_check_ids()
    if extra_check_ids:
        known_ids = known_ids.union(extra_check_ids)
    unknown_checks = [key for key in checks if key not in known_ids]
    if unknown_checks:
        raise ValueError(f"Unknown check ids in checks: {', '.join(sorted(unknown_checks))}")

    sev = rules.get("severity_overrides", {})
    if not isinstance(sev, dict):
        raise ValueError("severity_overrides must be a map")
    unknown_severity = [key for key in sev if key not in known_ids]
    if unknown_severity:
        raise ValueError(
            "Unknown check ids in severity_overrides: " + ", ".join(sorted(unknown_severity))
        )

    keywords = rules.get("keywords", {})
    if not isinstance(keywords, dict):
        raise ValueError("keywords must be a map")
