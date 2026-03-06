from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

from .checks import CheckSpec


def load_plugin_checks(plugin_paths: list[str] | None) -> list[CheckSpec]:
    if not plugin_paths:
        return []

    files = _expand_plugin_files(plugin_paths)
    checks: list[CheckSpec] = []
    seen_ids: set[str] = set()

    for file_path in files:
        module = _load_module_from_file(file_path)
        entries = _extract_check_entries(module)
        for entry in entries:
            spec = _to_check_spec(entry, file_path)
            if spec.check_id in seen_ids:
                raise ValueError(f"Duplicate plugin check_id: {spec.check_id}")
            seen_ids.add(spec.check_id)
            checks.append(spec)

    return checks


def _expand_plugin_files(plugin_paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for raw in plugin_paths:
        path = Path(raw)
        if not path.exists():
            raise ValueError(f"Plugin path not found: {raw}")
        if path.is_file():
            if path.suffix != ".py":
                raise ValueError(f"Plugin file must be .py: {raw}")
            files.append(path)
            continue

        for file_path in sorted(path.glob("*.py")):
            if file_path.name.startswith("__"):
                continue
            files.append(file_path)

    if not files:
        raise ValueError("No plugin python files found")
    return files


def _load_module_from_file(path: Path) -> ModuleType:
    module_name = f"mcp_plugin_{path.stem}_{abs(hash(str(path)))}"
    spec = importlib.util.spec_from_file_location(module_name, str(path))
    if spec is None or spec.loader is None:
        raise ValueError(f"Unable to load plugin module: {path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _extract_check_entries(module: ModuleType) -> list[Any]:
    if hasattr(module, "CHECKS"):
        entries = getattr(module, "CHECKS")
    elif hasattr(module, "get_checks"):
        entries = module.get_checks()
    else:
        raise ValueError("Plugin must expose CHECKS or get_checks()")

    if not isinstance(entries, list):
        raise ValueError("Plugin checks container must be a list")
    return entries


def _to_check_spec(entry: Any, source: Path) -> CheckSpec:
    if isinstance(entry, CheckSpec):
        return entry

    if not isinstance(entry, dict):
        raise ValueError(f"Plugin check entry must be dict or CheckSpec in {source}")

    check_id = entry.get("check_id")
    default_severity = entry.get("default_severity")
    runner = entry.get("runner")

    if not isinstance(check_id, str) or not check_id:
        raise ValueError(f"Plugin check_id must be a non-empty string in {source}")
    if not isinstance(default_severity, str):
        raise ValueError(f"Plugin default_severity must be string in {source}")
    if not callable(runner):
        raise ValueError(f"Plugin runner must be callable in {source}")

    sev = default_severity.lower()
    if sev not in {"critical", "high", "medium", "low"}:
        raise ValueError(f"Invalid plugin severity '{default_severity}' in {source}")

    return CheckSpec(check_id=check_id, default_severity=sev, runner=runner)
