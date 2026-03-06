from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
import hashlib
import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any

from .checks import CheckSpec
from .models import Finding


PLUGIN_RUNNER_TIMEOUT_SECONDS = 1.0


def load_plugin_checks(
    plugin_paths: list[str] | None,
    allowed_origins: list[str] | None = None,
    lock_file: str | None = None,
) -> list[CheckSpec]:
    if not plugin_paths:
        return []

    files = _expand_plugin_files(plugin_paths)
    _validate_allowed_origins(files, allowed_origins)
    _validate_lock_file(files, lock_file)
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


def build_plugin_manifest(plugin_paths: list[str]) -> dict[str, str]:
    files = _expand_plugin_files(plugin_paths)
    manifest: dict[str, str] = {}
    for file_path in files:
        manifest[str(file_path.resolve())] = _sha256_file(file_path)
    return manifest


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
    return [p.resolve() for p in files]


def _validate_allowed_origins(files: list[Path], allowed_origins: list[str] | None) -> None:
    if not allowed_origins:
        return
    allowed = [Path(p).resolve() for p in allowed_origins]
    for file_path in files:
        if not any(_is_relative_to(file_path, prefix) for prefix in allowed):
            raise ValueError(f"Plugin file not allowed by origin policy: {file_path}")


def _validate_lock_file(files: list[Path], lock_file: str | None) -> None:
    if not lock_file:
        return
    lock_path = Path(lock_file)
    if not lock_path.exists():
        raise ValueError(f"Plugin lock file not found: {lock_file}")
    try:
        lock_payload = json.loads(lock_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid plugin lock file JSON: {lock_file}") from exc

    if not isinstance(lock_payload, dict):
        raise ValueError("Plugin lock file must contain a JSON object mapping path->sha256")

    for file_path in files:
        key = str(file_path.resolve())
        expected = lock_payload.get(key)
        if not isinstance(expected, str):
            raise ValueError(f"Missing plugin hash in lock file for: {key}")
        actual = _sha256_file(file_path)
        if actual != expected:
            raise ValueError(f"Plugin hash mismatch for {key}")


def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(8192)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def _is_relative_to(path: Path, prefix: Path) -> bool:
    try:
        path.relative_to(prefix)
        return True
    except ValueError:
        return False


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

    module_prefix = _module_prefix(source)
    if not (check_id.startswith("plugin_") or check_id.startswith(f"{module_prefix}_")):
        raise ValueError(
            f"Plugin check_id '{check_id}' must start with 'plugin_' or '{module_prefix}_'"
        )

    return CheckSpec(
        check_id=check_id,
        default_severity=sev,
        runner=_wrap_safe_runner(check_id, runner),
    )


def _module_prefix(source: Path) -> str:
    raw = source.stem.lower()
    return "".join(ch if ch.isalnum() else "_" for ch in raw)


def _wrap_safe_runner(check_id: str, runner: Any):
    def safe_runner(scan_input):
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(runner, scan_input)
            try:
                result = future.result(timeout=PLUGIN_RUNNER_TIMEOUT_SECONDS)
            except FuturesTimeoutError:
                return [
                    Finding(
                        check_id=check_id,
                        title="Plugin check timed out",
                        severity="medium",
                        category="plugin",
                        message="Plugin check exceeded execution timeout.",
                        evidence=f"timeout={PLUGIN_RUNNER_TIMEOUT_SECONDS}s",
                        remediation="Reduce plugin runtime or optimize the check logic.",
                        evidence_data={"error": "timeout"},
                    )
                ]
            except Exception as exc:  # noqa: BLE001
                return [
                    Finding(
                        check_id=check_id,
                        title="Plugin check failed",
                        severity="medium",
                        category="plugin",
                        message="Plugin check raised an exception.",
                        evidence=f"{type(exc).__name__}: {exc}",
                        remediation="Fix plugin implementation or disable the plugin check.",
                        evidence_data={"error": "exception", "exception_type": type(exc).__name__},
                    )
                ]

        if not isinstance(result, list):
            return [
                Finding(
                    check_id=check_id,
                    title="Plugin check returned invalid result",
                    severity="medium",
                    category="plugin",
                    message="Plugin check must return a list of Finding objects.",
                    evidence=f"received_type={type(result).__name__}",
                    remediation="Update plugin runner to return list[Finding].",
                    evidence_data={"error": "invalid_return_type"},
                )
            ]

        normalized: list[Finding] = []
        for item in result:
            if isinstance(item, Finding):
                normalized.append(item)
            else:
                normalized.append(
                    Finding(
                        check_id=check_id,
                        title="Plugin check returned invalid finding item",
                        severity="medium",
                        category="plugin",
                        message="Plugin returned a non-Finding item.",
                        evidence=f"item_type={type(item).__name__}",
                        remediation="Ensure each item in plugin result is a Finding.",
                        evidence_data={"error": "invalid_finding_item"},
                    )
                )
                break
        return normalized

    return safe_runner
