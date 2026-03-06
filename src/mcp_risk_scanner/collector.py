from __future__ import annotations

import json
import os
import re
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .models import ScanInput


def collect_input(target: str, timeout_seconds: int = 10) -> ScanInput:
    target = target.strip()
    if target.startswith("http://") or target.startswith("https://"):
        return _from_url(target, timeout_seconds)

    target_path = Path(target)
    if target_path.exists():
        if target_path.is_dir():
            return _from_directory(target_path)
        return _from_file(target_path)

    if _looks_like_npm_package(target):
        return _from_npm(target, timeout_seconds)

    raise ValueError(
        "Unsupported target. Provide a local path, URL, or npm package name."
    )


def _from_file(path: Path) -> ScanInput:
    if path.name != "server.json":
        raise ValueError("Only server.json file input is supported for local files.")

    server_json = _load_json(path)
    package_json_path = path.parent / "package.json"
    package_json = _load_json(package_json_path) if package_json_path.exists() else None

    return ScanInput(
        target=str(path),
        source_type="file",
        server_json=server_json,
        package_json=package_json,
        root_dir=str(path.parent),
        raw_sources={"server_json_path": str(path)},
    )


def _from_directory(path: Path) -> ScanInput:
    server_json_path = path / "server.json"
    if not server_json_path.exists():
        raise ValueError(f"No server.json found in directory: {path}")

    server_json = _load_json(server_json_path)
    package_json_path = path / "package.json"
    package_json = _load_json(package_json_path) if package_json_path.exists() else None

    return ScanInput(
        target=str(path),
        source_type="directory",
        server_json=server_json,
        package_json=package_json,
        root_dir=str(path),
        raw_sources={"server_json_path": str(server_json_path)},
    )


def _from_url(url: str, timeout_seconds: int) -> ScanInput:
    server_json = _fetch_json(url, timeout_seconds)
    return ScanInput(
        target=url,
        source_type="url",
        server_json=server_json,
        package_json=None,
        raw_sources={"server_json_url": url},
    )


def _from_npm(package_name: str, timeout_seconds: int) -> ScanInput:
    metadata_url = f"https://registry.npmjs.org/{package_name}"
    metadata = _fetch_json(metadata_url, timeout_seconds)

    latest_tag = metadata.get("dist-tags", {}).get("latest")
    versions = metadata.get("versions", {})
    package_json = versions.get(latest_tag) if latest_tag else None

    server_json = _extract_server_json_from_package(package_json)
    if not server_json:
        server_json = {
            "name": package_name,
            "description": "No server.json found in npm metadata",
            "tools": [],
        }

    return ScanInput(
        target=package_name,
        source_type="npm",
        server_json=server_json,
        package_json=package_json,
        raw_sources={
            "npm_package": package_name,
            "npm_latest": latest_tag,
            "npm_metadata_url": metadata_url,
        },
    )


def _extract_server_json_from_package(package_json: dict | None) -> dict | None:
    if not package_json:
        return None
    mcp = package_json.get("mcp")
    if isinstance(mcp, dict):
        server = mcp.get("server")
        if isinstance(server, dict):
            return server
    return None


def _fetch_json(url: str, timeout_seconds: int) -> dict:
    request = Request(url, headers={"User-Agent": "mcp-risk-scanner/0.1"})
    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw)
    except (HTTPError, URLError, TimeoutError) as exc:
        raise RuntimeError(f"Unable to fetch JSON from {url}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid JSON payload from {url}") from exc


def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid JSON in {path}: {exc}") from exc


def _looks_like_npm_package(value: str) -> bool:
    # Accept standard package names like foo or @scope/foo
    return bool(re.fullmatch(r"(?:@[a-z0-9._-]+/)?[a-z0-9._-]+", value))
