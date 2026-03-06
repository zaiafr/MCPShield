#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[pre-push] Running unit tests..."
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*.py' -q

echo "[pre-push] Running CLI smoke checks..."
PYTHONPATH=src python3 -m mcp_risk_scanner.cli --version >/dev/null
PYTHONPATH=src python3 -m mcp_risk_scanner.cli scan-batch ./fixtures/ci-safe --summary-only --out /tmp/mcp-prepush --fail-on-critical --min-score 80 >/dev/null

echo "[pre-push] All checks passed."
