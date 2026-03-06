from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .checks import run_checks
from .collector import collect_input
from .models import ScanResult
from .report import render_json, render_markdown
from .scoring import calculate_score


def main() -> None:
    parser = argparse.ArgumentParser(prog="mcp-risk-scan", description="Scan MCP server risk")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a server target")
    scan_parser.add_argument("target", help="Path, URL, or npm package name")
    scan_parser.add_argument(
        "--format",
        choices=["json", "md", "both"],
        default="both",
        help="Output format",
    )
    scan_parser.add_argument(
        "--out",
        default=".",
        help="Output directory for report files",
    )

    args = parser.parse_args()

    if args.command == "scan":
        _run_scan(args.target, args.format, args.out)


def _run_scan(target: str, output_format: str, out_dir: str) -> None:
    scan_input = collect_input(target)
    findings = run_checks(scan_input)
    score, risk_level = calculate_score(findings)

    result = ScanResult(
        target=scan_input.target,
        source_type=scan_input.source_type,
        score=score,
        risk_level=risk_level,
        findings=findings,
    )

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stem = _safe_stem(target)

    if output_format in {"json", "both"}:
        json_report = render_json(result)
        json_path = out / f"{stem}.risk.json"
        json_path.write_text(json_report, encoding="utf-8")
        print(f"Wrote {json_path}")

    if output_format in {"md", "both"}:
        md_report = render_markdown(result)
        md_path = out / f"{stem}.risk.md"
        md_path.write_text(md_report, encoding="utf-8")
        print(f"Wrote {md_path}")

    print(f"Final score: {score}/100 ({risk_level})")


def _safe_stem(target: str) -> str:
    raw = target.replace("https://", "").replace("http://", "")
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in raw)
    cleaned = cleaned.strip("._")
    return cleaned[:80] or "scan"


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
