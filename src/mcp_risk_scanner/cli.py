from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import sys
from collections import Counter

from .checks import run_checks
from .collector import collect_input
from .models import Finding, ScanResult
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
    batch_parser = subparsers.add_parser("scan-batch", help="Scan a directory of local targets")
    batch_parser.add_argument(
        "input_dir",
        help="Directory containing target subdirectories with server.json",
    )
    batch_parser.add_argument(
        "--format",
        choices=["json", "md", "both"],
        default="both",
        help="Output format for per-target reports",
    )
    batch_parser.add_argument(
        "--out",
        default=".",
        help="Output directory for report files",
    )
    batch_parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Only write summary outputs (json, md, csv), skip per-target reports",
    )

    args = parser.parse_args()

    if args.command == "scan":
        _run_scan(args.target, args.format, args.out)
    elif args.command == "scan-batch":
        _run_scan_batch(args.input_dir, args.format, args.out, summary_only=args.summary_only)


def _run_scan(target: str, output_format: str, out_dir: str) -> None:
    result = _scan_target(target)

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stem = _safe_stem(target)
    _write_result_files(result, output_format, out, stem)
    print(f"Final score: {result.score}/100 ({result.risk_level})")


def _scan_target(target: str) -> ScanResult:
    scan_input = collect_input(target)
    findings = _sort_findings(run_checks(scan_input))
    score, risk_level = calculate_score(findings)
    return ScanResult(
        target=scan_input.target,
        source_type=scan_input.source_type,
        score=score,
        risk_level=risk_level,
        findings=findings,
    )


def _run_scan_batch(
    input_dir: str, output_format: str, out_dir: str, summary_only: bool = False
) -> None:
    root = Path(input_dir)
    if not root.exists() or not root.is_dir():
        raise ValueError(f"Input directory not found: {input_dir}")

    targets = sorted(
        p for p in root.iterdir() if p.is_dir() and (p / "server.json").exists()
    )
    if not targets:
        raise ValueError(f"No scan targets found in: {input_dir}")

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    results: list[ScanResult] = []
    for target in targets:
        result = _scan_target(str(target))
        results.append(result)
        if not summary_only:
            _write_result_files(result, output_format, out, _safe_stem(target.name))

    summary = _build_summary(results)
    summary_json_path = out / "summary.json"
    summary_json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"Wrote {summary_json_path}")

    summary_md_path = out / "summary.md"
    summary_md_path.write_text(_render_summary_markdown(summary), encoding="utf-8")
    print(f"Wrote {summary_md_path}")

    summary_csv_path = out / "summary.csv"
    summary_csv_path.write_text(_render_summary_csv(results), encoding="utf-8")
    print(f"Wrote {summary_csv_path}")


def _write_result_files(result: ScanResult, output_format: str, out: Path, stem: str) -> None:
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


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-_severity_rank(f.severity), f.check_id))


def _severity_rank(severity: str) -> int:
    ranks = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return ranks.get(severity, 0)


def _build_summary(results: list[ScanResult]) -> dict:
    risk_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    check_counts: Counter[str] = Counter()
    for result in results:
        risk_counts[result.risk_level] = risk_counts.get(result.risk_level, 0) + 1
        check_counts.update(f.check_id for f in result.findings)

    avg_score = sum(r.score for r in results) / len(results)
    top_checks = [
        {"check_id": check_id, "count": count}
        for check_id, count in sorted(check_counts.items(), key=lambda item: (-item[1], item[0]))
    ][:10]
    return {
        "total_scanned": len(results),
        "average_score": round(avg_score, 2),
        "risk_level_counts": risk_counts,
        "top_checks": top_checks,
    }


def _render_summary_markdown(summary: dict) -> str:
    lines = [
        "# MCP Batch Scan Summary",
        "",
        f"- Total scanned: **{summary['total_scanned']}**",
        f"- Average score: **{summary['average_score']}**",
        "",
        "## Risk Levels",
        "",
        "| Level | Count |",
        "|---|---|",
    ]
    for level in ["critical", "high", "medium", "low"]:
        lines.append(f"| {level} | {summary['risk_level_counts'].get(level, 0)} |")

    lines.extend(["", "## Top Checks", "", "| Check ID | Count |", "|---|---|"])
    for entry in summary["top_checks"]:
        lines.append(f"| {entry['check_id']} | {entry['count']} |")
    lines.append("")
    return "\n".join(lines)


def _render_summary_csv(results: list[ScanResult]) -> str:
    rows: list[list[str]] = [["target", "score", "risk_level", "findings_count"]]
    for result in results:
        rows.append(
            [
                result.target,
                str(result.score),
                result.risk_level,
                str(len(result.findings)),
            ]
        )

    # Use csv writer for proper quoting; keep line endings stable.
    from io import StringIO

    buf = StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerows(rows)
    return buf.getvalue()


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
