from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import sys
from collections import Counter
from typing import Any

from .checks import list_available_checks, run_checks
from .collector import collect_input
from . import __version__
from .models import Finding, ScanResult
from .plugins import load_plugin_checks
from .report import render_json, render_markdown
from .rules import load_rules
from .scoring import calculate_score


def main() -> None:
    parser = argparse.ArgumentParser(prog="mcpshield", description="Scan MCP server risk")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a server target")
    scan_parser.add_argument("target", nargs="?", help="Path, URL, or npm package name")
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
    scan_parser.add_argument(
        "--rules",
        default=None,
        help="Path to rules.yml for check toggles/severity/threshold overrides",
    )
    scan_parser.add_argument(
        "--plugins",
        nargs="*",
        default=None,
        help="Plugin .py files or directories containing plugin checks",
    )
    scan_parser.add_argument(
        "--allow-plugins",
        action="store_true",
        help="Explicitly allow loading and executing plugin checks",
    )
    scan_parser.add_argument(
        "--allow-plugin-origin",
        action="append",
        default=None,
        help="Allowed plugin path prefix (repeatable)",
    )
    scan_parser.add_argument(
        "--plugin-lock",
        default=None,
        help="Path to plugin lock JSON mapping plugin absolute paths to sha256",
    )
    scan_parser.add_argument(
        "--list-checks",
        action="store_true",
        help="List available checks and exit",
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
    batch_parser.add_argument(
        "--fail-on-critical",
        action="store_true",
        help="Return non-zero if any scanned target is in critical risk level",
    )
    batch_parser.add_argument(
        "--min-score",
        type=float,
        default=None,
        help="Return non-zero if any scanned target score falls below this threshold",
    )
    batch_parser.add_argument(
        "--rules",
        default=None,
        help="Path to rules.yml for check toggles/severity/threshold overrides",
    )
    batch_parser.add_argument(
        "--plugins",
        nargs="*",
        default=None,
        help="Plugin .py files or directories containing plugin checks",
    )
    batch_parser.add_argument(
        "--allow-plugins",
        action="store_true",
        help="Explicitly allow loading and executing plugin checks",
    )
    batch_parser.add_argument(
        "--allow-plugin-origin",
        action="append",
        default=None,
        help="Allowed plugin path prefix (repeatable)",
    )
    batch_parser.add_argument(
        "--plugin-lock",
        default=None,
        help="Path to plugin lock JSON mapping plugin absolute paths to sha256",
    )
    compare_parser = subparsers.add_parser(
        "compare-summaries", help="Compare two summary.csv files and write delta outputs"
    )
    compare_parser.add_argument("old_csv", help="Baseline summary.csv path")
    compare_parser.add_argument("new_csv", help="Current summary.csv path")
    compare_parser.add_argument("--out", default=".", help="Output directory for delta files")
    manifest_parser = subparsers.add_parser(
        "plugin-manifest", help="Generate plugin lock manifest (path->sha256)"
    )
    manifest_parser.add_argument(
        "plugins",
        nargs="+",
        help="Plugin .py files or directories to include in manifest",
    )
    manifest_parser.add_argument(
        "--out",
        default="plugins.lock",
        help="Output lock file path",
    )

    args = parser.parse_args()

    if args.command == "scan":
        if args.list_checks:
            plugin_checks = _resolve_plugins(
                args.plugins,
                args.allow_plugins,
                allowed_origins=args.allow_plugin_origin,
                lock_file=args.plugin_lock,
            )
            rules, _ = load_rules(
                args.rules, extra_check_ids={spec.check_id for spec in plugin_checks}
            )
            _print_check_list(rules, plugin_checks=plugin_checks)
            return
        if not args.target:
            raise ValueError("scan target is required unless --list-checks is used")
        _run_scan(
            args.target,
            args.format,
            args.out,
            rules_path=args.rules,
            plugin_paths=args.plugins,
            allow_plugins=args.allow_plugins,
            allowed_origins=args.allow_plugin_origin,
            plugin_lock=args.plugin_lock,
        )
    elif args.command == "scan-batch":
        _run_scan_batch(
            args.input_dir,
            args.format,
            args.out,
            summary_only=args.summary_only,
            fail_on_critical=args.fail_on_critical,
            min_score=args.min_score,
            rules_path=args.rules,
            plugin_paths=args.plugins,
            allow_plugins=args.allow_plugins,
            allowed_origins=args.allow_plugin_origin,
            plugin_lock=args.plugin_lock,
        )
    elif args.command == "compare-summaries":
        _run_compare_summaries(args.old_csv, args.new_csv, args.out)
    elif args.command == "plugin-manifest":
        _run_plugin_manifest(args.plugins, args.out)


def _run_scan(
    target: str,
    output_format: str,
    out_dir: str,
    rules_path: str | None = None,
    plugin_paths: list[str] | None = None,
    allow_plugins: bool = False,
    allowed_origins: list[str] | None = None,
    plugin_lock: str | None = None,
    quiet: bool = False,
) -> None:
    plugin_checks = _resolve_plugins(
        plugin_paths,
        allow_plugins,
        allowed_origins=allowed_origins,
        lock_file=plugin_lock,
    )
    rules, rules_source = load_rules(
        rules_path, extra_check_ids={spec.check_id for spec in plugin_checks}
    )
    result = _scan_target(
        target, rules=rules, rules_source=rules_source, plugin_checks=plugin_checks
    )

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stem = _safe_stem(target)
    _write_result_files(result, output_format, out, stem, quiet=quiet)
    _emit(f"Final score: {result.score}/100 ({result.risk_level})", quiet=quiet)


def _print_check_list(
    rules: dict[str, Any] | None = None, plugin_checks: list[Any] | None = None
) -> None:
    checks = list_available_checks(rules, extra_checks=plugin_checks)
    print("check_id | default_severity | enabled")
    print("---|---|---")
    for check in checks:
        enabled = "true" if check["enabled"] else "false"
        print(f"{check['check_id']} | {check['default_severity']} | {enabled}")


def _scan_target(
    target: str,
    rules: dict[str, Any] | None = None,
    rules_source: str | None = None,
    plugin_checks: list[Any] | None = None,
) -> ScanResult:
    scan_input = collect_input(target)
    findings = _sort_findings(run_checks(scan_input, rules, extra_checks=plugin_checks))
    score, risk_level = calculate_score(findings)
    return ScanResult(
        target=scan_input.target,
        source_type=scan_input.source_type,
        score=score,
        risk_level=risk_level,
        findings=findings,
        rules_source=rules_source,
    )


def _run_scan_batch(
    input_dir: str,
    output_format: str,
    out_dir: str,
    summary_only: bool = False,
    fail_on_critical: bool = False,
    min_score: float | None = None,
    rules_path: str | None = None,
    plugin_paths: list[str] | None = None,
    allow_plugins: bool = False,
    allowed_origins: list[str] | None = None,
    plugin_lock: str | None = None,
    quiet: bool = False,
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
    plugin_checks = _resolve_plugins(
        plugin_paths,
        allow_plugins,
        allowed_origins=allowed_origins,
        lock_file=plugin_lock,
    )
    rules, rules_source = load_rules(
        rules_path, extra_check_ids={spec.check_id for spec in plugin_checks}
    )

    results: list[ScanResult] = []
    for target in targets:
        result = _scan_target(
            str(target), rules=rules, rules_source=rules_source, plugin_checks=plugin_checks
        )
        results.append(result)
        if not summary_only:
            _write_result_files(
                result, output_format, out, _safe_stem(target.name), quiet=quiet
            )

    summary = _build_summary(results)
    summary_json_path = out / "summary.json"
    summary_json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    _emit(f"Wrote {summary_json_path}", quiet=quiet)

    summary_md_path = out / "summary.md"
    summary_md_path.write_text(_render_summary_markdown(summary), encoding="utf-8")
    _emit(f"Wrote {summary_md_path}", quiet=quiet)

    summary_csv_path = out / "summary.csv"
    summary_csv_path.write_text(_render_summary_csv(results), encoding="utf-8")
    _emit(f"Wrote {summary_csv_path}", quiet=quiet)

    violations: list[str] = []
    if fail_on_critical and summary["risk_level_counts"].get("critical", 0) > 0:
        violations.append("critical risk targets detected")

    if min_score is not None:
        below = [r for r in results if r.score < min_score]
        if below:
            violations.append(
                f"{len(below)} target(s) below min score {min_score}: "
                + ", ".join(Path(r.target).name for r in below[:10])
            )

    if violations:
        raise RuntimeError("Quality gate failed: " + " | ".join(violations))


def _write_result_files(
    result: ScanResult, output_format: str, out: Path, stem: str, quiet: bool = False
) -> None:
    if output_format in {"json", "both"}:
        json_report = render_json(result)
        json_path = out / f"{stem}.risk.json"
        json_path.write_text(json_report, encoding="utf-8")
        _emit(f"Wrote {json_path}", quiet=quiet)

    if output_format in {"md", "both"}:
        md_report = render_markdown(result)
        md_path = out / f"{stem}.risk.md"
        md_path.write_text(md_report, encoding="utf-8")
        _emit(f"Wrote {md_path}", quiet=quiet)


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


def _run_compare_summaries(
    old_csv: str, new_csv: str, out_dir: str, quiet: bool = False
) -> None:
    old_rows = _load_summary_csv(old_csv)
    new_rows = _load_summary_csv(new_csv)
    delta = _build_delta(old_rows, new_rows)

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    delta_json_path = out / "delta.json"
    delta_json_path.write_text(json.dumps(delta, indent=2), encoding="utf-8")
    _emit(f"Wrote {delta_json_path}", quiet=quiet)

    delta_md_path = out / "delta.md"
    delta_md_path.write_text(_render_delta_markdown(delta), encoding="utf-8")
    _emit(f"Wrote {delta_md_path}", quiet=quiet)


def _emit(message: str, quiet: bool = False) -> None:
    if not quiet:
        print(message)


def _resolve_plugins(
    plugin_paths: list[str] | None,
    allow_plugins: bool,
    allowed_origins: list[str] | None = None,
    lock_file: str | None = None,
) -> list[Any]:
    if (plugin_paths or allowed_origins or lock_file) and not allow_plugins:
        raise ValueError("Refusing to load plugins without --allow-plugins")
    return load_plugin_checks(
        plugin_paths if allow_plugins else None,
        allowed_origins=allowed_origins,
        lock_file=lock_file,
    )


def _run_plugin_manifest(plugin_paths: list[str], out_path: str) -> None:
    from .plugins import build_plugin_manifest

    manifest = build_plugin_manifest(plugin_paths)
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {out}")


def _load_summary_csv(path: str) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    with Path(path).open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"target", "score", "risk_level", "findings_count"}
        if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
            raise ValueError(f"Invalid summary CSV header in {path}")
        for row in reader:
            target = str(row["target"])
            rows[target] = {
                "score": float(row["score"]),
                "risk_level": str(row["risk_level"]),
                "findings_count": int(row["findings_count"]),
            }
    return rows


def _build_delta(
    old_rows: dict[str, dict[str, Any]], new_rows: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    all_targets = sorted(set(old_rows) | set(new_rows))
    changes: list[dict[str, Any]] = []
    regressions = 0
    improvements = 0
    new_targets = 0
    removed_targets = 0

    for target in all_targets:
        old = old_rows.get(target)
        new = new_rows.get(target)
        if old is None and new is not None:
            new_targets += 1
            regressions += 1 if _risk_rank(new["risk_level"]) >= _risk_rank("high") else 0
            changes.append(
                {
                    "target": target,
                    "status": "new",
                    "score_delta": None,
                    "risk_change": f"none -> {new['risk_level']}",
                    "old": None,
                    "new": new,
                }
            )
            continue
        if old is not None and new is None:
            removed_targets += 1
            changes.append(
                {
                    "target": target,
                    "status": "removed",
                    "score_delta": None,
                    "risk_change": f"{old['risk_level']} -> none",
                    "old": old,
                    "new": None,
                }
            )
            continue

        assert old is not None and new is not None
        score_delta = round(new["score"] - old["score"], 2)
        old_rank = _risk_rank(old["risk_level"])
        new_rank = _risk_rank(new["risk_level"])
        status = "unchanged"
        if new_rank < old_rank or score_delta > 0:
            improvements += 1
            status = "improved"
        elif new_rank > old_rank or score_delta < 0:
            regressions += 1
            status = "regressed"

        changes.append(
            {
                "target": target,
                "status": status,
                "score_delta": score_delta,
                "risk_change": f"{old['risk_level']} -> {new['risk_level']}",
                "old": old,
                "new": new,
            }
        )

    return {
        "targets_compared": len(all_targets),
        "regressions_count": regressions,
        "improvements_count": improvements,
        "new_targets_count": new_targets,
        "removed_targets_count": removed_targets,
        "changes": changes,
    }


def _render_delta_markdown(delta: dict[str, Any]) -> str:
    lines = [
        "# MCP Summary Delta",
        "",
        f"- Targets compared: **{delta['targets_compared']}**",
        f"- Improvements: **{delta['improvements_count']}**",
        f"- Regressions: **{delta['regressions_count']}**",
        f"- New targets: **{delta['new_targets_count']}**",
        f"- Removed targets: **{delta['removed_targets_count']}**",
        "",
        "## Changes",
        "",
        "| Target | Status | Score Delta | Risk Change |",
        "|---|---|---|---|",
    ]
    for change in delta["changes"]:
        score_delta = (
            "n/a" if change["score_delta"] is None else f"{change['score_delta']:+.2f}"
        )
        lines.append(
            f"| {change['target']} | {change['status']} | {score_delta} | {change['risk_change']} |"
        )
    lines.append("")
    return "\n".join(lines)


def _risk_rank(level: str) -> int:
    ranks = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
    return ranks.get(level, 0)


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
