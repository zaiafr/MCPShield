import json
import tempfile
import unittest
from pathlib import Path

from mcp_risk_scanner.checks import run_checks
from mcp_risk_scanner.checks import list_available_checks
from mcp_risk_scanner.report import render_json
from mcp_risk_scanner.collector import collect_input
from mcp_risk_scanner.rules import load_rules
from mcp_risk_scanner.models import ScanResult


class RulesConfigTests(unittest.TestCase):
    def test_rules_disable_check_and_override_severity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            target.mkdir()
            (target / "server.json").write_text(
                json.dumps(
                    {
                        "name": "x",
                        "tools": [
                            {
                                "name": "exec_shell",
                                "description": "Execute shell commands",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            rules_path = root / "rules.yml"
            rules_path.write_text(
                """
checks:
  dangerous_tools:
    enabled: false
severity_overrides:
  missing_docs: critical
""".strip()
                + "\n",
                encoding="utf-8",
            )

            rules, _ = load_rules(str(rules_path))
            scan_input = collect_input(str(target))
            findings = run_checks(scan_input, rules)
            by_id = {f.check_id: f for f in findings}

            self.assertNotIn("dangerous_tools", by_id)
            self.assertIn("missing_docs", by_id)
            self.assertEqual(by_id["missing_docs"].severity, "critical")

    def test_rules_override_stale_release_days(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            target.mkdir()
            (target / "server.json").write_text(
                json.dumps(
                    {
                        "name": "x",
                        "tools": [],
                        "releaseDate": "2025-01-01T00:00:00Z",
                    }
                ),
                encoding="utf-8",
            )

            rules_path = root / "rules.yml"
            rules_path.write_text(
                """
thresholds:
  stale_release_days: 99999
""".strip()
                + "\n",
                encoding="utf-8",
            )

            rules, _ = load_rules(str(rules_path))
            scan_input = collect_input(str(target))
            findings = run_checks(scan_input, rules)
            ids = {f.check_id for f in findings}
            self.assertNotIn("stale_release", ids)

    def test_report_includes_rules_source_metadata(self):
        result = ScanResult(
            target="x",
            source_type="directory",
            score=90,
            risk_level="low",
            findings=[],
            rules_source="/tmp/rules.yml",
        )
        report_json = render_json(result)
        self.assertIn('\"rules_source\": \"/tmp/rules.yml\"', report_json)

    def test_unknown_check_ids_in_rules_raise(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules_path = Path(tmp) / "rules.yml"
            rules_path.write_text(
                "checks:\n  unknown_check:\n    enabled: false\n",
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_rules(str(rules_path))

    def test_list_available_checks_reflects_rules_enablement(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules_path = Path(tmp) / "rules.yml"
            rules_path.write_text(
                "checks:\n  dangerous_tools:\n    enabled: false\n",
                encoding="utf-8",
            )
            rules, _ = load_rules(str(rules_path))
            checks = list_available_checks(rules)
            dangerous = [c for c in checks if c["check_id"] == "dangerous_tools"][0]
            self.assertEqual(dangerous["enabled"], False)


if __name__ == "__main__":
    unittest.main()
