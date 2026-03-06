import json
import tempfile
import time
import unittest
from pathlib import Path

from mcp_risk_scanner.checks import known_check_ids, run_checks, list_available_checks
from mcp_risk_scanner.collector import collect_input
from mcp_risk_scanner.rules import load_rules
from mcp_risk_scanner.plugins import load_plugin_checks


class PluginTests(unittest.TestCase):
    def test_load_plugin_checks_and_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plugin_file = root / "plugin_one.py"
            plugin_file.write_text(
                """
from mcp_risk_scanner.models import Finding

def check(scan_input):
    return [
        Finding(
            check_id="plugin_demo",
            title="Plugin demo",
            severity="low",
            category="plugin",
            message="plugin",
            evidence="plugin ran",
            remediation="none",
        )
    ]

CHECKS = [
    {
        "check_id": "plugin_demo",
        "default_severity": "low",
        "runner": check,
    }
]
""".strip()
                + "\n",
                encoding="utf-8",
            )

            plugin_checks = load_plugin_checks([str(plugin_file)])
            self.assertEqual(len(plugin_checks), 1)
            self.assertEqual(plugin_checks[0].check_id, "plugin_demo")

            target = root / "target"
            target.mkdir()
            (target / "server.json").write_text(
                json.dumps({"name": "x", "tools": []}), encoding="utf-8"
            )
            scan_input = collect_input(str(target))
            findings = run_checks(scan_input, extra_checks=plugin_checks)
            ids = {f.check_id for f in findings}
            self.assertIn("plugin_demo", ids)

    def test_rules_validation_accepts_plugin_check_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plugin_file = root / "plugin_two.py"
            plugin_file.write_text(
                """
from mcp_risk_scanner.models import Finding

def check(scan_input):
    return []

CHECKS = [
    {
        "check_id": "plugin_two_check",
        "default_severity": "medium",
        "runner": check,
    }
]
""".strip()
                + "\n",
                encoding="utf-8",
            )
            plugin_checks = load_plugin_checks([str(plugin_file)])

            rules_path = root / "rules.yml"
            rules_path.write_text(
                """
checks:
  plugin_two_check:
    enabled: false
""".strip()
                + "\n",
                encoding="utf-8",
            )

            rules, _ = load_rules(
                str(rules_path),
                extra_check_ids={c.check_id for c in plugin_checks},
            )
            checks = list_available_checks(rules, extra_checks=plugin_checks)
            row = [c for c in checks if c["check_id"] == "plugin_two_check"][0]
            self.assertEqual(row["enabled"], False)

    def test_known_check_ids_includes_plugins(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plugin_file = root / "plugin_three.py"
            plugin_file.write_text(
                """
def check(scan_input):
    return []

CHECKS = [
    {
        "check_id": "plugin_three_check",
        "default_severity": "low",
        "runner": check,
    }
]
""".strip()
                + "\n",
                encoding="utf-8",
            )
            plugin_checks = load_plugin_checks([str(plugin_file)])
            ids = known_check_ids(extra_checks=plugin_checks)
            self.assertIn("plugin_three_check", ids)

    def test_plugin_check_id_namespace_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plugin_file = root / "custom.py"
            plugin_file.write_text(
                """
def check(scan_input):
    return []

CHECKS = [
    {
        "check_id": "badname",
        "default_severity": "low",
        "runner": check,
    }
]
""".strip()
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_plugin_checks([str(plugin_file)])

    def test_plugin_exception_isolated_to_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plugin_file = root / "plugin_boom.py"
            plugin_file.write_text(
                """
def check(scan_input):
    raise RuntimeError("boom")

CHECKS = [
    {
        "check_id": "plugin_boom_check",
        "default_severity": "low",
        "runner": check,
    }
]
""".strip()
                + "\n",
                encoding="utf-8",
            )
            plugin_checks = load_plugin_checks([str(plugin_file)])

            target = root / "target"
            target.mkdir()
            (target / "server.json").write_text(
                json.dumps({"name": "x", "tools": []}), encoding="utf-8"
            )
            scan_input = collect_input(str(target))
            findings = run_checks(scan_input, extra_checks=plugin_checks)
            match = [f for f in findings if f.check_id == "plugin_boom_check"]
            self.assertEqual(len(match), 1)
            self.assertIn("raised an exception", match[0].message)

    def test_plugin_timeout_isolated_to_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plugin_file = root / "plugin_slow.py"
            plugin_file.write_text(
                """
import time

def check(scan_input):
    time.sleep(1.2)
    return []

CHECKS = [
    {
        "check_id": "plugin_slow_check",
        "default_severity": "low",
        "runner": check,
    }
]
""".strip()
                + "\n",
                encoding="utf-8",
            )
            plugin_checks = load_plugin_checks([str(plugin_file)])

            target = root / "target"
            target.mkdir()
            (target / "server.json").write_text(
                json.dumps({"name": "x", "tools": []}), encoding="utf-8"
            )
            scan_input = collect_input(str(target))
            start = time.time()
            findings = run_checks(scan_input, extra_checks=plugin_checks)
            elapsed = time.time() - start
            self.assertLess(elapsed, 2.5)
            match = [f for f in findings if f.check_id == "plugin_slow_check"]
            self.assertEqual(len(match), 1)
            self.assertIn("timed out", match[0].title.lower())


if __name__ == "__main__":
    unittest.main()
