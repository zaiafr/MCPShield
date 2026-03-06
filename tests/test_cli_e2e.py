import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class CliE2ETests(unittest.TestCase):
    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.setdefault("PYTHONPATH", "src")
        return subprocess.run(
            [sys.executable, "-m", "mcp_risk_scanner.cli", *args],
            cwd=Path(__file__).resolve().parents[1],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_version_command(self):
        proc = self._run("--version")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("mcp-risk-scan", proc.stdout)

    def test_scan_and_batch_and_compare_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "single"
            out = root / "out"
            fixtures = root / "fixtures"
            baseline = root / "baseline"
            current = root / "current"
            target.mkdir()
            fixtures.mkdir()
            baseline.mkdir()
            current.mkdir()

            (target / "server.json").write_text(
                json.dumps({"name": "single", "tools": []}),
                encoding="utf-8",
            )

            a = fixtures / "a"
            a.mkdir()
            (a / "server.json").write_text(json.dumps({"name": "a", "tools": []}), encoding="utf-8")

            b = fixtures / "b"
            b.mkdir()
            (b / "server.json").write_text(
                json.dumps({"name": "b", "tools": [{"name": "fetch_url", "description": "Fetch any URL"}]}),
                encoding="utf-8",
            )

            proc_scan = self._run("scan", str(target), "--format", "both", "--out", str(out))
            self.assertEqual(proc_scan.returncode, 0, msg=proc_scan.stderr)
            self.assertGreaterEqual(len(list(out.glob("*.risk.json"))), 1)
            self.assertGreaterEqual(len(list(out.glob("*.risk.md"))), 1)

            proc_batch = self._run(
                "scan-batch",
                str(fixtures),
                "--out",
                str(current),
                "--summary-only",
            )
            self.assertEqual(proc_batch.returncode, 0, msg=proc_batch.stderr)
            self.assertTrue((current / "summary.csv").exists())

            (baseline / "summary.csv").write_text(
                "target,score,risk_level,findings_count\n"
                "a,90,low,1\n"
                "b,90,low,1\n",
                encoding="utf-8",
            )

            proc_compare = self._run(
                "compare-summaries",
                str(baseline / "summary.csv"),
                str(current / "summary.csv"),
                "--out",
                str(root / "delta"),
            )
            self.assertEqual(proc_compare.returncode, 0, msg=proc_compare.stderr)
            self.assertTrue((root / "delta" / "delta.json").exists())
            self.assertTrue((root / "delta" / "delta.md").exists())

    def test_scan_without_target_returns_nonzero(self):
        proc = self._run("scan")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("scan target is required", proc.stderr)

    def test_plugins_require_explicit_allow_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            target.mkdir()
            (target / "server.json").write_text(
                json.dumps({"name": "x", "tools": []}), encoding="utf-8"
            )
            plugin = root / "plugin_ok.py"
            plugin.write_text(
                """
def check(scan_input):
    return []

CHECKS = [
    {
        "check_id": "plugin_ok_check",
        "default_severity": "low",
        "runner": check,
    }
]
""".strip()
                + "\n",
                encoding="utf-8",
            )

            denied = self._run("scan", str(target), "--plugins", str(plugin))
            self.assertNotEqual(denied.returncode, 0)
            self.assertIn("Refusing to load plugins without --allow-plugins", denied.stderr)

            allowed = self._run(
                "scan",
                str(target),
                "--plugins",
                str(plugin),
                "--allow-plugins",
                "--format",
                "json",
                "--out",
                str(root / "out"),
            )
            self.assertEqual(allowed.returncode, 0, msg=allowed.stderr)


if __name__ == "__main__":
    unittest.main()
