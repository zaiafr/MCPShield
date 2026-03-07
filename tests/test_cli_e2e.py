import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class CliE2ETests(unittest.TestCase):
    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return self._run_module("mcp_risk_scanner.cli", *args)

    def _run_public(self, *args: str) -> subprocess.CompletedProcess[str]:
        return self._run_module("mcpshield.cli", *args)

    def _run_module(self, module_name: str, *args: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.setdefault("PYTHONPATH", "src")
        return subprocess.run(
            [sys.executable, "-m", module_name, *args],
            cwd=Path(__file__).resolve().parents[1],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_version_command(self):
        proc = self._run_public("--version")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("mcpshield", proc.stdout.lower())

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

            proc_sarif = self._run("scan", str(target), "--sarif", "--out", str(out))
            self.assertEqual(proc_sarif.returncode, 0, msg=proc_sarif.stderr)
            self.assertGreaterEqual(len(list(out.glob("*.risk.sarif"))), 1)

            proc_batch = self._run(
                "scan-batch",
                str(fixtures),
                "--out",
                str(current),
                "--summary-only",
                "--sarif",
            )
            self.assertEqual(proc_batch.returncode, 0, msg=proc_batch.stderr)
            self.assertTrue((current / "summary.csv").exists())
            self.assertTrue((current / "summary.sarif").exists())

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

    def test_batch_baseline_gate_fails_on_new_high_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixtures = root / "fixtures"
            baseline = root / "baseline"
            current = root / "current"
            fixtures.mkdir()

            target = fixtures / "sample"
            target.mkdir()
            (target / "server.json").write_text(
                json.dumps(
                    {
                        "name": "sample",
                        "tools": [{"name": "fetch_url", "description": "Fetch any URL"}],
                    }
                ),
                encoding="utf-8",
            )

            baseline_proc = self._run(
                "scan-batch",
                str(fixtures),
                "--summary-only",
                "--sarif",
                "--out",
                str(baseline),
            )
            self.assertEqual(baseline_proc.returncode, 0, msg=baseline_proc.stderr)

            (target / "server.json").write_text(
                json.dumps(
                    {
                        "name": "sample",
                        "tools": [
                            {"name": "fetch_url", "description": "Fetch any URL"},
                            {"name": "delete_file", "description": "Delete files"},
                        ],
                    }
                ),
                encoding="utf-8",
            )

            current_proc = self._run(
                "scan-batch",
                str(fixtures),
                "--summary-only",
                "--sarif",
                "--baseline-sarif",
                str(baseline / "summary.sarif"),
                "--fail-on-new-high",
                "--out",
                str(current),
            )
            self.assertNotEqual(current_proc.returncode, 0)
            self.assertIn("new high-severity findings", current_proc.stderr)
            self.assertTrue((current / "regression-summary.json").exists())

    def test_scan_without_target_returns_nonzero(self):
        proc = self._run_public("scan")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("scan target is required", proc.stderr)

    def test_internal_module_entrypoint_remains_compatible(self):
        proc = self._run("--version")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("mcpshield", proc.stdout.lower())

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

    def test_plugin_manifest_and_lock_enforcement(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            target.mkdir()
            (target / "server.json").write_text(
                json.dumps({"name": "x", "tools": []}), encoding="utf-8"
            )
            plugin = root / "plugin_locked.py"
            plugin.write_text(
                """
def check(scan_input):
    return []

CHECKS = [
    {
        "check_id": "plugin_locked_check",
        "default_severity": "low",
        "runner": check,
    }
]
""".strip()
                + "\n",
                encoding="utf-8",
            )

            lock_path = root / "plugins.lock"
            manifest = self._run("plugin-manifest", str(plugin), "--out", str(lock_path))
            self.assertEqual(manifest.returncode, 0, msg=manifest.stderr)
            self.assertTrue(lock_path.exists())

            ok = self._run(
                "scan",
                str(target),
                "--plugins",
                str(plugin),
                "--allow-plugins",
                "--plugin-lock",
                str(lock_path),
                "--format",
                "json",
                "--out",
                str(root / "out"),
            )
            self.assertEqual(ok.returncode, 0, msg=ok.stderr)

            lock_data = json.loads(lock_path.read_text(encoding="utf-8"))
            key = next(iter(lock_data.keys()))
            lock_data[key] = "deadbeef"
            lock_path.write_text(json.dumps(lock_data, indent=2) + "\n", encoding="utf-8")

            bad = self._run(
                "scan",
                str(target),
                "--plugins",
                str(plugin),
                "--allow-plugins",
                "--plugin-lock",
                str(lock_path),
                "--format",
                "json",
                "--out",
                str(root / "out2"),
            )
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn("Plugin hash mismatch", bad.stderr)

    def test_example_plugin_cli_flow_with_origin_and_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            out = root / "out"
            lock_path = root / "plugins.lock"
            target.mkdir()
            (target / "server.json").write_text(
                json.dumps(
                    {
                        "name": "example-target",
                        "description": "TODO: tighten review before release",
                        "tools": [],
                    }
                ),
                encoding="utf-8",
            )
            for index in range(21):
                (target / f"module_{index}.py").write_text(
                    "print('example')\n", encoding="utf-8"
                )

            repo_root = Path(__file__).resolve().parents[1]
            plugin_dir = repo_root / "plugins" / "examples"

            manifest = self._run("plugin-manifest", str(plugin_dir), "--out", str(lock_path))
            self.assertEqual(manifest.returncode, 0, msg=manifest.stderr)

            proc = self._run(
                "scan",
                str(target),
                "--allow-plugins",
                "--plugins",
                str(plugin_dir),
                "--allow-plugin-origin",
                str(plugin_dir),
                "--plugin-lock",
                str(lock_path),
                "--format",
                "json",
                "--out",
                str(out),
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)

            report_path = next(out.glob("*.risk.json"))
            report = json.loads(report_path.read_text(encoding="utf-8"))
            finding_ids = {finding["check_id"] for finding in report["findings"]}
            self.assertIn("plugin_todo_tag", finding_ids)
            self.assertIn("plugin_file_count", finding_ids)

    def test_plugin_guide_includes_tested_example_command(self):
        repo_root = Path(__file__).resolve().parents[1]
        plugin_guide = (repo_root / "docs" / "plugins.md").read_text(encoding="utf-8")
        self.assertIn("plugin-manifest ./plugins/examples --out ./plugins/examples.lock", plugin_guide)
        self.assertIn("scan ./samples", plugin_guide)
        self.assertIn("--plugins ./plugins/examples", plugin_guide)
        self.assertIn("--allow-plugin-origin ./plugins/examples", plugin_guide)
        self.assertIn("--plugin-lock ./plugins/examples.lock", plugin_guide)


if __name__ == "__main__":
    unittest.main()
