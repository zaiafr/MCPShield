import json
import tempfile
import unittest
from pathlib import Path

from mcp_risk_scanner import cli


class BatchCliTests(unittest.TestCase):
    def test_run_scan_batch_writes_reports_and_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixtures = root / "fixtures"
            out = root / "out"
            fixtures.mkdir()

            alpha = fixtures / "alpha"
            alpha.mkdir()
            (alpha / "server.json").write_text(
                json.dumps(
                    {
                        "name": "alpha",
                        "tools": [],
                        "oauth": {
                            "scopes": ["read:data"],
                            "leastPrivilege": True,
                            "tenantIsolation": True,
                            "auditLog": True,
                        },
                        "securityPolicy": "https://example.invalid/security",
                    }
                ),
                encoding="utf-8",
            )
            (alpha / "SECURITY.md").write_text("ok", encoding="utf-8")
            (alpha / "CHANGELOG.md").write_text("ok", encoding="utf-8")

            beta = fixtures / "beta"
            beta.mkdir()
            (beta / "server.json").write_text(
                json.dumps(
                    {
                        "name": "beta",
                        "tools": [
                            {"name": "fetch_url", "description": "Fetch any URL"},
                            {"name": "delete_file", "description": "Delete files"},
                        ],
                        "oauth": {"scopes": ["admin"]},
                    }
                ),
                encoding="utf-8",
            )

            gamma = fixtures / "gamma"
            gamma.mkdir()
            (gamma / "server.json").write_text(
                json.dumps(
                    {
                        "name": "gamma",
                        "tools": [],
                        "releaseDate": "2000-01-01T00:00:00Z",
                    }
                ),
                encoding="utf-8",
            )

            cli._run_scan_batch(str(fixtures), "both", str(out), quiet=True)

            self.assertTrue((out / "alpha.risk.json").exists())
            self.assertTrue((out / "beta.risk.json").exists())
            self.assertTrue((out / "gamma.risk.json").exists())
            self.assertTrue((out / "summary.json").exists())
            self.assertTrue((out / "summary.md").exists())

            summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["total_scanned"], 3)
            self.assertIn("top_checks", summary)
            self.assertGreater(len(summary["top_checks"]), 0)

    def test_run_scan_batch_summary_only_writes_only_summary_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixtures = root / "fixtures"
            out = root / "out"
            fixtures.mkdir()

            sample = fixtures / "sample"
            sample.mkdir()
            (sample / "server.json").write_text(
                json.dumps({"name": "sample", "tools": []}),
                encoding="utf-8",
            )

            cli._run_scan_batch(
                str(fixtures), "both", str(out), summary_only=True, quiet=True
            )

            self.assertTrue((out / "summary.json").exists())
            self.assertTrue((out / "summary.md").exists())
            self.assertTrue((out / "summary.csv").exists())
            self.assertFalse((out / "sample.risk.json").exists())
            self.assertFalse((out / "sample.risk.md").exists())

    def test_summary_csv_contains_header_and_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixtures = root / "fixtures"
            out = root / "out"
            fixtures.mkdir()

            alpha = fixtures / "alpha"
            alpha.mkdir()
            (alpha / "server.json").write_text(
                json.dumps({"name": "alpha", "tools": []}),
                encoding="utf-8",
            )

            beta = fixtures / "beta"
            beta.mkdir()
            (beta / "server.json").write_text(
                json.dumps(
                    {
                        "name": "beta",
                        "tools": [{"name": "fetch_url", "description": "Fetch any URL"}],
                    }
                ),
                encoding="utf-8",
            )

            cli._run_scan_batch(str(fixtures), "json", str(out), quiet=True)
            csv_text = (out / "summary.csv").read_text(encoding="utf-8")
            self.assertIn("target,score,risk_level,findings_count", csv_text)
            self.assertIn("alpha", csv_text)
            self.assertIn("beta", csv_text)

    def test_run_scan_batch_fail_on_critical_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixtures = root / "fixtures"
            out = root / "out"
            fixtures.mkdir()

            critical_target = fixtures / "critical"
            critical_target.mkdir()
            (critical_target / "server.json").write_text(
                json.dumps(
                    {
                        "name": "critical",
                        "tools": [
                            {"name": "delete_file", "description": "Delete files"},
                            {"name": "fetch_url", "description": "Fetch any URL"},
                        ],
                        "oauth": {"scopes": ["admin"]},
                    }
                ),
                encoding="utf-8",
            )
            (critical_target / "package.json").write_text(
                json.dumps(
                    {"dependencies": {"@modelcontextprotocol/server-git": "2025.9.1"}}
                ),
                encoding="utf-8",
            )

            with self.assertRaises(RuntimeError):
                cli._run_scan_batch(
                    str(fixtures), "json", str(out), fail_on_critical=True, quiet=True
                )

    def test_run_scan_batch_min_score_raises_when_any_target_below_threshold(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixtures = root / "fixtures"
            out = root / "out"
            fixtures.mkdir()

            low = fixtures / "low"
            low.mkdir()
            (low / "server.json").write_text(
                json.dumps({"name": "low", "tools": [{"name": "delete_file", "description": "Delete files"}]}),
                encoding="utf-8",
            )

            high = fixtures / "high"
            high.mkdir()
            (high / "server.json").write_text(
                json.dumps({"name": "high", "tools": []}),
                encoding="utf-8",
            )

            with self.assertRaises(RuntimeError):
                cli._run_scan_batch(str(fixtures), "json", str(out), min_score=80, quiet=True)

    def test_compare_summaries_writes_delta_json_and_md(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_csv = root / "old.csv"
            new_csv = root / "new.csv"
            out = root / "out"
            out.mkdir()

            old_csv.write_text(
                "\n".join(
                    [
                        "target,score,risk_level,findings_count",
                        "alpha,60,high,5",
                        "beta,90,low,1",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            new_csv.write_text(
                "\n".join(
                    [
                        "target,score,risk_level,findings_count",
                        "alpha,80,medium,2",
                        "gamma,50,high,4",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            cli._run_compare_summaries(str(old_csv), str(new_csv), str(out), quiet=True)

            self.assertTrue((out / "delta.json").exists())
            self.assertTrue((out / "delta.md").exists())

            delta = json.loads((out / "delta.json").read_text(encoding="utf-8"))
            self.assertEqual(delta["targets_compared"], 3)
            self.assertEqual(delta["regressions_count"], 1)
            self.assertEqual(delta["improvements_count"], 1)
            self.assertEqual(delta["new_targets_count"], 1)
            self.assertEqual(delta["removed_targets_count"], 1)

            md = (out / "delta.md").read_text(encoding="utf-8")
            self.assertIn("alpha", md)
            self.assertIn("gamma", md)
            self.assertIn("beta", md)

    def test_scan_target_returns_findings_in_deterministic_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "server.json").write_text(
                json.dumps(
                    {
                        "name": "x",
                        "command": "bash",
                        "args": ["-lc", "node server.js"],
                        "tools": [
                            {"name": "delete_file", "description": "Delete files"},
                            {"name": "fetch_url", "description": "Fetch any URL"},
                        ],
                        "oauth": {"scopes": ["admin"]},
                    }
                ),
                encoding="utf-8",
            )

            result = cli._scan_target(str(d))
            pairs = [(f.severity, f.check_id) for f in result.findings]
            ranks = {"critical": 4, "high": 3, "medium": 2, "low": 1}

            for first, second in zip(pairs, pairs[1:]):
                first_rank = ranks[first[0]]
                second_rank = ranks[second[0]]
                self.assertTrue(
                    first_rank > second_rank
                    or (first_rank == second_rank and first[1] <= second[1])
                )


if __name__ == "__main__":
    unittest.main()
