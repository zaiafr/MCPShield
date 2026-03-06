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

            cli._run_scan_batch(str(fixtures), "both", str(out))

            self.assertTrue((out / "alpha.risk.json").exists())
            self.assertTrue((out / "beta.risk.json").exists())
            self.assertTrue((out / "gamma.risk.json").exists())
            self.assertTrue((out / "summary.json").exists())
            self.assertTrue((out / "summary.md").exists())

            summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["total_scanned"], 3)
            self.assertIn("top_checks", summary)
            self.assertGreater(len(summary["top_checks"]), 0)

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
