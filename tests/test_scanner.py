import json
import tempfile
import unittest
from pathlib import Path

from mcp_risk_scanner.checks import run_checks
from mcp_risk_scanner.collector import collect_input
from mcp_risk_scanner.scoring import calculate_score


class ScannerTests(unittest.TestCase):
    def test_collect_input_from_directory_requires_server_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            with self.assertRaises(ValueError):
                collect_input(str(d))

    def test_detects_auth_missing_when_no_auth_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "server.json").write_text(
                json.dumps({"name": "x", "tools": []}), encoding="utf-8"
            )
            scan_input = collect_input(str(d))
            findings = run_checks(scan_input)
            ids = {f.check_id for f in findings}
            self.assertIn("auth_missing", ids)

    def test_detects_cve_rule_for_server_git(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "server.json").write_text(
                json.dumps({"name": "x", "tools": []}), encoding="utf-8"
            )
            (d / "package.json").write_text(
                json.dumps(
                    {
                        "dependencies": {
                            "@modelcontextprotocol/server-git": "2025.9.1"
                        }
                    }
                ),
                encoding="utf-8",
            )
            scan_input = collect_input(str(d))
            findings = run_checks(scan_input)
            ids = {f.check_id for f in findings}
            self.assertIn("cve_@modelcontextprotocol/server-git", ids)

    def test_scoring_drops_with_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "server.json").write_text(
                json.dumps(
                    {
                        "name": "x",
                        "command": "bash",
                        "args": ["-lc", "node server.js"],
                        "tools": [{"name": "exec_shell", "description": "exec"}],
                    }
                ),
                encoding="utf-8",
            )
            scan_input = collect_input(str(d))
            findings = run_checks(scan_input)
            score, level = calculate_score(findings)
            self.assertLess(score, 100)
            self.assertIn(level, {"medium", "high", "critical", "low"})

    def test_detects_token_passthrough_hint(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "server.json").write_text(
                json.dumps(
                    {
                        "name": "x",
                        "tools": [],
                        "description": "Proxy that forwards bearer token to upstream APIs",
                    }
                ),
                encoding="utf-8",
            )
            scan_input = collect_input(str(d))
            findings = run_checks(scan_input)
            ids = {f.check_id for f in findings}
            self.assertIn("token_passthrough_hint", ids)

    def test_detects_stale_release_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "server.json").write_text(
                json.dumps(
                    {
                        "name": "x",
                        "tools": [],
                        "releaseDate": "2000-01-01T00:00:00Z",
                    }
                ),
                encoding="utf-8",
            )
            scan_input = collect_input(str(d))
            findings = run_checks(scan_input)
            ids = {f.check_id for f in findings}
            self.assertIn("stale_release", ids)

    def test_detects_ssrf_hint(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "server.json").write_text(
                json.dumps(
                    {
                        "name": "x",
                        "tools": [
                            {
                                "name": "fetch_url",
                                "description": "Fetch any URL provided by user input",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            scan_input = collect_input(str(d))
            findings = run_checks(scan_input)
            ids = {f.check_id for f in findings}
            self.assertIn("ssrf_hint", ids)

    def test_detects_missing_network_allowlist(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "server.json").write_text(
                json.dumps(
                    {
                        "name": "x",
                        "tools": [
                            {
                                "name": "http_proxy",
                                "description": "Perform network requests",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            scan_input = collect_input(str(d))
            findings = run_checks(scan_input)
            ids = {f.check_id for f in findings}
            self.assertIn("missing_network_allowlist", ids)

    def test_detects_missing_least_privilege_scope_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "server.json").write_text(
                json.dumps(
                    {
                        "name": "x",
                        "oauth": {"scopes": ["read:data"]},
                    }
                ),
                encoding="utf-8",
            )
            scan_input = collect_input(str(d))
            findings = run_checks(scan_input)
            ids = {f.check_id for f in findings}
            self.assertIn("least_privilege_missing", ids)

    def test_detects_missing_tenant_isolation_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "server.json").write_text(
                json.dumps(
                    {
                        "name": "x",
                        "oauth": {"scopes": ["read:data"], "leastPrivilege": True},
                    }
                ),
                encoding="utf-8",
            )
            scan_input = collect_input(str(d))
            findings = run_checks(scan_input)
            ids = {f.check_id for f in findings}
            self.assertIn("tenant_isolation_missing", ids)

    def test_detects_missing_audit_logging_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "server.json").write_text(
                json.dumps(
                    {
                        "name": "x",
                        "oauth": {
                            "scopes": ["read:data"],
                            "leastPrivilege": True,
                            "tenantIsolation": True,
                        },
                    }
                ),
                encoding="utf-8",
            )
            scan_input = collect_input(str(d))
            findings = run_checks(scan_input)
            ids = {f.check_id for f in findings}
            self.assertIn("audit_logging_missing", ids)

    def test_detects_destructive_tool_without_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "server.json").write_text(
                json.dumps(
                    {
                        "name": "x",
                        "tools": [
                            {
                                "name": "delete_file",
                                "description": "Delete files in workspace",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            scan_input = collect_input(str(d))
            findings = run_checks(scan_input)
            ids = {f.check_id for f in findings}
            self.assertIn("destructive_tool_confirmation_missing", ids)


if __name__ == "__main__":
    unittest.main()


class CliStemTests(unittest.TestCase):
    def test_safe_stem_strips_leading_dot_underscore_noise(self):
        from mcp_risk_scanner.cli import _safe_stem

        self.assertEqual(_safe_stem("./samples"), "samples")
