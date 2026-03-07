import re
import unittest
from pathlib import Path

from mcp_risk_scanner.checks import list_available_checks


class DocsTests(unittest.TestCase):
    def test_readme_uses_product_name_heading(self):
        repo_root = Path(__file__).resolve().parents[1]
        readme = (repo_root / "README.md").read_text(encoding="utf-8")
        self.assertTrue(readme.startswith("# MCPShield\n"))
        self.assertIn("offline-first mcp policy and trust scanner", readme.lower())

    def test_check_catalog_lists_all_built_in_checks(self):
        repo_root = Path(__file__).resolve().parents[1]
        catalog_path = repo_root / "docs" / "checks.md"
        self.assertTrue(catalog_path.exists(), "docs/checks.md should exist")

        catalog = catalog_path.read_text(encoding="utf-8")
        documented_ids = set(re.findall(r"^## `([^`]+)`$", catalog, flags=re.MULTILINE))
        registry_ids = {item["check_id"] for item in list_available_checks()}

        self.assertEqual(documented_ids, registry_ids)
        self.assertIn("False-positive caveats", catalog)

    def test_readme_links_to_check_catalog(self):
        repo_root = Path(__file__).resolve().parents[1]
        readme = (repo_root / "README.md").read_text(encoding="utf-8")
        self.assertIn("docs/checks.md", readme)

    def test_positioning_doc_exists_and_mentions_competitors(self):
        repo_root = Path(__file__).resolve().parents[1]
        positioning_path = repo_root / "docs" / "positioning.md"
        self.assertTrue(positioning_path.exists(), "docs/positioning.md should exist")

        positioning = positioning_path.read_text(encoding="utf-8")
        self.assertIn("MCPSafe", positioning)
        self.assertIn("MCP_Scanner", positioning)
        self.assertIn("mcpserver-audit", positioning)
        self.assertIn("offline-first", positioning.lower())
        self.assertIn("docs/positioning.md", readme := (repo_root / "README.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
