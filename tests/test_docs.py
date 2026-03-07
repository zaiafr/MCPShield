import re
import unittest
from pathlib import Path

from mcp_risk_scanner.checks import list_available_checks


class DocsTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
