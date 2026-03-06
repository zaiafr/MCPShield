import unittest

from mcp_risk_scanner.collector import collect_input


class CollectorOfflineTests(unittest.TestCase):
    def test_collect_url_uses_injected_fetcher(self):
        calls = []

        def fake_fetch(url: str, timeout_seconds: int) -> dict:
            calls.append((url, timeout_seconds))
            return {"name": "url-server", "tools": []}

        scan_input = collect_input(
            "https://example.invalid/server.json",
            timeout_seconds=7,
            fetch_json=fake_fetch,
        )

        self.assertEqual(scan_input.source_type, "url")
        self.assertEqual(scan_input.server_json["name"], "url-server")
        self.assertEqual(calls, [("https://example.invalid/server.json", 7)])

    def test_collect_npm_uses_injected_fetcher_and_extracts_server(self):
        calls = []

        def fake_fetch(url: str, timeout_seconds: int) -> dict:
            calls.append((url, timeout_seconds))
            return {
                "dist-tags": {"latest": "1.2.3"},
                "versions": {
                    "1.2.3": {
                        "name": "@scope/pkg",
                        "version": "1.2.3",
                        "mcp": {
                            "server": {
                                "name": "pkg-server",
                                "tools": [{"name": "read_data", "description": "Read data"}],
                            }
                        },
                    }
                },
            }

        scan_input = collect_input("@scope/pkg", timeout_seconds=9, fetch_json=fake_fetch)

        self.assertEqual(scan_input.source_type, "npm")
        self.assertEqual(scan_input.server_json["name"], "pkg-server")
        self.assertEqual(scan_input.raw_sources["npm_latest"], "1.2.3")
        self.assertEqual(
            calls,
            [("https://registry.npmjs.org/@scope/pkg", 9)],
        )


if __name__ == "__main__":
    unittest.main()
