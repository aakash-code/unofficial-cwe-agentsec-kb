import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "tools"))
import agentsec  # noqa: E402


class AgentSecTests(unittest.TestCase):
    def test_knowledge_base_validates(self):
        result = agentsec.validate_rules()
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(result["rule_count"], 20)
        self.assertEqual(result["cwe_data"]["version"], "4.20")
        self.assertEqual(result["cwe_data"]["counts"]["weaknesses"], 969)

    def test_full_cwe_catalog_is_searchable_and_retrievable(self):
        results = agentsec.search_cwe("CWE-918")
        self.assertEqual(results[0]["entry"]["id"], "CWE-918")
        entry = agentsec.get_cwe("CWE-918")
        self.assertIsNotNone(entry)
        assert entry is not None
        self.assertEqual(entry["type"], "weakness")
        self.assertTrue(entry["content"]["children"])

    def test_cwe_search_prefers_base_weakness_and_reports_mapping_usage(self):
        top = agentsec.search_cwe("sql injection")[0]["entry"]
        self.assertEqual(top["id"], "CWE-89")
        self.assertEqual(top["mapping_usage"], "Allowed")
        self.assertEqual(agentsec.cwe_mapping_usage()["CWE-699"], "Prohibited")

    def test_cwe_search_understands_common_shorthand(self):
        expected = {
            "IDOR": "CWE-639", "XSS": "CWE-79", "XXE": "CWE-611", "SSRF": "CWE-918", "CSRF": "CWE-352",
            "prompt injection": "CWE-1427", "race condition": "CWE-362", "sql injection": "CWE-89",
            "os command injection": "CWE-78", "open redirect": "CWE-601", "path traversal": "CWE-22",
        }
        for query, cwe_id in expected.items():
            with self.subTest(query=query):
                self.assertEqual(agentsec.search_cwe(query)[0]["entry"]["id"], cwe_id)

    def test_rules_must_cite_existing_allowed_cwes(self):
        problems = agentsec.cwe_mapping_problems(["CWE-79", "CWE-20", "CWE-699", "CWE-999999"])
        self.assertEqual(len(problems), 3)
        self.assertIn("Discouraged", problems[0])
        self.assertIn("Prohibited", problems[1])
        self.assertIn("not in the CWE", problems[2])

    def test_every_readable_cwe_entry_fits_a_tool_result(self):
        # Claude Code rejects MCP results above ~25k tokens; the raw CWE-79 tree (62k chars) failed.
        catalog = agentsec.load_cwe_catalog()
        largest = max(
            len(json.dumps(agentsec.readable_cwe(entry), separators=(",", ":")))
            for collection in ("weaknesses", "categories", "views")
            for entry in catalog[collection]
        )
        self.assertLess(largest, 45_000)

    def test_readable_cwe_sections_filter(self):
        entry = agentsec.readable_cwe(agentsec.get_cwe("CWE-79"), ["Mapping_Notes"])
        self.assertEqual(list(entry["sections"]), ["Mapping_Notes"])
        self.assertIn("Content_History", entry["available_sections"])
        self.assertNotIn("Content_History", agentsec.readable_cwe(agentsec.get_cwe("CWE-79"))["sections"])

    def test_search_returns_command_rule(self):
        results = agentsec.search_rules("untrusted command execution")
        self.assertTrue(results)
        self.assertEqual(results[0]["rule"]["id"], "ASKB-INJECT-002")

    def test_reviewer_reports_fixture_patterns(self):
        fixture = PROJECT_ROOT / "tests" / "fixtures" / "vulnerable_app"
        result = agentsec.review_path(str(fixture))
        found_rules = {finding["rule_id"] for finding in result["findings"]}
        self.assertTrue({"ASKB-INJECT-002", "ASKB-CRYPTO-001", "ASKB-XSS-001", "ASKB-IAC-001"}.issubset(found_rules))
        self.assertTrue(all(finding["disposition"] == "needs-human-review" for finding in result["findings"]))

    def test_reviewer_finds_each_planted_pattern_exactly(self):
        fixture = PROJECT_ROOT / "tests" / "fixtures" / "vulnerable_app"
        found = {(f["evidence"]["path"], f["evidence"]["line"], f["rule_id"]) for f in agentsec.review_path(str(fixture))["findings"]}
        expected = {
            ("app.py", 6, "ASKB-INJECT-002"), ("app.py", 10, "ASKB-CRYPTO-001"), ("app.py", 13, "ASKB-SECRETS-001"),
            ("network.tf", 2, "ASKB-IAC-001"), ("page.js", 2, "ASKB-XSS-001"),
            ("service.py", 5, "ASKB-SESSION-001"), ("service.py", 9, "ASKB-INJECT-001"), ("service.py", 10, "ASKB-INJECT-001"),
            ("service.py", 14, "ASKB-AUTH-003"), ("service.py", 18, "ASKB-DESER-001"), ("service.py", 21, "ASKB-CSRF-001"),
            ("service.py", 23, "ASKB-REDIRECT-001"),
            ("routes.js", 1, "ASKB-INJECT-001"), ("routes.js", 2, "ASKB-REDIRECT-001"), ("routes.js", 3, "ASKB-SESSION-001"),
        }
        self.assertEqual(found, expected)

    def test_reviewer_has_no_false_positives_on_safe_equivalents(self):
        result = agentsec.review_path(str(PROJECT_ROOT / "tests" / "fixtures" / "safe_app"))
        self.assertEqual(result["files_scanned"], 2)
        self.assertEqual(result["findings"], [])

    def test_reviewer_skips_dependency_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            vendored = Path(directory, "node_modules", "pkg")
            vendored.mkdir(parents=True)
            (vendored / "index.js").write_text("child_process.exec(userInput)\n")
            Path(directory, "main.py").write_text("print('ok')\n")
            result = agentsec.review_path(directory)
        self.assertEqual(result["files_scanned"], 1)
        self.assertEqual(result["findings"], [])

    def test_mcp_server_survives_malformed_messages(self):
        lines = [
            "not json",
            "[1, 2]",
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": "oops"}),
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            "",
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "agentsec_get_cwe", "arguments": {"cwe_id": "nope"}}}),
            json.dumps({"jsonrpc": "2.0", "id": 3, "method": "ping"}),
        ]
        completed = subprocess.run(
            [sys.executable, str(PROJECT_ROOT / "tools" / "agentsec.py"), "serve"],
            input="\n".join(lines) + "\n", capture_output=True, text=True, timeout=60,
        )
        replies = [json.loads(line) for line in completed.stdout.splitlines()]
        self.assertEqual([reply.get("error", {}).get("code") for reply in replies[:3]], [-32700, -32600, -32602])
        self.assertEqual(replies[0]["id"], None)
        self.assertTrue(replies[3]["result"]["isError"])
        self.assertEqual(replies[4], {"jsonrpc": "2.0", "id": 3, "result": {}})
        self.assertEqual(len(replies), 5)

    def test_version_is_consistent_everywhere(self):
        import re
        sources = {
            "pyproject.toml": r'^version = "([^"]+)"',
            "CITATION.cff": r'^version: "([^"]+)"',
            "README.md": r"--ref v([0-9.]+)",
            "tools/agentsec.py": r'^VERSION = "([^"]+)"',
            "build_backend.py": r'^VERSION = "([^"]+)"',
        }
        versions = {path: re.search(pattern, (PROJECT_ROOT / path).read_text(encoding="utf-8"), re.M).group(1) for path, pattern in sources.items()}
        for path in ("plugin.json", ".claude-plugin/plugin.json", ".codex-plugin/plugin.json", "gemini-extension.json"):
            versions[path] = json.loads((PROJECT_ROOT / path).read_text(encoding="utf-8"))["version"]
        marketplace = json.loads((PROJECT_ROOT / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8"))
        versions["marketplace"] = marketplace["version"]
        versions["marketplace plugin"] = marketplace["plugins"][0]["version"]
        self.assertEqual(len(set(versions.values())), 1, versions)

    def test_wheel_installs_everything_under_one_package(self):
        import zipfile
        sys.path.insert(0, str(PROJECT_ROOT))
        import build_backend
        with tempfile.TemporaryDirectory() as directory:
            names = zipfile.ZipFile(Path(directory, build_backend.build_wheel(directory))).namelist()
        top_level = {name.split("/")[0] for name in names}
        self.assertEqual(top_level, {"agentsec_kb", build_backend.DIST_INFO})
        self.assertIn("agentsec_kb/tools/agentsec.py", names)
        self.assertIn("agentsec_kb/data/cwe/4.20/catalog.json", names)
        self.assertIn("agentsec_kb/vendor/cwe/4.20/cwec_v4.20.xml.zip", names)

    def test_mcp_initialize_and_list_tools(self):
        process = subprocess.Popen(
            [sys.executable, str(PROJECT_ROOT / "tools" / "agentsec.py"), "serve"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            requests = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "agentsec_cwe_status", "arguments": {}}},
            ]
            assert process.stdin is not None
            assert process.stdout is not None
            for request in requests:
                process.stdin.write(json.dumps(request) + "\n")
                process.stdin.flush()
            initialize = json.loads(process.stdout.readline())
            tools = json.loads(process.stdout.readline())
            cwe_status = json.loads(process.stdout.readline())
            self.assertEqual(initialize["result"]["serverInfo"]["name"], "agentsec-kb")
            self.assertEqual(len(tools["result"]["tools"]), 7)
            self.assertEqual(json.loads(cwe_status["result"]["content"][0]["text"])["version"], "4.20")
        finally:
            process.terminate()
            process.wait(timeout=5)
            if process.stdin is not None:
                process.stdin.close()
            if process.stdout is not None:
                process.stdout.close()


if __name__ == "__main__":
    unittest.main()
