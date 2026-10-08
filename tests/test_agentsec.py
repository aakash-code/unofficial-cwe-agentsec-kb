import json
import subprocess
import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "tools"))
import agentsec  # noqa: E402


class AgentSecTests(unittest.TestCase):
    def test_knowledge_base_validates(self):
        result = agentsec.validate_rules()
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(result["rule_count"], 12)
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
            self.assertEqual(cwe_status["result"]["structuredContent"]["version"], "4.20")
        finally:
            process.terminate()
            process.wait(timeout=5)
            if process.stdin is not None:
                process.stdin.close()
            if process.stdout is not None:
                process.stdout.close()


if __name__ == "__main__":
    unittest.main()
