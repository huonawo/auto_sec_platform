import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

from ai.ai_analysis import AIAnalyzer  # noqa: E402


class AIAnalysisTest(unittest.TestCase):
    def test_extracts_nuclei_findings_and_recommendations(self):
        scan_data = {
            "target": "http://example.com",
            "scan_type": "web",
            "result": {
                "findings": [
                    {
                        "template-id": "sql-injection-check",
                        "info": {
                            "name": "SQL Injection Exposure",
                            "severity": "high",
                            "type": "sqli",
                            "description": "Possible SQL injection.",
                        },
                        "matched-at": "http://example.com/search?q=1",
                    }
                ]
            },
        }

        analysis = AIAnalyzer().analyze(scan_data)

        self.assertEqual(analysis["summary"]["total"], 1)
        self.assertEqual(analysis["vulnerabilities"][0]["classification"], "injection")
        self.assertGreaterEqual(analysis["vulnerabilities"][0]["risk_score"], 7)
        self.assertTrue(analysis["recommendations"])
        self.assertIn("authorization_notice", analysis)

    def test_nmap_output_produces_observations_without_crashing(self):
        scan_data = {
            "target": "192.168.1.10",
            "scan_type": "cve",
            "result": {
                "nmap_output": (
                    "PORT   STATE SERVICE VERSION\n"
                    "22/tcp open  ssh     OpenSSH 8.9\n"
                    "80/tcp open  http    nginx\n"
                )
            },
        }

        analysis = AIAnalyzer().analyze(scan_data)

        self.assertEqual(analysis["summary"]["total"], 0)
        self.assertEqual(len(analysis["observations"]), 2)
        self.assertEqual(analysis["observations"][0]["port"], "22")
        self.assertEqual(analysis["observations"][0]["service"], "ssh")
        self.assertTrue(analysis["recommendations"])

    def test_empty_scan_returns_clear_summary(self):
        analysis = AIAnalyzer().analyze({"target": "http://empty.example", "result": {"findings": []}})

        self.assertEqual(analysis["summary"]["total"], 0)
        self.assertEqual(analysis["summary"]["critical"], 0)
        self.assertEqual(analysis["observations"], [])
        self.assertTrue(analysis["recommendations"])

    def test_scan_errors_are_preserved(self):
        analysis = AIAnalyzer().analyze(
            {
                "target": "http://example.com",
                "result": {
                    "httpx_error": "httpx not found",
                    "findings": [],
                },
            }
        )

        self.assertIn("httpx_error: httpx not found", analysis["errors"])


if __name__ == "__main__":
    unittest.main()
