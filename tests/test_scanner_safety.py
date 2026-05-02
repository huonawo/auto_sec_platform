import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

from modules.ad.ad_scan import ADScanner  # noqa: E402
from modules.persistence.persistence import PersistenceScanner  # noqa: E402
from modules.webscan.webscan import WebScanner  # noqa: E402


class ScannerSafetyTest(unittest.TestCase):
    def test_persistence_scan_does_not_execute_psexec_by_default(self):
        result = PersistenceScanner("192.168.1.10").run({})

        self.assertEqual(result["target"], "192.168.1.10")
        self.assertIn("warnings", result)
        self.assertTrue(any("does not execute psexec" in item.lower() for item in result["warnings"]))
        self.assertNotIn("psexec_output", result)
        self.assertEqual(result["checks"][0]["status"], "not_executed")

    def test_ad_secretsdump_requires_explicit_credential_dump_flag(self):
        calls = []

        def fake_run(command, **kwargs):
            calls.append(command)
            return SimpleNamespace(returncode=0, stdout="ok", stderr="")

        with patch("modules.ad.ad_scan.subprocess.run", side_effect=fake_run):
            result = ADScanner("example.local").run(
                {
                    "authorized": True,
                    "enable_secretsdump": True,
                    "allow_credential_dump": False,
                }
            )

        self.assertTrue(any(command[0] == "bloodhound-python" for command in calls))
        self.assertFalse(any(command[0] == "secretsdump.py" for command in calls))
        self.assertTrue(any("credential dump" in item.lower() for item in result["warnings"]))

    def test_web_scan_records_missing_tools_as_errors(self):
        with patch(
            "modules.webscan.webscan.subprocess.run",
            side_effect=[FileNotFoundError("httpx missing"), FileNotFoundError("nuclei missing")],
        ):
            result = WebScanner("http://example.com").run({})

        self.assertIn("httpx_error", result)
        self.assertIn("nuclei_error", result)
        self.assertIn("httpx missing", result["httpx_error"])
        self.assertIn("nuclei missing", result["nuclei_error"])

    def test_web_scan_preserves_valid_json_lines_when_later_lines_are_malformed(self):
        httpx_output = SimpleNamespace(
            returncode=0,
            stdout=(
                '{"url":"http://example.com","status_code":200,'
                '"title":"Example","webserver":"nginx"}\n'
                '{not-json}\n'
            ),
            stderr="",
        )
        nuclei_output = SimpleNamespace(returncode=0, stdout="{not-json}\n", stderr="")

        with patch(
            "modules.webscan.webscan.subprocess.run",
            side_effect=[httpx_output, nuclei_output],
        ):
            result = WebScanner("http://example.com").run({})

        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["web_context"]["status_code"], 200)
        self.assertEqual(result["web_context"]["title"], "Example")
        self.assertTrue(any("invalid JSON" in item for item in result["warnings"]))


if __name__ == "__main__":
    unittest.main()
