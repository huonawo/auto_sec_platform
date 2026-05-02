import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

from utils.safety import normalize_scan_options  # noqa: E402


class SafetyOptionsTest(unittest.TestCase):
    def test_scan_options_default_to_safe_values(self):
        options = normalize_scan_options(None)

        self.assertFalse(options["authorized"])
        self.assertTrue(options["safe_mode"])
        self.assertFalse(options["allow_credential_dump"])

    def test_scan_options_preserve_explicit_values(self):
        options = normalize_scan_options(
            {
                "authorized": True,
                "safe_mode": False,
                "allow_credential_dump": True,
                "custom": "value",
            }
        )

        self.assertTrue(options["authorized"])
        self.assertFalse(options["safe_mode"])
        self.assertTrue(options["allow_credential_dump"])
        self.assertEqual(options["custom"], "value")


if __name__ == "__main__":
    unittest.main()
