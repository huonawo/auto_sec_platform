import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

from utils.parser import validate_target  # noqa: E402


class TargetValidationTest(unittest.TestCase):
    def test_accepts_url_and_ip_cidr(self):
        self.assertEqual(validate_target("https://example.com"), "https://example.com")
        self.assertEqual(validate_target("192.168.1.0/24"), "192.168.1.0/24")

    def test_rejects_empty_or_invalid_ip(self):
        with self.assertRaises(ValueError):
            validate_target("")
        with self.assertRaises(ValueError):
            validate_target("999.168.1.1")


if __name__ == "__main__":
    unittest.main()
