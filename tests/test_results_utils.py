import json
import os
import shutil
import sys
import time
import unittest
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
TEMP_ROOT = ROOT / "output" / "test_tmp"
TEMP_ROOT.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(BACKEND))

from utils.results import (  # noqa: E402
    list_result_records,
    read_result_file,
    resolve_result_path,
    save_result_record,
)


class TestOutputDir:
    def __enter__(self):
        self.path = TEMP_ROOT / f"case_{uuid.uuid4().hex}"
        self.path.mkdir(parents=True)
        return str(self.path)

    def __exit__(self, exc_type, exc, tb):
        shutil.rmtree(self.path, ignore_errors=True)


class ResultUtilsTest(unittest.TestCase):
    def test_lists_latest_result_first(self):
        with TestOutputDir() as tmp:
            os.environ["AUTOSEC_OUTPUT_DIR"] = tmp
            old_path = save_result_record(
                "web",
                target="http://old.example",
                result={"findings": []},
                task_id="old-task",
            )
            time.sleep(0.02)
            new_path = save_result_record(
                "web",
                target="http://new.example",
                result={"findings": []},
                task_id="new-task",
            )

            records = list_result_records()

            self.assertEqual(records[0]["file"], os.path.basename(new_path))
            self.assertEqual(records[1]["file"], os.path.basename(old_path))

    def test_resolve_result_path_blocks_traversal(self):
        with TestOutputDir() as tmp:
            os.environ["AUTOSEC_OUTPUT_DIR"] = tmp

            with self.assertRaises(ValueError):
                resolve_result_path("../secret.json")

    def test_read_result_file_returns_payload(self):
        with TestOutputDir() as tmp:
            os.environ["AUTOSEC_OUTPUT_DIR"] = tmp
            path = save_result_record(
                "cve",
                target="192.168.1.10",
                result={"nmap_output": "PORT STATE SERVICE\n22/tcp open ssh"},
            )

            payload = read_result_file(os.path.basename(path))

            self.assertEqual(payload["target"], "192.168.1.10")
            self.assertEqual(payload["scan_type"], "cve")
            self.assertEqual(payload["status"], "completed")
            self.assertEqual(payload["result"]["nmap_output"], "PORT STATE SERVICE\n22/tcp open ssh")

    def test_corrupt_result_file_is_reported_without_crashing(self):
        with TestOutputDir() as tmp:
            os.environ["AUTOSEC_OUTPUT_DIR"] = tmp
            bad = Path(tmp) / "bad.json"
            bad.write_text("{not-json", encoding="utf-8")

            records = list_result_records()

            self.assertEqual(records[0]["file"], "bad.json")
            self.assertIn("error", records[0])


if __name__ == "__main__":
    unittest.main()
