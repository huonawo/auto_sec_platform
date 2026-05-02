import os
import shutil
import sys
import unittest
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
TEMP_ROOT = ROOT / "output" / "test_tmp"
TEMP_ROOT.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(BACKEND))

from modules.ctf.ctf_agent import AgentState, CTFAgent, extract_and_update  # noqa: E402
from modules.ctf.ctf_executor import CTFExecutor  # noqa: E402
from utils.results import list_result_records  # noqa: E402


class TestOutputDir:
    def __enter__(self):
        self.path = TEMP_ROOT / f"ctf_{uuid.uuid4().hex}"
        self.path.mkdir(parents=True)
        self.old = os.environ.get("AUTOSEC_OUTPUT_DIR")
        os.environ["AUTOSEC_OUTPUT_DIR"] = str(self.path)
        return str(self.path)

    def __exit__(self, exc_type, exc, tb):
        if self.old is None:
            os.environ.pop("AUTOSEC_OUTPUT_DIR", None)
        else:
            os.environ["AUTOSEC_OUTPUT_DIR"] = self.old
        shutil.rmtree(self.path, ignore_errors=True)


class CTFExecutorSafetyTest(unittest.TestCase):
    def test_blocks_dangerous_shell_commands(self):
        result = CTFExecutor().execute("rm -rf /tmp/autosec-danger")

        self.assertEqual(result["returncode"], -1)
        self.assertIn("blocked", result["stderr"].lower())

    def test_allows_safe_local_python_decoding(self):
        result = CTFExecutor().execute("python3 -c \"print('flag{safe_readonly}')\"")

        self.assertEqual(result["returncode"], 0)
        self.assertEqual(result["flag"], "flag{safe_readonly}")

    def test_allows_safe_quoted_filter_patterns(self):
        executor = CTFExecutor()

        self.assertIsNone(executor.validate_command("curl -s -k http://ctf.test | grep -oP '<!--.*?-->'"))
        self.assertIsNone(executor.validate_command("python3 -c \"print('a;b<c>')\""))

    def test_category_allowlists_gate_active_tools(self):
        self.assertIsNone(CTFExecutor(category="encoding").validate_command("python3 -c \"print('x')\""))
        self.assertIn("not allowed", CTFExecutor(category="encoding").validate_command("curl -s http://ctf.test"))
        self.assertIn(
            "active_probes",
            CTFExecutor(category="sqli", active_probes=False).validate_command("sqlmap -u http://ctf.test --batch"),
        )
        self.assertIsNone(
            CTFExecutor(category="sqli", active_probes=True).validate_command("sqlmap -u http://ctf.test --batch")
        )


class CTFAgentBehaviorTest(unittest.TestCase):
    def test_active_probe_commands_require_explicit_authorization(self):
        default_agent = CTFAgent("http://ctf.example", "web challenge", "web")
        authorized_agent = CTFAgent(
            "http://ctf.example",
            "web challenge",
            "web",
            options={"authorized_active_probes": True},
        )

        self.assertEqual(default_agent._active_probe_commands(), [])
        self.assertTrue(any("UNION" in cmd for cmd in authorized_agent._active_probe_commands()))

    def test_saves_ctf_result_record_after_run(self):
        with TestOutputDir():
            agent = CTFAgent("http://ctf.example", "web challenge", "web", max_rounds=1)
            agent.web_context = {"target": "http://ctf.example", "links": ["/admin"]}
            agent.history = [
                {
                    "round": 1,
                    "thought": "Check source",
                    "action": "curl",
                    "observation": "flag{saved_record}",
                    "commands": ["curl -s -k http://ctf.example"],
                    "flag": "flag{saved_record}",
                }
            ]

            saved = agent._save_result("flag_found", "flag{saved_record}")
            records = list_result_records()

            self.assertTrue(saved.endswith(".json"))
            self.assertEqual(records[0]["scan_type"], "ctf")
            self.assertEqual(records[0]["data"]["result"]["flag"], "flag{saved_record}")
            self.assertEqual(records[0]["data"]["result"]["web_context"]["links"], ["/admin"])

    def test_web_solver_emits_recon_and_classification_before_reasoning(self):
        class FlowAgent(CTFAgent):
            def _collect_initial_web_context(self):
                self.web_context = {"target": self.url, "url_params": {"id": ["1"]}}
                return self.web_context

            def _classify_web_context(self):
                self.classification = {
                    "category": "encoding",
                    "confidence": 0.8,
                    "key_signals": ["base64"],
                    "playbook": ["decode candidate strings"],
                }
                self.executor.category = "encoding"
                return self.classification

            def _call_pentestgpt(self):
                if self.classification["category"] != "encoding":
                    raise AssertionError("classification was not injected before reasoning")
                return {
                    "hypothesis": "decode",
                    "exact_commands": ["python3 -c \"print('flag{flow_ok}')\""],
                }

            def _call_shannon_review(self, commands, context=""):
                return commands

        with TestOutputDir():
            events = list(FlowAgent("http://ctf.example", "web challenge", "web", max_rounds=3).solve())

        self.assertEqual(events[0]["type"], "recon")
        self.assertEqual(events[0]["round"], 0)
        self.assertEqual(events[1]["type"], "classification")
        self.assertEqual(events[1]["round"], 1)
        self.assertEqual(events[2]["round"], 2)
        self.assertEqual(events[2]["status"], "flag_found")

    def test_extract_and_update_decodes_base64_flag(self):
        state = extract_and_update("page contains Q1RGe2Vhc3lfYmFzZTY0fQ==", AgentState())

        self.assertIn("Q1RGe2Vhc3lfYmFzZTY0fQ==", state.base64_candidates)
        self.assertTrue(any(item["decoded"] == "CTF{easy_base64}" for item in state.decoded_results))
        self.assertTrue(any(item["is_flag"] for item in state.decoded_results))

    def test_loop_stops_after_state_extracts_decoded_base64_flag(self):
        class Base64Agent(CTFAgent):
            def _collect_initial_web_context(self):
                self.web_context = {"target": self.url}
                return self.web_context

            def _classify_web_context(self):
                self.classification = {
                    "category": "encoding",
                    "confidence": 0.9,
                    "key_signals": ["base64"],
                    "playbook": ["decode base64"],
                }
                self.executor.category = "encoding"
                return self.classification

            def _call_pentestgpt(self):
                return {
                    "hypothesis": "collect encoded blob",
                    "exact_commands": ["python3 -c \"print('Q1RGe2Vhc3lfYmFzZTY0fQ==')\""],
                }

            def _call_shannon_review(self, commands, context=""):
                return commands

        with TestOutputDir():
            events = list(Base64Agent("http://ctf.example", "web challenge", "web", max_rounds=5).solve())

        flag_events = [event for event in events if event.get("status") == "flag_found"]
        self.assertEqual(len(flag_events), 1)
        self.assertEqual(flag_events[0]["flag"], "CTF{easy_base64}")
        self.assertEqual(flag_events[0]["round"], 2)


if __name__ == "__main__":
    unittest.main()
