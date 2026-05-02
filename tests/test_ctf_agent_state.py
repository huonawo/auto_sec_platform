import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

from modules.ctf.ctf_agent import AgentState, extract_and_update, CTFAgent  # noqa: E402


class ExtractAndUpdateTest(unittest.TestCase):
    """Test extract_and_update parses command output into AgentState."""

    def test_base64_candidate_extracted_and_decoded(self):
        # Q1RGe2Vhc3lfYmFzZTY0fQ== decodes to CTF{easy_base64}
        output = "Here is the secret: Q1RGe2Vhc3lfYmFzZTY0fQ=="
        state = extract_and_update(output, AgentState())

        self.assertEqual(len(state.base64_candidates), 1)
        self.assertEqual(state.base64_candidates[0], "Q1RGe2Vhc3lfYmFzZTY0fQ")
        self.assertEqual(len(state.decoded_results), 1)
        self.assertIn("CTF{easy_base64}", state.decoded_results[0]["decoded"])
        self.assertTrue(state.decoded_results[0]["is_flag"])

    def test_non_flag_base64_not_marked(self):
        output = "token: aGVsbG8gd29ybGQ="  # "hello world"
        state = extract_and_update(output, AgentState())

        self.assertEqual(len(state.base64_candidates), 1)
        self.assertFalse(state.decoded_results[0]["is_flag"])

    def test_js_variables_extracted(self):
        output = 'const correctPassword = "s3cret"; let token = "abc123";'
        state = extract_and_update(output, AgentState())

        self.assertEqual(state.js_variables["correctPassword"], "s3cret")
        self.assertEqual(state.js_variables["token"], "abc123")

    def test_error_patterns_extracted(self):
        output = "Warning: mysql_error in query\nSyntaxError: unexpected token"
        state = extract_and_update(output, AgentState())

        self.assertIn("Warning:", state.error_patterns)
        self.assertIn("SyntaxError", state.error_patterns)
        self.assertIn("mysql_error", state.error_patterns)

    def test_cookies_extracted(self):
        output = "HTTP/1.1 200 OK\nSet-Cookie: session=abc123def; Path=/"
        state = extract_and_update(output, AgentState())

        self.assertEqual(state.cookies["session"], "abc123def")

    def test_empty_output_no_change(self):
        state = AgentState()
        original = AgentState()
        extract_and_update("", state)

        self.assertEqual(state.base64_candidates, original.base64_candidates)
        self.assertEqual(state.decoded_results, original.decoded_results)

    def test_dedup_base64_candidates(self):
        output = "Q1RGe2Vhc3lfYmFzZTY0fQ== and again Q1RGe2Vhc3lfYmFzZTY0fQ=="
        state = extract_and_update(output, AgentState())

        # Same candidate should not be added twice
        self.assertEqual(len(state.base64_candidates), 1)

    def test_state_is_additive(self):
        state = AgentState()
        extract_and_update("Q1RGe2Vhc3lfYmFzZTY0fQ==", state)
        extract_and_update("aGVsbG8gd29ybGQ=", state)

        self.assertEqual(len(state.base64_candidates), 2)
        self.assertEqual(len(state.decoded_results), 2)


class CTFAgentSolveFlagDetectionTest(unittest.TestCase):
    """Test that the solve loop terminates early when a flag is found in decoded base64."""

    @patch("modules.ctf.ctf_agent.httpx_client")
    def test_solve_stops_after_round_1_flag_in_output(self, mock_httpx):
        """Simulate Round 1 output containing a base64-encoded flag.

        The executor returns output with Q1RGe2Vhc3lfYmFzZTY0fQ==
        which decodes to CTF{easy_base64}. The agent should detect
        the flag via extract_and_update and terminate after Round 1.
        """
        # Mock PentestGPT to return a basic analysis
        mock_pentestgpt_resp = MagicMock()
        mock_pentestgpt_resp.json.return_value = {
            "analysis": {
                "hypothesis": "Look for hidden content",
                "exact_commands": ["curl -s -k http://ctf.example.com"],
            }
        }
        mock_pentestgpt_resp.raise_for_status = MagicMock()

        # Mock Shannon to pass through commands unchanged
        mock_shannon_resp = MagicMock()
        mock_shannon_resp.json.return_value = {
            "reviewed": {"commands": ["curl -s -k http://ctf.example.com"]}
        }
        mock_shannon_resp.raise_for_status = MagicMock()

        def post_side_effect(url, **kwargs):
            if "pentestgpt" in url:
                return mock_pentestgpt_resp
            return mock_shannon_resp

        mock_httpx.post.side_effect = post_side_effect

        agent = CTFAgent(
            url="http://ctf.example.com",
            description="Find the hidden flag",
            category="web",
            max_rounds=5,
        )

        # Mock executor to return output with base64-encoded flag
        mock_result = {
            "step_id": "ctf-step",
            "action": "test",
            "outputs": [
                {
                    "command": "curl -s -k http://ctf.example.com",
                    "stdout": "Welcome! Here is your secret: Q1RGe2Vhc3lfYmFzZTY0fQ==",
                    "stderr": "",
                    "returncode": 0,
                    "flag": None,  # Executor didn't catch it (base64 encoded)
                }
            ],
            "flag": None,
        }
        agent.executor = MagicMock()
        agent.executor.execute_steps.return_value = [mock_result]
        agent.executor.load_skills.return_value = ""

        # Collect all yielded results
        results = list(agent.solve())

        # Should have exactly 1 round (flag found, no continuation)
        round_results = [r for r in results if r["type"] == "round"]
        self.assertEqual(len(round_results), 1)
        self.assertEqual(round_results[0]["round"], 1)
        self.assertIsNotNone(round_results[0]["flag"])
        self.assertIn("CTF{easy_base64}", round_results[0]["flag"])
        self.assertEqual(round_results[0]["status"], "flag_found")

        # State should have the decoded flag
        self.assertTrue(agent.state.decoded_results)
        self.assertTrue(any(r["is_flag"] for r in agent.state.decoded_results))

    @patch("modules.ctf.ctf_agent.httpx_client")
    def test_solve_detects_flag_from_executor_directly(self, mock_httpx):
        """When executor already catches the flag (non-base64), solve still terminates."""
        mock_pentestgpt_resp = MagicMock()
        mock_pentestgpt_resp.json.return_value = {
            "analysis": {
                "hypothesis": "Try basic commands",
                "exact_commands": ["curl -s -k http://ctf.example.com/flag"],
            }
        }
        mock_pentestgpt_resp.raise_for_status = MagicMock()

        mock_shannon_resp = MagicMock()
        mock_shannon_resp.json.return_value = {
            "reviewed": {"commands": ["curl -s -k http://ctf.example.com/flag"]}
        }
        mock_shannon_resp.raise_for_status = MagicMock()

        def post_side_effect(url, **kwargs):
            if "pentestgpt" in url:
                return mock_pentestgpt_resp
            return mock_shannon_resp

        mock_httpx.post.side_effect = post_side_effect

        agent = CTFAgent(
            url="http://ctf.example.com",
            description="Find the flag",
            category="web",
            max_rounds=5,
        )

        mock_result = {
            "step_id": "ctf-step",
            "action": "test",
            "outputs": [
                {
                    "command": "curl -s -k http://ctf.example.com/flag",
                    "stdout": "CTF{direct_flag_here}",
                    "stderr": "",
                    "returncode": 0,
                    "flag": "CTF{direct_flag_here}",
                }
            ],
            "flag": "CTF{direct_flag_here}",
        }
        agent.executor = MagicMock()
        agent.executor.execute_steps.return_value = [mock_result]
        agent.executor.load_skills.return_value = ""

        results = list(agent.solve())
        round_results = [r for r in results if r["type"] == "round"]

        self.assertEqual(len(round_results), 1)
        self.assertEqual(round_results[0]["flag"], "CTF{direct_flag_here}")

    @patch("modules.ctf.ctf_agent.httpx_client")
    def test_solve_continues_without_flag(self, mock_httpx):
        """When no flag is found, solve continues through all rounds."""
        mock_pentestgpt_resp = MagicMock()
        mock_pentestgpt_resp.json.return_value = {
            "analysis": {
                "hypothesis": "Try something",
                "exact_commands": ["curl -s -k http://ctf.example.com"],
            }
        }
        mock_pentestgpt_resp.raise_for_status = MagicMock()

        mock_shannon_resp = MagicMock()
        mock_shannon_resp.json.return_value = {
            "reviewed": {"commands": ["curl -s -k http://ctf.example.com"]}
        }
        mock_shannon_resp.raise_for_status = MagicMock()

        def post_side_effect(url, **kwargs):
            if "pentestgpt" in url:
                return mock_pentestgpt_resp
            return mock_shannon_resp

        mock_httpx.post.side_effect = post_side_effect

        agent = CTFAgent(
            url="http://ctf.example.com",
            description="No flag challenge",
            category="web",
            max_rounds=3,
        )

        mock_result = {
            "step_id": "ctf-step",
            "action": "test",
            "outputs": [
                {
                    "command": "curl -s -k http://ctf.example.com",
                    "stdout": "Nothing interesting here",
                    "stderr": "",
                    "returncode": 0,
                    "flag": None,
                }
            ],
            "flag": None,
        }
        agent.executor = MagicMock()
        agent.executor.execute_steps.return_value = [mock_result]
        agent.executor.load_skills.return_value = ""

        results = list(agent.solve())
        round_results = [r for r in results if r["type"] == "round"]
        final_results = [r for r in results if r["type"] == "final"]

        # Should have 3 rounds + 1 final
        self.assertEqual(len(round_results), 3)
        self.assertEqual(len(final_results), 1)
        self.assertEqual(final_results[0]["status"], "max_rounds_reached")

        # All rounds should have tried_commands populated
        # (each round tries the same command, but dedup filters it after round 1)
        self.assertIn("curl -s -k http://ctf.example.com", agent.state.tried_commands)


class AgentStateDataclassTest(unittest.TestCase):
    """Test AgentState default values and field behavior."""

    def test_defaults(self):
        state = AgentState()
        self.assertEqual(state.base64_candidates, [])
        self.assertEqual(state.decoded_results, [])
        self.assertEqual(state.js_variables, {})
        self.assertEqual(state.endpoints_tried, {})
        self.assertEqual(state.error_patterns, [])
        self.assertEqual(state.cookies, {})
        self.assertEqual(state.new_urls, [])
        self.assertEqual(state.tried_commands, set())
        self.assertEqual(state.current_hypothesis, "unknown")
        self.assertEqual(state.failed_strategies, [])

    def test_independent_instances(self):
        """Each AgentState instance should have independent collections."""
        s1 = AgentState()
        s2 = AgentState()
        s1.base64_candidates.append("test")
        s1.tried_commands.add("cmd")

        self.assertEqual(s2.base64_candidates, [])
        self.assertEqual(s2.tried_commands, set())


if __name__ == "__main__":
    unittest.main()
