import sys
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

from modules.ctf.ctf_agent import (  # noqa: E402
    AgentState,
    extract_and_update,
    detect_challenge_type,
    CTFAgent,
)
from modules.ctf.ctf_classifier import CTFClassifier, fallback_classification  # noqa: E402


# ── extract_and_update ─────────────────────────────────────────────────────


class ExtractAndUpdateTest(unittest.TestCase):
    """Test extract_and_update parses command output into AgentState."""

    def test_base64_candidate_extracted_and_decoded(self):
        output = "Here is the secret: Q1RGe2Vhc3lfYmFzZTY0fQ=="
        state = extract_and_update(output, AgentState())

        self.assertEqual(len(state.base64_candidates), 1)
        self.assertEqual(len(state.decoded_results), 1)
        self.assertIn("CTF{easy_base64}", state.decoded_results[0]["decoded"])
        self.assertTrue(state.decoded_results[0]["is_flag"])

    def test_non_flag_base64_not_marked(self):
        output = "token: aGVsbG8gd29ybGQ="
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

        self.assertEqual(len(state.base64_candidates), 1)

    def test_state_is_additive(self):
        state = AgentState()
        extract_and_update("Q1RGe2Vhc3lfYmFzZTY0fQ==", state)
        extract_and_update("aGVsbG8gd29ybGQ=", state)

        self.assertEqual(len(state.base64_candidates), 2)
        self.assertEqual(len(state.decoded_results), 2)


class ExtractHTTPPatternsTest(unittest.TestCase):
    """Test HTTP-aware extraction in extract_and_update."""

    def test_http_headers_extracted(self):
        output = (
            "HTTP/1.1 200 OK\r\n"
            "Server: nginx/1.14\r\n"
            "X-Powered-By: Express\r\n"
            "X-Debug-Mode: true\r\n"
            "Content-Type: text/html\r\n"
        )
        state = extract_and_update(output, AgentState())

        self.assertEqual(state.http_headers["Server"], "nginx/1.14")
        self.assertEqual(state.http_headers["X-Powered-By"], "Express")
        self.assertEqual(state.http_headers["X-Debug-Mode"], "true")
        self.assertEqual(state.http_headers["Content-Type"], "text/html")

    def test_html_comments_extracted(self):
        output = '<html><!-- TODO: remove debug info --><!-- password: admin123 --></html>'
        state = extract_and_update(output, AgentState())

        self.assertEqual(len(state.html_comments), 2)
        self.assertIn("TODO: remove debug info", state.html_comments)
        self.assertIn("password: admin123", state.html_comments)

    def test_html_comments_deduped(self):
        output = "<!-- same --><!-- same -->"
        state = extract_and_update(output, AgentState())

        self.assertEqual(len(state.html_comments), 1)

    def test_hidden_form_fields_extracted(self):
        output = '<input type="hidden" name="csrf_token" value="abc123">'
        state = extract_and_update(output, AgentState())

        self.assertEqual(state.form_fields["csrf_token"], "abc123")

    def test_redirect_chain_extracted(self):
        output = "HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n"
        state = extract_and_update(output, AgentState())

        self.assertIn("/login", state.redirect_chain)

    def test_multiple_redirects(self):
        output = "Location: /step1\nLocation: /step2\nLocation: /step3"
        state = extract_and_update(output, AgentState())

        self.assertEqual(len(state.redirect_chain), 3)
        self.assertEqual(state.redirect_chain, ["/step1", "/step2", "/step3"])

    def test_www_authenticate_extracted(self):
        output = "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"secret\""
        state = extract_and_update(output, AgentState())

        self.assertIn("WWW-Authenticate", state.http_headers)


# ── detect_challenge_type ──────────────────────────────────────────────────


class DetectChallengeTypeTest(unittest.TestCase):
    """Test challenge type detection from description and output."""

    def test_cookie_forgery_from_description(self):
        types = detect_challenge_type("Forge the admin cookie to access the flag")
        self.assertIn("cookie_forgery", types)

    def test_header_injection_from_description(self):
        types = detect_challenge_type("Bypass IP check using X-Forwarded-For header")
        self.assertIn("header_injection", types)

    def test_ssti_from_output(self):
        types = detect_challenge_type("", "Error rendering template: jinja2.TemplateSyntaxError")
        self.assertIn("ssti", types)

    def test_sqli_from_description(self):
        types = detect_challenge_type("Login bypass via SQL injection in query parameter")
        self.assertIn("sqli", types)

    def test_jwt_from_output(self):
        output = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.signature"
        types = detect_challenge_type("", output)
        self.assertIn("jwt", types)

    def test_xss_from_description(self):
        types = detect_challenge_type("Find the reflected XSS vulnerability")
        self.assertIn("xss", types)

    def test_lfi_from_output(self):
        types = detect_challenge_type("", "Warning: include(../config.php) failed")
        self.assertIn("lfi", types)

    def test_ssrf_from_description(self):
        types = detect_challenge_type("Access the internal metadata service via SSRF")
        self.assertIn("ssrf", types)

    def test_base64_from_description(self):
        types = detect_challenge_type("Decode the base64 encoded message to find the flag")
        self.assertIn("base64", types)

    def test_multiple_types(self):
        types = detect_challenge_type(
            "JWT token with SQL injection in the user parameter"
        )
        self.assertIn("jwt", types)
        self.assertIn("sqli", types)

    def test_unknown_defaults(self):
        types = detect_challenge_type("Find the hidden flag")
        self.assertEqual(types, ["unknown"])

    def test_command_inject_from_description(self):
        types = detect_challenge_type("Exploit the command injection in the ping form")
        self.assertIn("command_inject", types)

    def test_deserializ_from_output(self):
        types = detect_challenge_type("", "PHP Fatal error: Uncaught Error: Cannot unserialize")
        self.assertIn("deserializ", types)


# ── CTFClassifier ──────────────────────────────────────────────────────────


class CTFClassifierTest(unittest.TestCase):
    """Test web challenge classifier."""

    def test_ssti_from_template_error(self):
        ctx = {
            "body": "Error: jinja2 template rendering failed at line 5",
            "headers": {},
            "cookies": [],
            "comments": [],
            "forms": [],
            "hidden_fields": [],
            "error_patterns": [],
            "base64_candidates": [],
            "jwt_candidates": [],
            "technologies": [],
            "title": "",
            "url_params": {},
        }
        result = CTFClassifier().classify(ctx)
        self.assertEqual(result["category"], "ssti")
        self.assertGreater(result["confidence"], 0)

    def test_jwt_from_token_in_body(self):
        ctx = {
            "body": "Your token: eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZ3Vlc3QifQ.abc123",
            "headers": {},
            "cookies": [],
            "comments": [],
            "forms": [],
            "hidden_fields": [],
            "error_patterns": [],
            "base64_candidates": [],
            "jwt_candidates": ["eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiZ3Vlc3QifQ.abc123"],
            "technologies": [],
            "title": "",
            "url_params": {},
        }
        result = CTFClassifier().classify(ctx)
        self.assertEqual(result["category"], "jwt")

    def test_sqli_from_mysql_error(self):
        ctx = {
            "body": "You have an error in your SQL syntax; check the manual for MySQL",
            "headers": {},
            "cookies": [],
            "comments": [],
            "forms": [],
            "hidden_fields": [],
            "error_patterns": ["mysql"],
            "base64_candidates": [],
            "jwt_candidates": [],
            "technologies": [],
            "title": "",
            "url_params": {"id": ["1"]},
        }
        result = CTFClassifier().classify(ctx)
        self.assertEqual(result["category"], "sqli")

    def test_fallback_on_empty_context(self):
        result = fallback_classification()
        self.assertEqual(result["category"], "unknown")
        self.assertEqual(result["confidence"], 0.0)
        self.assertTrue(result["playbook"])

    def test_flask_cookie_detected(self):
        ctx = {
            "body": "Welcome! session=eyJyb2xlIjoiZ3Vlc3QifQ.signature",
            "headers": {},
            "cookies": [{"name": "session", "value": "eyJyb2xlIjoiZ3Vlc3QifQ.signature"}],
            "comments": [],
            "forms": [],
            "hidden_fields": [],
            "error_patterns": [],
            "base64_candidates": [],
            "jwt_candidates": [],
            "technologies": ["flask"],
            "title": "",
            "url_params": {},
        }
        result = CTFClassifier().classify(ctx)
        self.assertIn(result["category"], ("jwt", "cookie_forgery"))


# ── AgentState ─────────────────────────────────────────────────────────────


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
        # HTTP-aware fields
        self.assertEqual(state.http_headers, {})
        self.assertEqual(state.html_comments, [])
        self.assertEqual(state.form_fields, {})
        self.assertEqual(state.redirect_chain, [])
        self.assertEqual(state.challenge_types, [])

    def test_independent_instances(self):
        s1 = AgentState()
        s2 = AgentState()
        s1.base64_candidates.append("test")
        s1.tried_commands.add("cmd")
        s1.http_headers["Server"] = "nginx"

        self.assertEqual(s2.base64_candidates, [])
        self.assertEqual(s2.tried_commands, set())
        self.assertEqual(s2.http_headers, {})

    def test_to_prompt_dict_includes_http_fields(self):
        state = AgentState()
        state.http_headers["X-Debug"] = "true"
        state.html_comments.append("secret hint")
        state.challenge_types.append("ssti")

        d = state.to_prompt_dict()
        self.assertEqual(d["http_headers"]["X-Debug"], "true")
        self.assertIn("secret hint", d["html_comments"])
        self.assertIn("ssti", d["challenge_types"])


# ── CTFAgent.solve integration ─────────────────────────────────────────────


class CTFAgentSolveFlagDetectionTest(unittest.TestCase):
    """Test that the solve loop terminates early when a flag is found."""

    @patch("modules.ctf.ctf_agent.httpx_client")
    def test_solve_stops_after_flag_in_output(self, mock_httpx):
        """Executor returns output with a direct flag — solve terminates after Round 1."""
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
        agent.web_context = {}
        agent.classification = fallback_classification()

        # Skip web recon for this test
        agent.category = "unknown"
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
            category="unknown",
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

        self.assertEqual(len(round_results), 3)
        self.assertEqual(len(final_results), 1)
        self.assertEqual(final_results[0]["status"], "max_rounds_reached")


if __name__ == "__main__":
    unittest.main()
