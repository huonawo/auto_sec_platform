import base64
import json
import logging
import os
import re
from dataclasses import dataclass, field

import httpx as httpx_client

from modules.ctf.ctf_executor import CTFExecutor

logger = logging.getLogger(__name__)

# Pattern for flag detection in decoded base64
_FLAG_IN_DECODED = re.compile(r"(?:flag|ctf|CTF|FLAG)\{[^}]{4,}\}", re.IGNORECASE)


@dataclass
class AgentState:
    """Cumulative state that persists across all rounds — never cleared."""

    # Accumulated discoveries (append-only)
    base64_candidates: list[str] = field(default_factory=list)
    decoded_results: list[dict] = field(default_factory=list)  # {raw, decoded, is_flag}
    js_variables: dict = field(default_factory=dict)  # {varName: value}
    endpoints_tried: dict = field(default_factory=dict)  # {url: status_code}
    error_patterns: list[str] = field(default_factory=list)
    cookies: dict = field(default_factory=dict)
    new_urls: list[str] = field(default_factory=list)

    # Dedup control
    tried_commands: set = field(default_factory=set)

    # Current reasoning state
    current_hypothesis: str = "unknown"
    failed_strategies: list[str] = field(default_factory=list)


def extract_and_update(output: str, state: AgentState) -> AgentState:
    """Extract structured information from command output and append to state.

    This function is additive — it only appends new discoveries, never clears.
    """
    if not output:
        return state

    # 1. Extract base64 candidates (>=16 chars, optional trailing =)
    candidates = re.findall(r'[A-Za-z0-9+/]{16,}={0,2}', output)
    for c in candidates:
        if c not in state.base64_candidates:
            state.base64_candidates.append(c)
            try:
                # Pad to valid base64 length if needed
                padded = c + "==" if len(c) % 4 else c
                decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
                is_flag = bool(_FLAG_IN_DECODED.search(decoded))
                state.decoded_results.append({
                    "raw": c,
                    "decoded": decoded,
                    "is_flag": is_flag,
                })
            except Exception:
                pass

    # 2. Extract JS variable assignments (const/let/var name = "value")
    js_vars = re.findall(
        r'(?:const|let|var)\s+(\w+)\s*=\s*["\']([^"\']+)["\']', output
    )
    for name, val in js_vars:
        state.js_variables[name] = val

    # 3. Extract URLs and infer endpoint status
    urls = re.findall(r'https?://\S+', output)
    for url in urls:
        clean_url = url.rstrip(".,;:")
        if clean_url not in state.new_urls:
            state.new_urls.append(clean_url)
    # Infer status codes from output context
    status_matches = re.findall(r'(https?://\S+)\s+.*?(\d{3})', output)
    for url, code in status_matches:
        state.endpoints_tried[url.rstrip(".,;:")] = int(code)

    # 4. Extract error patterns
    error_keywords = [
        "SyntaxError", "mysql_error", "Warning:", "Traceback",
        "undefined", "Segmentation fault", "Permission denied",
        "404 Not Found", "500 Internal Server Error",
    ]
    for kw in error_keywords:
        if kw in output and kw not in state.error_patterns:
            state.error_patterns.append(kw)

    # 5. Extract cookies from Set-Cookie headers
    cookie_matches = re.findall(r'Set-Cookie:\s*(\w+)=([^\s;]+)', output, re.IGNORECASE)
    for name, val in cookie_matches:
        state.cookies[name] = val

    return state


PENTESTGPT_URL = os.environ.get("PENTESTGPT_URL", "http://auto_sec_pentestgpt:8001")
SHANNON_URL = os.environ.get("SHANNON_URL", "http://auto_sec_shannon:8002")


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
    ):
        self.url = url
        self.description = description
        self.category = category
        self.ctf_name = ctf_name
        self.max_rounds = max_rounds
        self.timeout = timeout

        self.executor = CTFExecutor(timeout=60)
        self.history: list[dict] = []
        self.skills_context: str = ""
        self.state = AgentState()

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

    def _is_base64_challenge(self) -> bool:
        """Check if this is a base64-themed challenge."""
        desc_lower = self.description.lower()
        return "base64" in desc_lower or "编码" in desc_lower or "encode" in desc_lower

    def _recon_commands(self) -> list[str]:
        """Round 1 fixed recon commands."""
        return [
            f"curl -s -k {self.url}",
            f"curl -sI -k {self.url}",
            f"curl -s -k {self.url} | grep -i base64",
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

    def _build_state_summary(self) -> str:
        """Build a summary of AgentState for injection into PentestGPT prompt."""
        s = self.state
        parts = []
        if s.base64_candidates:
            parts.append(f"Base64候选 ({len(s.base64_candidates)}): {s.base64_candidates[-10:]}")
        if s.decoded_results:
            decoded_strs = [
                f"{r['raw'][:30]}→{r['decoded'][:50]}"
                + (" [FLAG!]" if r["is_flag"] else "")
                for r in s.decoded_results[-10:]
            ]
            parts.append(f"解码结果: {decoded_strs}")
        if s.js_variables:
            parts.append(f"JS变量: {s.js_variables}")
        if s.endpoints_tried:
            parts.append(f"已试端点: {s.endpoints_tried}")
        if s.error_patterns:
            parts.append(f"错误模式: {s.error_patterns}")
        if s.cookies:
            parts.append(f"Cookies: {s.cookies}")
        if s.failed_strategies:
            parts.append(f"失败策略: {s.failed_strategies}")
        if s.current_hypothesis and s.current_hypothesis != "unknown":
            parts.append(f"当前假设: {s.current_hypothesis}")
        if s.tried_commands:
            parts.append(f"已试命令 ({len(s.tried_commands)}): {sorted(s.tried_commands)[-10:]}")
        return "\n".join(parts) if parts else "（尚无累积信息）"

    def _call_pentestgpt(self, round_num: int) -> dict:
        """Call PentestGPT /analyze with AgentState summary injected into prompt."""
        history = self._build_history_for_pentestgpt()
        state_summary = self._build_state_summary()

        # Build the structured context per spec
        context = (
            f"=== 目标 ===\n"
            f"URL: {self.url}\n"
            f"描述: {self.description}\n"
            f"类别: {self.category}\n"
            f"挑战名: {self.ctf_name or 'Unknown'}\n"
            f"\n=== 已知信息（勿重复探测）===\n"
            f"{state_summary}\n"
            f"\n=== 本轮目标 ===\n"
            f"Round {round_num}/{self.max_rounds}。基于已知信息推进，不要重复已失败的命令。\n"
        )
        if self.state.base64_candidates:
            context += "若发现 base64 候选未解码，exact_commands 必须包含解码命令。\n"
        if self.state.js_variables:
            context += "若 JS 变量中有疑似密码/token，必须尝试使用。\n"
        if self.state.failed_strategies:
            context += "当前策略已穷尽，必须尝试全新方向。\n"

        try:
            resp = httpx_client.post(
                f"{PENTESTGPT_URL}/analyze",
                json={
                    "scan_results": {"ctf_context": context},
                    "target": self.url,
                    "context": "This is a CTF challenge. Analyze and suggest the next attack approach. Focus on what has NOT been tried yet.",
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
                return result["decoded"]
        return None

    def solve(self):
        """Generator that yields per-round results for streaming.

        Four-step loop per round:
          Step 1: extract_and_update — parse previous round output into AgentState
          Step 2: base64 decode check — try all candidates, early flag return
          Step 3: PentestGPT with state summary — inject cumulative knowledge
          Step 4: command dedup + execute — filter tried commands, run new ones

        Yields dicts with keys: type, round, thought, action, observation, flag
        """
        self._load_skills()

        for round_num in range(1, self.max_rounds + 1):
            log = []
            log.append(f"{'═' * 50}")
            log.append(f"  Round {round_num} / {self.max_rounds}")
            log.append(f"{'═' * 50}")
            logger.info("[CTF Agent] === Round %d/%d ===", round_num, self.max_rounds)

            # ── Step 1: Extract & update state from previous round output ──
            if round_num > 1 and self.history:
                prev_output = self.history[-1].get("observation_summary", "")
                log.append("")
                log.append("── Step 1: State Extraction ──")
                extract_and_update(prev_output, self.state)
                log.append(f"Base64 candidates: {len(self.state.base64_candidates)}")
                log.append(f"JS variables: {len(self.state.js_variables)}")
                log.append(f"Error patterns: {self.state.error_patterns}")

                # ── Step 2: Check decoded base64 for flags ──
                decoded_flag = self._check_decoded_flags()
                if decoded_flag:
                    log.append(f"FLAG FOUND in decoded base64: {decoded_flag}")
                    full_observation = "\n".join(log)
                    yield {
                        "type": "round", "round": round_num,
                        "thought": "Flag found in decoded base64",
                        "action": "base64 decode",
                        "observation": full_observation,
                        "flag": decoded_flag,
                        "status": "flag_found",
                    }
                    return

            # ── Step 3: PentestGPT with state summary ──
            log.append("")
            log.append("── Step 3: PentestGPT Analysis ──")
            analysis = self._call_pentestgpt(round_num)
            thought_summary = self._extract_thought_summary(analysis)
            log.append(thought_summary)

            # Extract commands from PentestGPT
            log.append("")
            log.append("── Command Planning ──")
            pentestgpt_commands = analysis.get("exact_commands", [])
            if not pentestgpt_commands:
                pentestgpt_commands = self._fallback_from_analysis(analysis)
                source = "Fallback from analysis"
            else:
                source = "PentestGPT exact_commands"

            # Round 1: merge with fixed recon commands
            if round_num == 1:
                if self._is_base64_challenge():
                    recon = self._base64_recon_commands()
                    source = "PentestGPT + Base64 Recon"
                else:
                    recon = self._recon_commands()
                    source = "PentestGPT + Recon"
                pentestgpt_commands = self._merge_commands(pentestgpt_commands, recon)

            log.append(f"Source: {source}")
            log.append(f"PentestGPT generated {len(pentestgpt_commands)} command(s)")

            # Shannon review
            log.append("")
            log.append("── Shannon Review ──")
            context = f"Round {round_num}, category: {self.category}"
            if analysis.get("hypothesis"):
                context += f", hypothesis: {analysis['hypothesis']}"
            reviewed_commands = self._call_shannon_review(pentestgpt_commands, context)

            # ── Step 4: Command dedup + execute ──
            log.append("")
            log.append("── Step 4: Execution ──")
            final_commands = self._dedup_commands(reviewed_commands)

            if not final_commands:
                # All commands already tried — record failed strategy
                self.state.failed_strategies.append(
                    analysis.get("hypothesis", self.state.current_hypothesis)
                )
                log.append("All commands already tried — strategy exhausted")
                log.append(f"Failed strategies: {self.state.failed_strategies}")
                # Force PentestGPT to try a completely new direction next round
                self.state.current_hypothesis = "策略已穷尽，必须尝试全新方向"
            else:
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

                # Extract state from execution output (for non-round-1 or if round 1 had output)
                for sr in step_results:
                    for out in sr.get("outputs", []):
                        stdout = out.get("stdout", "")
                        stderr = out.get("stderr", "")
                        extract_and_update(stdout + "\n" + stderr, self.state)

                # Check decoded flags after extraction
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

                # Build observation for GUI display
                full_observation = "\n".join(log)

                # Record history
                round_record = {
                    "round": round_num,
                    "thought": thought_summary,
                    "action": action_summary,
                    "observation": full_observation,
                    "observation_summary": observation_summary,
                    "commands": final_commands,
                    "hypothesis": analysis.get("hypothesis", self.state.current_hypothesis),
                    "flag": flag,
                }
                self.history.append(round_record)

                yield {
                    "type": "round", "round": round_num,
                    "thought": thought_summary,
                    "action": action_summary,
                    "observation": full_observation,
                    "flag": flag,
                    "status": "flag_found" if flag else "continuing",
                }

                if flag:
                    return
                continue

            # Strategy exhausted path — still yield a round for GUI
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
            }

        # Exhausted all rounds
        yield {
            "type": "final",
            "round": self.max_rounds,
            "thought": "", "action": "", "observation": "",
            "flag": None,
            "status": "max_rounds_reached",
            "message": f"Reached maximum rounds ({self.max_rounds}) without finding flag.",
        }
