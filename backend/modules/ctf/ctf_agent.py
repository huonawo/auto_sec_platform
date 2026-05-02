import json
import logging
import os
import re

import httpx as httpx_client

from modules.ctf.ctf_executor import CTFExecutor

logger = logging.getLogger(__name__)

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
        self.tried_methods: set[str] = set()
        self.current_hypothesis: str = ""
        self.skills_context: str = ""

    def _load_skills(self):
        """Load CTF skill knowledge base for the challenge category."""
        self.skills_context = self.executor.load_skills(self.category)
        if self.skills_context:
            logger.info("[CTF Agent] Loaded skills for category: %s (%d chars)",
                        self.category, len(self.skills_context))

    def _build_history_for_pentestgpt(self) -> list[dict]:
        """Build structured history list for PentestGPT context."""
        history = []
        for h in self.history[-5:]:
            # Use full observation output, not the truncated summary
            obs = h.get("observation", "") or h.get("observation_summary", "")
            record = {
                "round": h.get("round", 0),
                "commands": h.get("commands", []),
                "observation": obs[:10000],
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

    def _call_pentestgpt(self) -> dict:
        """Call PentestGPT /analyze with skill knowledge and history."""
        history = self._build_history_for_pentestgpt()

        # Build context string
        context_parts = [
            f"CTF Challenge: {self.ctf_name or 'Unknown'}",
            f"Category: {self.category}",
            f"URL/Target: {self.url}",
            f"Description: {self.description}",
        ]
        if self.current_hypothesis:
            context_parts.append(f"Current Hypothesis: {self.current_hypothesis}")
        if self.tried_methods:
            context_parts.append(f"Already Tried: {'; '.join(sorted(self.tried_methods))}")
        context = "\n".join(context_parts)

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
        """Extract a readable summary of execution results."""
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
                    truncated = stdout[:20000] + ("..." if len(stdout) > 20000 else "")
                    parts.append(truncated)
                if stderr:
                    parts.append(f"[stderr] {stderr[:3000]}")
                if out.get("flag"):
                    parts.append(f"*** FLAG FOUND: {out['flag']} ***")
        return "\n".join(parts) if parts else "No output"

    def solve(self):
        """Generator that yields per-round results for streaming.

        Yields dicts with keys: type, round, thought, action, observation, flag
        """
        self._load_skills()

        for round_num in range(1, self.max_rounds + 1):
            log = []
            log.append(f"{'═' * 50}")
            log.append(f"  Round {round_num} / {self.max_rounds}")
            log.append(f"{'═' * 50}")
            logger.info("[CTF Agent] === Round %d/%d ===", round_num, self.max_rounds)

            # ── Step 1: PentestGPT (with skill knowledge + history) ──
            log.append("")
            log.append("── Step 1: PentestGPT Analysis ──")
            analysis = self._call_pentestgpt()
            thought_summary = self._extract_thought_summary(analysis)
            self.tried_methods.add(thought_summary[:100])
            log.append(thought_summary[:600])
            if len(thought_summary) > 600:
                log.append("  ... (truncated)")

            # ── Step 2: Extract commands from PentestGPT ──
            log.append("")
            log.append("── Step 2: Command Planning ──")

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

            # ── Step 3: Shannon review and optimize ──
            log.append("")
            log.append("── Step 3: Shannon Review ──")
            log.append("Calling Shannon /review ...")

            context = f"Round {round_num}, category: {self.category}"
            if analysis.get("hypothesis"):
                context += f", hypothesis: {analysis['hypothesis']}"
            final_commands = self._call_shannon_review(pentestgpt_commands, context)

            action_summary = self._extract_action_summary(final_commands, source)
            log.append(f"Final commands after review: {len(final_commands)}")
            log.append(action_summary[:500])

            # ── Step 4: Execute ──
            log.append("")
            log.append("── Step 4: Command Execution ──")
            log.append(f"Running in auto_sec_kali ...")

            steps = [{"step_id": "ctf-step", "action": source, "commands": final_commands}]
            step_results = self.executor.execute_steps(steps)
            observation_summary = self._extract_observation_summary(step_results)

            exec_count = sum(len(sr.get("outputs", [])) for sr in step_results)
            log.append(f"Executed {exec_count} command(s):")
            log.append(observation_summary)

            # ── Step 5: Flag check ──
            log.append("")
            log.append("── Step 5: Flag Detection ──")
            flag = None
            for sr in step_results:
                if sr.get("flag"):
                    flag = sr["flag"]
                    break

            if flag:
                log.append(f"FLAG FOUND: {flag}")
            else:
                log.append("No flag in command output")

            # Build observation for GUI display
            full_observation = "\n".join(log)

            # Record history with structured data
            round_record = {
                "round": round_num,
                "thought": thought_summary,
                "action": action_summary,
                "observation": full_observation,
                "observation_summary": observation_summary[:5000],
                "commands": final_commands,
                "hypothesis": analysis.get("hypothesis", self.current_hypothesis),
                "flag": flag,
            }
            self.history.append(round_record)

            # Update hypothesis
            if not flag and observation_summary != "No output":
                self.current_hypothesis = (
                    f"Round {round_num}: "
                    f"{analysis.get('hypothesis', '')}. "
                    f"Results: {observation_summary[:500]}. "
                    f"Need to try different approaches."
                )

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

        # Exhausted all rounds
        yield {
            "type": "final",
            "round": self.max_rounds,
            "thought": "", "action": "", "observation": "",
            "flag": None,
            "status": "max_rounds_reached",
            "message": f"Reached maximum rounds ({self.max_rounds}) without finding flag.",
        }
