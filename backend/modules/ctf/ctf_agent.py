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
    """ReAct-loop agent that coordinates PentestGPT + Shannon + CTF Executor."""

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

    def _build_context(self) -> str:
        """Build context string for PentestGPT analysis."""
        parts = [
            f"=== CTF Challenge ===",
            f"Name: {self.ctf_name or 'Unknown'}",
            f"Category: {self.category}",
            f"URL/Target: {self.url}",
            f"Description: {self.description}",
        ]

        if self.current_hypothesis:
            parts.append(f"\n=== Current Hypothesis ===\n{self.current_hypothesis}")

        if self.tried_methods:
            parts.append(f"\n=== Already Tried Methods ===\n" +
                         "\n".join(f"- {m}" for m in sorted(self.tried_methods)))

        if self.history:
            parts.append("\n=== Execution History ===")
            for h in self.history[-5:]:
                parts.append(f"\nRound {h['round']}:")
                if h.get("thought"):
                    parts.append(f"  Thought: {h['thought']}")
                if h.get("action"):
                    parts.append(f"  Action: {h['action']}")
                if h.get("observation"):
                    obs = h["observation"]
                    if len(obs) > 500:
                        obs = obs[:500] + "... (truncated)"
                    parts.append(f"  Observation: {obs}")

        if self.skills_context:
            truncated = self.skills_context[:3000]
            if len(self.skills_context) > 3000:
                truncated += "\n... (truncated)"
            parts.append(f"\n=== CTF Skills Reference ===\n{truncated}")

        return "\n".join(parts)

    def _recon_commands(self) -> list[str]:
        """Round 1 fixed recon commands."""
        return [
            f"curl -s {self.url}",
            f"curl -sI {self.url}",
            f"curl -s {self.url} | grep -i base64",
        ]

    def _fallback_from_analysis(self, analysis: dict) -> list[str]:
        """Generate commands from PentestGPT analysis when Shannon returns nothing."""
        cmds = []
        next_steps = analysis.get("next_steps", [])
        attack_ideas = analysis.get("attack_ideas", [])

        # Always try basic page fetch
        cmds.append(f"curl -s -L {self.url}")

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
            cmds.append(f"curl -sI {self.url}")
        if "source" in hint_blob or "comment" in hint_blob or "html" in hint_blob:
            cmds.append(f"curl -s {self.url} | grep -iE 'flag|ctf|secret|key|password|admin|hidden'")
        if "base64" in hint_blob or "encode" in hint_blob:
            cmds.append(f"curl -s {self.url} | grep -i base64")
        if "cookie" in hint_blob:
            cmds.append(f"curl -sv {self.url} 2>&1 | grep -i set-cookie")
        if "redirect" in hint_blob or "302" in hint_blob:
            cmds.append(f"curl -sI -L {self.url} | grep -iE 'location|HTTP'")
        if "robots" in hint_blob:
            cmds.append(f"curl -s {self.url}/robots.txt")
        if "admin" in hint_blob or "login" in hint_blob:
            cmds.append(f"curl -s {self.url}/admin")
            cmds.append(f"curl -s {self.url}/login")

        return cmds[:5]

    def _call_pentestgpt(self, context: str) -> dict:
        """Call PentestGPT /analyze to get attack reasoning."""
        try:
            resp = httpx_client.post(
                f"{PENTESTGPT_URL}/analyze",
                json={
                    "scan_results": {"ctf_context": context},
                    "target": self.url,
                    "context": (
                        "This is a CTF challenge. Analyze the challenge and suggest "
                        "the next attack approach. Focus on what has NOT been tried yet."
                    ),
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

    def _call_shannon(self, thought: dict) -> list[dict]:
        """Call Shannon /execute to get concrete commands from the attack idea."""
        next_steps = thought.get("next_steps", [])
        attack_ideas = thought.get("attack_ideas", [])
        findings = thought.get("findings", [])

        action = ""
        tool = ""
        if next_steps:
            step = next_steps[0]
            action = step if isinstance(step, str) else step.get("description", str(step))
        elif attack_ideas:
            idea = attack_ideas[0] if isinstance(attack_ideas[0], dict) else {}
            action = idea.get("technique", "") + ": " + idea.get("description", "")
            tool = idea.get("tools", "")
        elif findings:
            f = findings[0] if isinstance(findings[0], dict) else {}
            action = f"Investigate: {f.get('name', '')} - {f.get('description', '')}"

        if not action:
            action = "Enumerate and analyze the target for vulnerabilities"

        logger.info("[CTF Agent] Shannon request: action=%s tool=%s", action, tool)

        try:
            resp = httpx_client.post(
                f"{SHANNON_URL}/execute",
                json={
                    "step_id": "ctf-step",
                    "action": action,
                    "tool": tool or self.category,
                    "target": self.url,
                    "parameters": {
                        "category": self.category,
                        "description": self.description,
                    },
                },
                timeout=120,
            )
            resp.raise_for_status()
            data = resp.json()
            logger.info("[CTF Agent] Shannon raw: %s",
                        json.dumps(data, ensure_ascii=False)[:600])

            execution = data.get("execution", data)
            commands = execution.get("commands", [])
            if isinstance(commands, str):
                commands = [commands]

            logger.info("[CTF Agent] Shannon commands: %s", commands)
            return [{"step_id": "ctf-step", "action": action, "commands": commands}]
        except Exception as e:
            logger.warning("[CTF Agent] Shannon call failed: %s", e)
            return [{"step_id": "ctf-step", "action": action, "commands": []}]

    def _extract_thought_summary(self, analysis: dict) -> str:
        """Extract a readable summary from PentestGPT analysis."""
        if analysis.get("error"):
            return f"Error: {analysis['error']}"
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

    def _extract_action_summary(self, steps: list[dict]) -> str:
        """Extract a readable summary of planned actions."""
        parts = []
        for step in steps:
            action = step.get("action", "")
            commands = step.get("commands", [])
            if action:
                parts.append(f"Action: {action}")
            if commands:
                parts.append("Commands:\n" + "\n".join(f"  $ {c}" for c in commands[:5]))
            else:
                parts.append("Commands: (none)")
        return "\n".join(parts) if parts else "No commands generated"

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
                    truncated = stdout[:800] + ("..." if len(stdout) > 800 else "")
                    parts.append(truncated)
                if stderr:
                    parts.append(f"[stderr] {stderr[:300]}")
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

            # ── Step 1: PentestGPT ──
            log.append("")
            log.append("── Step 1: PentestGPT Analysis ──")
            context = self._build_context()
            analysis = self._call_pentestgpt(context)
            thought_summary = self._extract_thought_summary(analysis)
            self.tried_methods.add(thought_summary[:100])
            log.append(thought_summary[:600])
            if len(thought_summary) > 600:
                log.append("  ... (truncated)")

            # ── Step 2: Build command list ──
            log.append("")
            log.append("── Step 2: Command Planning ──")

            if round_num == 1:
                # Round 1: fixed recon commands
                commands = self._recon_commands()
                action_summary = "Action: Initial recon\nCommands:\n" + "\n".join(f"  $ {c}" for c in commands)
                steps = [{"step_id": "ctf-recon", "action": "Initial recon", "commands": commands}]
                log.append(f"Round 1: executing {len(commands)} fixed recon commands")
            else:
                # Round 2+: ask Shannon
                log.append("Calling Shannon /execute ...")
                steps = self._call_shannon(analysis)
                raw_commands = []
                for s in steps:
                    raw_commands.extend(s.get("commands", []))

                if not raw_commands:
                    # Shannon empty → fallback from PentestGPT analysis
                    fallback_cmds = self._fallback_from_analysis(analysis)
                    steps = [{"step_id": "ctf-fallback", "action": "Fallback from analysis", "commands": fallback_cmds}]
                    action_summary = "Action: Fallback from PentestGPT analysis\nCommands:\n" + "\n".join(f"  $ {c}" for c in fallback_cmds)
                    log.append(f"Shannon returned NO commands, generated {len(fallback_cmds)} from analysis:")
                else:
                    action_summary = self._extract_action_summary(steps)
                    log.append(f"Shannon returned {len(raw_commands)} command(s):")

            log.append(action_summary[:500])

            # ── Step 3: Execute ──
            log.append("")
            log.append("── Step 3: Command Execution ──")
            log.append(f"Running in auto_sec_kali ...")

            step_results = self.executor.execute_steps(steps)
            observation_summary = self._extract_observation_summary(step_results)

            exec_count = sum(len(sr.get("outputs", [])) for sr in step_results)
            log.append(f"Executed {exec_count} command(s):")
            log.append(observation_summary[:1000])
            if len(observation_summary) > 1000:
                log.append("  ... (truncated)")

            # ── Step 4: Flag check (executor output ONLY) ──
            log.append("")
            log.append("── Step 4: Flag Detection ──")
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

            # Record history
            round_record = {
                "round": round_num,
                "thought": thought_summary,
                "action": action_summary,
                "observation": full_observation,
                "flag": flag,
            }
            self.history.append(round_record)

            # Update hypothesis
            if not flag and observation_summary != "No output":
                self.current_hypothesis = (
                    f"Round {round_num} results: "
                    f"{observation_summary[:200]}. "
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
