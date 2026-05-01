import os
import re
import glob
import logging
import subprocess

logger = logging.getLogger(__name__)

_FLAG_REGEX = re.compile(r"(?:flag|ctf|CTF|FLAG)\{[^}]{4,}\}", re.IGNORECASE)
_PLACEHOLDER_FILTER = lambda f: re.match(r"^(?:flag|ctf)\{x+\}$", f, re.IGNORECASE)

SKILLS_DIR = os.path.expanduser("~/.claude/skills/ctf-skills")


class CTFExecutor:
    """Executes commands directly in the backend container."""

    def __init__(self, timeout: int = 60):
        self.timeout = timeout

    def execute(self, command: str) -> dict:
        """Run a command directly via subprocess."""
        result = {
            "command": command,
            "stdout": "",
            "stderr": "",
            "returncode": -1,
            "flag": None,
        }
        try:
            proc = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            result["stdout"] = proc.stdout
            result["stderr"] = proc.stderr
            result["returncode"] = proc.returncode

            flag = self.check_flag(proc.stdout) or self.check_flag(proc.stderr)
            if flag:
                result["flag"] = flag
        except subprocess.TimeoutExpired:
            result["stderr"] = f"Command timed out after {self.timeout}s"
        except Exception as e:
            result["stderr"] = str(e)
        return result

    def check_flag(self, text: str) -> str | None:
        """Search for flag patterns in text. Returns first real match or None.
        Skips placeholders like CTF{xxxxxx} and flags shorter than 8 chars.
        """
        if not text:
            return None
        candidates = _FLAG_REGEX.findall(text)
        for flag in candidates:
            if _PLACEHOLDER_FILTER(flag):
                logger.debug("Skipping placeholder flag: %s", flag)
                continue
            if len(flag) < 8:
                continue
            return flag
        return None

    def load_skills(self, category: str) -> str:
        """Load CTF skill markdown for the given category as context."""
        skill_path = os.path.join(SKILLS_DIR, f"ctf-{category}", "SKILL.md")
        if not os.path.isfile(skill_path):
            fallback = os.path.join(SKILLS_DIR, "solve-challenge", "SKILL.md")
            if os.path.isfile(fallback):
                skill_path = fallback
            else:
                return ""
        try:
            with open(skill_path, "r", encoding="utf-8") as f:
                return f.read()
        except Exception as e:
            logger.warning("Failed to load skill %s: %s", skill_path, e)
            return ""

    def execute_steps(self, steps: list[dict]) -> list[dict]:
        """Execute a list of Shannon step objects, running each step's commands."""
        results = []
        for step in steps:
            commands = step.get("commands", [])
            if isinstance(commands, str):
                commands = [commands]
            step_result = {
                "step_id": step.get("step_id", ""),
                "action": step.get("action", ""),
                "outputs": [],
                "flag": None,
            }
            for cmd in commands:
                out = self.execute(cmd)
                step_result["outputs"].append(out)
                if out.get("flag"):
                    step_result["flag"] = out["flag"]
                    break
            results.append(step_result)
            if step_result["flag"]:
                break
        return results
