import os
import re
import glob
import base64
import logging
import subprocess

logger = logging.getLogger(__name__)

_FLAG_REGEX = re.compile(r"(?:flag|ctf|CTF|FLAG)\{[^}]{4,}\}", re.IGNORECASE)
_PLACEHOLDER_FILTER = lambda f: re.match(r"^(?:flag|ctf)\{x+\}$", f, re.IGNORECASE)
_CURL_NO_K = re.compile(r"^curl\b(?!.*\s-k\b)")
_BASE64_REGEX = re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}\b")

SKILLS_DIR = os.path.expanduser("~/.claude/skills/ctf-skills")


def _preprocess_command(command: str) -> str:
    """Auto-add -k to curl commands that don't already have it."""
    if _CURL_NO_K.match(command.strip()):
        command = command.strip().replace("curl ", "curl -k ", 1)
        logger.debug("Auto-added -k to curl command: %s", command)
    return command


def _decode_base64_strings(text: str) -> str:
    """Annotate base64-encoded strings in output with their decoded values."""
    if not text:
        return text

    def _try_decode(match):
        candidate = match.group(0)
        # Skip if it looks like a file path or URL fragment
        if "/" in candidate and not candidate.endswith("="):
            return candidate
        try:
            decoded = base64.b64decode(candidate)
            decoded_str = decoded.decode("utf-8")
            # Only annotate if result is printable and meaningful
            if decoded_str.isprintable() and len(decoded_str) >= 4:
                return f"{candidate} [decoded: {decoded_str}]"
        except Exception:
            pass
        return candidate

    return _BASE64_REGEX.sub(_try_decode, text)


class CTFExecutor:
    """Executes commands directly in the backend container."""

    def __init__(self, timeout: int = 60):
        self.timeout = timeout

    def execute(self, command: str) -> dict:
        """Run a command directly via subprocess."""
        command = _preprocess_command(command)
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

            # Decode base64 strings in output
            result["stdout"] = _decode_base64_strings(result["stdout"])
            result["stderr"] = _decode_base64_strings(result["stderr"])

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
