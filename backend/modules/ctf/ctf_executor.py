import os
import re
import glob
import shlex
import sys
import base64
import logging
import subprocess

logger = logging.getLogger(__name__)

_FLAG_REGEX = re.compile(r"(?:flag|ctf|CTF|FLAG)\{[^}]{4,}\}", re.IGNORECASE)
_PLACEHOLDER_FILTER = lambda f: re.match(r"^(?:flag|ctf)\{x+\}$", f, re.IGNORECASE)
_CURL_NO_K = re.compile(r"^curl\b(?!.*\s-k\b)")
_BASE64_REGEX = re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}\b")
OUTPUT_LIMIT = 20000
_BLOCKED_TOKENS = (
    " rm ",
    " rm\t",
    "rm -",
    "del ",
    "erase ",
    "format ",
    "shutdown",
    "reboot",
    "mkfs",
    "dd ",
    "chmod ",
    "chown ",
    "useradd",
    "net user",
    "powershell",
    "cmd.exe",
    "bash -i",
    "nc -e",
    "ncat -e",
    "mkfifo",
    "crontab",
    "systemctl",
    "service ",
    "secretsdump",
    "psexec",
)
_PASSIVE_TOOLS = {"curl", "grep", "egrep", "awk", "sed", "python3", "python", "echo", "cat", "head", "tail", "tr", "sort", "uniq", "cut", "base64"}
_CATEGORY_ALLOWED = {
    "unknown": _PASSIVE_TOOLS,
    "sqli": _PASSIVE_TOOLS,
    "lfi": _PASSIVE_TOOLS,
    "cmd_inject": _PASSIVE_TOOLS,
    "ssti": _PASSIVE_TOOLS,
    "encoding": {"python3", "python", "base64", "xxd"},
    "jwt": {"python3", "python", "base64", "grep", "sed", "awk", "echo"},
    "file_upload": _PASSIVE_TOOLS,
    "source_leak": _PASSIVE_TOOLS,
    "auth_bypass": _PASSIVE_TOOLS,
}
_ACTIVE_TOOLS = {
    "sqli": {"sqlmap"},
    "source_leak": {"git-dumper"},
}

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


def _has_unquoted_shell_control(command: str) -> bool:
    in_single = False
    in_double = False
    escaped = False
    for index, char in enumerate(command):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == "'" and not in_double:
            in_single = not in_single
            continue
        if char == '"' and not in_single:
            in_double = not in_double
            continue
        if in_single or in_double:
            continue
        if char in (";", "`", ">", "<"):
            return True
        if command.startswith("$(", index) or command.startswith("&&", index) or command.startswith("||", index):
            return True
    return False


def _truncate_output(text: str) -> str:
    return (text or "")[:OUTPUT_LIMIT]


class CTFExecutor:
    """Executes commands directly in the backend container."""

    def __init__(self, timeout: int = 60, category: str = "unknown", active_probes: bool = False):
        self.timeout = timeout
        self.category = category
        self.active_probes = active_probes

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
        safety_error = self.validate_command(command)
        if safety_error:
            result["stderr"] = f"Blocked unsafe command: {safety_error}"
            return result
        try:
            proc = self._run_command(command)
            decoded_stdout = _decode_base64_strings(proc.stdout)
            decoded_stderr = _decode_base64_strings(proc.stderr)
            flag = self.check_flag(decoded_stdout) or self.check_flag(decoded_stderr)
            result["stdout"] = _truncate_output(decoded_stdout)
            result["stderr"] = _truncate_output(decoded_stderr)
            result["returncode"] = proc.returncode
            if flag:
                result["flag"] = flag
        except subprocess.TimeoutExpired:
            result["stderr"] = f"Command timed out after {self.timeout}s"
        except Exception as e:
            result["stderr"] = str(e)
        return result

    def validate_command(self, command: str) -> str | None:
        """Allow read-only CTF helper commands and block destructive shell use."""
        normalized = f" {command.strip().lower()} "
        if not command.strip():
            return "empty command"
        for token in _BLOCKED_TOKENS:
            if token in normalized:
                return f"contains blocked token {token.strip()!r}"
        if _has_unquoted_shell_control(command):
            return "contains unsupported shell control syntax"
        for segment in command.split("|"):
            try:
                parts = shlex.split(segment.strip(), posix=os.name != "nt")
            except ValueError as exc:
                return f"cannot parse command: {exc}"
            if not parts:
                continue
            program = os.path.basename(parts[0]).lower()
            allowed = set(_CATEGORY_ALLOWED.get(self.category, _CATEGORY_ALLOWED["unknown"]))
            active_allowed = set(_ACTIVE_TOOLS.get(self.category, set()))
            if program in active_allowed and not self.active_probes:
                return f"program {program!r} requires active_probes=True"
            if program in active_allowed and self.active_probes:
                continue
            if program not in allowed:
                return f"program {program!r} is not allowed"
        return None

    def _run_command(self, command: str):
        python_match = re.match(r"^(?:python3|python)\s+-c\s+(.+)$", command.strip(), re.DOTALL)
        if python_match and "|" not in command:
            script = python_match.group(1).strip()
            if (script.startswith('"') and script.endswith('"')) or (script.startswith("'") and script.endswith("'")):
                script = script[1:-1]
            return subprocess.run(
                [sys.executable, "-c", script],
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        return subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=self.timeout,
        )

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

    def load_skills(self, category: str, max_chars: int = 12000) -> str:
        """Load SKILL.md + companion files for the given category.

        Parses markdown links [text](file.md) from the index SKILL.md
        and loads companion files within the character budget.
        """
        skill_dir = os.path.join(SKILLS_DIR, f"ctf-{category}")
        index_path = os.path.join(skill_dir, "SKILL.md")

        if not os.path.isfile(index_path):
            fallback = os.path.join(SKILLS_DIR, "solve-challenge", "SKILL.md")
            if os.path.isfile(fallback):
                index_path = fallback
                skill_dir = os.path.dirname(fallback)
            else:
                return ""

        try:
            with open(index_path, "r", encoding="utf-8") as f:
                index_content = f.read()
        except Exception as e:
            logger.warning("Failed to load skill %s: %s", index_path, e)
            return ""

        # Extract companion .md file references from markdown links
        companions = re.findall(r'\[.*?\]\(([^)]+\.md)\)', index_content)

        # Load companion files within budget, skip duplicates
        loaded = index_content
        seen = {os.path.basename(index_path)}
        for companion in companions:
            companion_name = os.path.basename(companion)
            if companion_name in seen:
                continue
            seen.add(companion_name)
            companion_path = os.path.join(skill_dir, companion_name)
            if not os.path.isfile(companion_path):
                continue
            try:
                with open(companion_path, "r", encoding="utf-8") as f:
                    content = f.read()
            except Exception:
                continue
            if len(loaded) + len(content) <= max_chars:
                loaded += f"\n\n--- {companion_name} ---\n{content}"
            else:
                # Try to fit a truncated version
                remaining = max_chars - len(loaded) - len(companion_name) - 20
                if remaining > 500:
                    loaded += f"\n\n--- {companion_name} ---\n{content[:remaining]}..."
                break

        logger.info("[CTF Executor] Loaded skill '%s': %d chars, %d companions",
                    category, len(loaded), len(seen) - 1)
        return loaded

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
