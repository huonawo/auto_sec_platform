import subprocess
import json

from utils.parser import validate_target
from modules.webscan.web_recon import build_web_context, context_from_httpx_record


class WebScanner:
    def __init__(self, target: str):
        self.target = validate_target(target)

    def run(self, options: dict = None) -> dict:
        options = options or {}
        warnings = []
        results = {
            "target": self.target,
            "findings": [],
            "warnings": warnings,
            "web_context": build_web_context(target=self.target),
        }

        # httpx 探测
        try:
            httpx_result = subprocess.run(
                ["httpx", "-u", self.target, "-json", "-silent"],
                capture_output=True, text=True, timeout=300,
            )
            if httpx_result.returncode != 0:
                results["httpx_error"] = f"exit code {httpx_result.returncode}: {httpx_result.stderr.strip()}"
            elif httpx_result.stdout:
                for line_number, line in enumerate(httpx_result.stdout.strip().split("\n"), 1):
                    if line:
                        try:
                            parsed = json.loads(line)
                        except json.JSONDecodeError as exc:
                            warnings.append(f"httpx invalid JSON on line {line_number}: {exc}")
                            continue
                        results["findings"].append(parsed)
                        results["web_context"] = context_from_httpx_record(self.target, parsed)
        except Exception as e:
            results["httpx_error"] = str(e)

        # nuclei 漏洞扫描
        try:
            nuclei_result = subprocess.run(
                [
                    "nuclei",
                    "-u",
                    self.target,
                    "-t",
                    "/root/nuclei-templates",
                    "-jsonl",
                    "-silent",
                    "-severity",
                    "info,low,medium,high,critical",
                ],
                capture_output=True, text=True, timeout=600,
            )
            if nuclei_result.returncode != 0:
                results["nuclei_error"] = f"exit code {nuclei_result.returncode}: {nuclei_result.stderr.strip()}"
            elif nuclei_result.stdout:
                for line_number, line in enumerate(nuclei_result.stdout.strip().split("\n"), 1):
                    if line:
                        try:
                            results["findings"].append(json.loads(line))
                        except json.JSONDecodeError as exc:
                            warnings.append(f"nuclei invalid JSON on line {line_number}: {exc}")
        except Exception as e:
            results["nuclei_error"] = str(e)

        results["web_context"]["errors"] = [
            value for key, value in results.items() if key.endswith("_error")
        ]
        results["web_context"]["warnings"] = warnings
        return results
