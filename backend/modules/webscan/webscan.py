import subprocess
import json

from utils.parser import validate_target


class WebScanner:
    def __init__(self, target: str):
        self.target = validate_target(target)

    def run(self, options: dict = None) -> dict:
        options = options or {}
        results = {"target": self.target, "findings": []}

        # httpx 探测
        try:
            httpx_result = subprocess.run(
                ["httpx", "-u", self.target, "-json", "-silent"],
                capture_output=True, text=True, timeout=300,
            )
            if httpx_result.returncode != 0:
                results["httpx_error"] = f"exit code {httpx_result.returncode}: {httpx_result.stderr.strip()}"
            elif httpx_result.stdout:
                for line in httpx_result.stdout.strip().split("\n"):
                    if line:
                        results["findings"].append(json.loads(line))
        except Exception as e:
            results["httpx_error"] = str(e)

        # nuclei 漏洞扫描
        try:
            nuclei_result = subprocess.run(
                ["nuclei", "-u", self.target, "-jsonl", "-silent"],
                capture_output=True, text=True, timeout=600,
            )
            if nuclei_result.returncode != 0:
                results["nuclei_error"] = f"exit code {nuclei_result.returncode}: {nuclei_result.stderr.strip()}"
            elif nuclei_result.stdout:
                for line in nuclei_result.stdout.strip().split("\n"):
                    if line:
                        results["findings"].append(json.loads(line))
        except Exception as e:
            results["nuclei_error"] = str(e)

        return results
