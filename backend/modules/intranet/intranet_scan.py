import subprocess

from utils.parser import validate_target


class IntranetScanner:
    def __init__(self, target: str):
        self.target = validate_target(target)

    def run(self, options: dict = None) -> dict:
        options = options or {}
        results = {"target": self.target, "hosts": []}

        try:
            nmap_result = subprocess.run(
                ["nmap", "-sn", self.target],
                capture_output=True, text=True, timeout=300,
            )
            if nmap_result.returncode != 0:
                results["nmap_error"] = f"exit code {nmap_result.returncode}: {nmap_result.stderr.strip()}"
            else:
                results["nmap_output"] = nmap_result.stdout
        except Exception as e:
            results["nmap_error"] = str(e)

        return results
