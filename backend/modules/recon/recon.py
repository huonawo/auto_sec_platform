import subprocess


class ReconScanner:
    def __init__(self, target: str):
        self.target = target

    def run(self, options: dict = None) -> dict:
        options = options or {}
        results = {"target": self.target, "subdomains": [], "ports": []}

        # nmap 端口扫描
        try:
            nmap_result = subprocess.run(
                ["nmap", "-sS", "-sV", "-T4", self.target],
                capture_output=True, text=True, timeout=600,
            )
            if nmap_result.returncode != 0:
                results["nmap_error"] = f"exit code {nmap_result.returncode}: {nmap_result.stderr.strip()}"
            else:
                results["nmap_output"] = nmap_result.stdout
        except Exception as e:
            results["nmap_error"] = str(e)

        return results
