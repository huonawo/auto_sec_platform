import subprocess


class PersistenceScanner:
    def __init__(self, target: str):
        self.target = target

    def run(self, options: dict = None) -> dict:
        options = options or {}
        results = {"target": self.target, "persistence_mechanisms": []}

        # 使用 Impacket 检查持久化
        try:
            result = subprocess.run(
                ["psexec.py", f"anonymous@{self.target}"],
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode != 0:
                results["psexec_error"] = f"exit code {result.returncode}: {result.stderr.strip()}"
            else:
                results["psexec_output"] = result.stdout
        except Exception as e:
            results["psexec_error"] = str(e)

        return results
