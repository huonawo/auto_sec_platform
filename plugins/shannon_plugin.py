import requests


class ShannonPlugin:
    def __init__(self, api_url: str = "http://auto_sec_shannon:8002"):
        self.api_url = api_url

    def run(self, target: str, context: dict = None) -> dict:
        try:
            resp = requests.post(
                f"{self.api_url}/plan",
                json={"target": target, "context": context or {}},
                timeout=300,
            )
            return resp.json()
        except Exception as e:
            return {"error": str(e)}
