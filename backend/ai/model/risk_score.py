SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 8,
    "medium": 5,
    "low": 2,
    "info": 1,
}


class RiskScorer:
    def score(self, vuln: dict) -> float:
        severity = vuln.get("severity", "info").lower()
        base = SEVERITY_WEIGHTS.get(severity, 1)

        # 类型加分
        vuln_type = vuln.get("type", "").lower()
        if "rce" in vuln_type or "remote-code" in vuln_type:
            base += 2
        elif "sqli" in vuln_type or "sql-injection" in vuln_type:
            base += 1.5
        elif "xss" in vuln_type:
            base += 1

        return min(base, 10.0)
