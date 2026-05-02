CATEGORIES = {
    "injection": ["sqli", "sql-injection", "xss", "command-injection", "code-injection"],
    "authentication": ["auth-bypass", "default-credentials", "weak-password"],
    "information-disclosure": ["info-disclosure", "directory-listing", "path-traversal"],
    "rce": ["rce", "remote-code-execution", "code-execution"],
    "misconfiguration": ["misconfig", "default-config", "exposed-panel"],
}


class VulnClassifier:
    def classify(self, vuln: dict) -> str:
        vuln_type = vuln.get("type", "").lower()
        name = vuln.get("name", "").lower()
        combined = f"{vuln_type} {name}"

        for category, keywords in CATEGORIES.items():
            for kw in keywords:
                if kw in combined:
                    return category

        return "other"
