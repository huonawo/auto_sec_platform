import re

from ai.model.risk_score import RiskScorer
from ai.model.vuln_classifier import VulnClassifier
from ai.model.path_planner import PathPlanner

AUTHORIZATION_NOTICE = "Use only for authorized security testing or lab environments."


class AIAnalyzer:
    def __init__(self, model: str = "default"):
        self.model = model
        self.risk_scorer = RiskScorer()
        self.classifier = VulnClassifier()
        self.path_planner = PathPlanner()

    def analyze(self, scan_data: dict) -> dict:
        vulns = self._extract_vulnerabilities(scan_data)
        observations = self._extract_observations(scan_data)
        errors = self._extract_messages(scan_data, "error")
        warnings = self._extract_messages(scan_data, "warning")

        classified = []
        for vuln in vulns:
            c = self.classifier.classify(vuln)
            score = self.risk_scorer.score(vuln)
            classified.append({**vuln, "classification": c, "risk_score": score})

        attack_paths = self.path_planner.plan(classified)
        recommendations = self._build_recommendations(classified, observations, errors)

        return {
            "vulnerabilities": classified,
            "observations": observations,
            "attack_paths": attack_paths,
            "recommendations": recommendations,
            "errors": errors,
            "warnings": warnings,
            "authorization_notice": AUTHORIZATION_NOTICE,
            "summary": {
                "total": len(classified),
                "critical": sum(1 for v in classified if v.get("risk_score", 0) >= 9),
                "high": sum(1 for v in classified if 7 <= v.get("risk_score", 0) < 9),
                "medium": sum(1 for v in classified if 4 <= v.get("risk_score", 0) < 7),
                "low": sum(1 for v in classified if v.get("risk_score", 0) < 4),
                "observations": len(observations),
                "errors": len(errors),
                "warnings": len(warnings),
            },
        }

    def _extract_vulnerabilities(self, scan_data: dict) -> list[dict]:
        vulns = []
        result = scan_data.get("result", {}) if isinstance(scan_data, dict) else {}
        findings = scan_data.get("findings", result.get("findings", []))
        if not findings and isinstance(result.get("vulns"), list):
            findings = result.get("vulns", [])
        for f in findings:
            info = f.get("info", {}) if isinstance(f.get("info", {}), dict) else {}
            vulns.append({
                "vuln_id": f.get("template-id", f.get("vuln_id", "unknown")),
                "type": f.get("type", info.get("type", "unknown")),
                "name": info.get("name", f.get("name", "")),
                "severity": info.get("severity", f.get("severity", "info")),
                "description": info.get("description", f.get("description", "")),
                "matched_at": f.get("matched-at", f.get("host", "")),
                "evidence": f.get("extracted-results", f.get("evidence", [])),
            })
        return vulns

    def _extract_observations(self, scan_data: dict) -> list[dict]:
        result = scan_data.get("result", {}) if isinstance(scan_data, dict) else {}
        nmap_output = result.get("nmap_output", scan_data.get("nmap_output", ""))
        observations = []
        if not nmap_output:
            return observations

        service_re = re.compile(r"^(\d+)\/(tcp|udp)\s+open\s+(\S+)\s*(.*)$", re.IGNORECASE)
        for line in nmap_output.splitlines():
            match = service_re.match(line.strip())
            if not match:
                continue
            port, protocol, service, detail = match.groups()
            observations.append(
                {
                    "type": "open-service",
                    "port": port,
                    "protocol": protocol,
                    "service": service,
                    "description": detail.strip(),
                    "raw": line.strip(),
                }
            )
        return observations

    def _extract_messages(self, payload, kind: str) -> list[str]:
        messages = []
        if isinstance(payload, dict):
            for key, value in payload.items():
                key_lower = str(key).lower()
                if key_lower == f"{kind}s" and isinstance(value, list):
                    messages.extend(str(item) for item in value if item)
                elif key_lower.endswith(f"_{kind}") and value:
                    messages.append(f"{key}: {value}")
                elif isinstance(value, (dict, list)):
                    messages.extend(self._extract_messages(value, kind))
        elif isinstance(payload, list):
            for item in payload:
                messages.extend(self._extract_messages(item, kind))
        return messages

    def _build_recommendations(
        self,
        vulns: list[dict],
        observations: list[dict],
        errors: list[str],
    ) -> list[str]:
        recommendations = []
        if errors:
            recommendations.append("Review scanner errors first; missing tools or failed commands can hide findings.")
        if any(v.get("risk_score", 0) >= 7 for v in vulns):
            recommendations.append("Prioritize validated high-risk findings and collect remediation evidence.")
        if observations:
            recommendations.append("Review exposed services and confirm each one is expected for the target asset.")
        if not vulns and not observations and not errors:
            recommendations.append("No structured vulnerabilities were found in this result; verify scan coverage before closing the assessment.")
        if not recommendations:
            recommendations.append("Document the result and validate it against the authorized test scope.")
        return recommendations
