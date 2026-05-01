import json

from ai.model.risk_score import RiskScorer
from ai.model.vuln_classifier import VulnClassifier
from ai.model.path_planner import PathPlanner
from ai.llm_client import LLMClient


class AIAnalyzer:
    def __init__(self, model: str = "default"):
        self.model = model
        self.risk_scorer = RiskScorer()
        self.classifier = VulnClassifier()
        self.path_planner = PathPlanner()
        self.llm = LLMClient()

    def analyze(self, scan_data: dict) -> dict:
        vulns = self._extract_vulnerabilities(scan_data)

        classified = []
        for vuln in vulns:
            c = self.classifier.classify(vuln)
            score = self.risk_scorer.score(vuln)
            classified.append({**vuln, "classification": c, "risk_score": score})

        attack_paths = self.path_planner.plan(classified)

        summary = {
            "total": len(classified),
            "critical": sum(1 for v in classified if v.get("risk_score", 0) >= 9),
            "high": sum(1 for v in classified if 7 <= v.get("risk_score", 0) < 9),
            "medium": sum(1 for v in classified if 4 <= v.get("risk_score", 0) < 7),
            "low": sum(1 for v in classified if v.get("risk_score", 0) < 4),
        }

        result = {
            "vulnerabilities": classified,
            "attack_paths": attack_paths,
            "summary": summary,
        }

        # LLM enrichment (graceful fallback if unavailable)
        if self.llm.available:
            result["vulnerabilities"] = self._llm_vuln_descriptions(classified)
            result["attack_paths"] = self._llm_attack_path_explanation(attack_paths, classified)
            result["llm_report"] = self._llm_risk_report(scan_data, classified, attack_paths, summary)
            result["llm_enabled"] = True
        else:
            result["llm_enabled"] = False

        return result

    def _extract_vulnerabilities(self, scan_data: dict) -> list[dict]:
        vulns = []
        findings = scan_data.get("findings", scan_data.get("result", {}).get("findings", []))
        for f in findings:
            vulns.append({
                "vuln_id": f.get("template-id", f.get("vuln_id", "unknown")),
                "type": f.get("type", f.get("info", {}).get("type", "unknown")),
                "name": f.get("info", {}).get("name", f.get("name", "")),
                "severity": f.get("info", {}).get("severity", f.get("severity", "info")),
                "description": f.get("info", {}).get("description", ""),
                "matched_at": f.get("matched-at", f.get("host", "")),
            })
        return vulns

    def _llm_vuln_descriptions(self, vulns: list[dict]) -> list[dict]:
        system = (
            "You are a senior penetration tester. For each vulnerability, provide:\n"
            "1. A clear description of what the vulnerability is and its potential impact\n"
            "2. A specific remediation recommendation\n"
            "Respond in JSON format: {\"descriptions\": [{\"vuln_id\": \"...\", \"description\": \"...\", \"remediation\": \"...\"}]}"
        )

        vuln_summary = []
        for v in vulns:
            vuln_summary.append({
                "vuln_id": v.get("vuln_id"),
                "name": v.get("name"),
                "type": v.get("type"),
                "severity": v.get("severity"),
                "matched_at": v.get("matched_at"),
                "existing_description": v.get("description", ""),
            })

        user = f"Analyze these vulnerabilities:\n{json.dumps(vuln_summary, ensure_ascii=False, indent=2)}"

        response = self.llm.chat(system, user)
        if not response:
            return vulns

        try:
            parsed = json.loads(response)
            desc_map = {d["vuln_id"]: d for d in parsed.get("descriptions", [])}
            for vuln in vulns:
                match = desc_map.get(vuln["vuln_id"])
                if match:
                    vuln["llm_description"] = match.get("description", "")
                    vuln["llm_remediation"] = match.get("remediation", "")
        except (json.JSONDecodeError, KeyError):
            for vuln in vulns:
                vuln["llm_description"] = ""
                vuln["llm_remediation"] = ""

        return vulns

    def _llm_attack_path_explanation(self, attack_paths: list[dict], vulns: list[dict]) -> list[dict]:
        if not attack_paths:
            return attack_paths

        system = (
            "You are a red team operator. Explain each attack path in natural language: "
            "what an attacker would do step by step, why this path is dangerous, and what assets are at risk. "
            "Respond in JSON format: {\"explanations\": [{\"path_id\": \"...\", \"explanation\": \"...\"}]}"
        )

        path_summary = []
        for p in attack_paths:
            path_summary.append({
                "path_id": p.get("path_id"),
                "name": p.get("name"),
                "priority": p.get("priority"),
                "steps": p.get("steps"),
            })

        user = f"Explain these attack paths:\n{json.dumps(path_summary, ensure_ascii=False, indent=2)}"

        response = self.llm.chat(system, user)
        if not response:
            return attack_paths

        try:
            parsed = json.loads(response)
            exp_map = {e["path_id"]: e for e in parsed.get("explanations", [])}
            for path in attack_paths:
                match = exp_map.get(path["path_id"])
                if match:
                    path["llm_explanation"] = match.get("explanation", "")
        except (json.JSONDecodeError, KeyError):
            for path in attack_paths:
                path["llm_explanation"] = ""

        return attack_paths

    def _llm_risk_report(self, scan_data: dict, vulns: list[dict], attack_paths: list[dict], summary: dict) -> str:
        system = (
            "You are a cybersecurity risk analyst. Generate a comprehensive risk assessment report in markdown format. "
            "Include:\n"
            "1. Executive Summary\n"
            "2. Overall Risk Level (Critical/High/Medium/Low)\n"
            "3. Top Concerns (the most dangerous findings)\n"
            "4. Attack Path Analysis (how an attacker could chain vulnerabilities)\n"
            "5. Prioritized Remediation Recommendations\n"
            "6. Conclusion\n"
            "Be concise but thorough. Use Chinese for the report."
        )

        vuln_brief = [{
            "name": v.get("name"),
            "severity": v.get("severity"),
            "risk_score": v.get("risk_score"),
            "classification": v.get("classification"),
            "matched_at": v.get("matched_at"),
        } for v in vulns]

        path_brief = [{
            "name": p.get("name"),
            "priority": p.get("priority"),
            "steps": p.get("steps"),
        } for p in attack_paths]

        user = (
            f"Target: {scan_data.get('target', 'unknown')}\n\n"
            f"Summary: {json.dumps(summary)}\n\n"
            f"Vulnerabilities:\n{json.dumps(vuln_brief, ensure_ascii=False, indent=2)}\n\n"
            f"Attack Paths:\n{json.dumps(path_brief, ensure_ascii=False, indent=2)}"
        )

        return self.llm.chat(system, user) or ""
