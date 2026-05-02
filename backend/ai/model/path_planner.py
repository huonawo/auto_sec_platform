import uuid


class PathPlanner:
    def plan(self, vulns: list[dict]) -> list[dict]:
        if not vulns:
            return []

        paths = []
        critical = [v for v in vulns if v.get("risk_score", 0) >= 9]
        high = [v for v in vulns if 7 <= v.get("risk_score", 0) < 9]

        # This is a defensive validation workflow, not an exploitation runner.
        if critical:
            paths.append({
                "path_id": f"path-{uuid.uuid4().hex[:8]}",
                "name": "Critical Validation Workflow",
                "steps": [
                    {"step": 1, "action": "confirm-scope", "description": "Confirm the asset is in the authorized test scope"},
                    {"step": 2, "action": "validate", "description": f"Safely validate {critical[0].get('name', 'critical finding')}", "target": critical[0].get("matched_at", "")},
                    {"step": 3, "action": "remediate", "description": "Document impact and remediation guidance"},
                ],
                "priority": "critical",
            })

        if high:
            paths.append({
                "path_id": f"path-{uuid.uuid4().hex[:8]}",
                "name": "High Severity Validation Workflow",
                "steps": [
                    {"step": 1, "action": "triage", "description": "Confirm affected service and evidence"},
                    {"step": 2, "action": "validate", "description": f"Safely validate {high[0].get('name', 'high finding')}", "target": high[0].get("matched_at", "")},
                ],
                "priority": "high",
            })

        paths.append({
            "path_id": f"path-{uuid.uuid4().hex[:8]}",
            "name": "General Review Workflow",
            "steps": [
                {"step": 1, "action": "review", "description": "Review collected evidence and scanner coverage"},
                {"step": 2, "action": "report", "description": "Prepare findings and remediation notes"},
            ],
            "priority": "medium",
        })

        return paths
