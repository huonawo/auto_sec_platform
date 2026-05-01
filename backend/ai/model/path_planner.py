import uuid


class PathPlanner:
    def plan(self, vulns: list[dict]) -> list[dict]:
        if not vulns:
            return []

        paths = []
        critical = [v for v in vulns if v.get("risk_score", 0) >= 9]
        high = [v for v in vulns if 7 <= v.get("risk_score", 0) < 9]

        # 优先攻击路径：critical → high → medium
        if critical:
            paths.append({
                "path_id": f"path-{uuid.uuid4().hex[:8]}",
                "name": "Critical Exploitation Chain",
                "steps": [
                    {"step": 1, "action": "recon", "description": "Port and service enumeration"},
                    {"step": 2, "action": "exploit", "description": f"Exploit {critical[0].get('name', 'critical vuln')}", "target": critical[0].get("matched_at", "")},
                    {"step": 3, "action": "post-exploit", "description": "Establish persistence"},
                ],
                "priority": "critical",
            })

        if high:
            paths.append({
                "path_id": f"path-{uuid.uuid4().hex[:8]}",
                "name": "High Severity Attack Path",
                "steps": [
                    {"step": 1, "action": "scan", "description": "Identify high-severity services"},
                    {"step": 2, "action": "exploit", "description": f"Exploit {high[0].get('name', 'high vuln')}", "target": high[0].get("matched_at", "")},
                ],
                "priority": "high",
            })

        # 通用路径
        paths.append({
            "path_id": f"path-{uuid.uuid4().hex[:8]}",
            "name": "General Reconnaissance",
            "steps": [
                {"step": 1, "action": "enum", "description": "Full port scan"},
                {"step": 2, "action": "vuln-scan", "description": "Run vulnerability templates"},
            ],
            "priority": "medium",
        })

        return paths
