"""Challenge type classifier for CTF web challenges.

Analyzes web_context (from web_recon) and challenge description
to detect the likely vulnerability category and generate a playbook.
"""
import re
from dataclasses import dataclass, field


@dataclass
class ChallengeSignal:
    """Accumulated signals for classification."""
    headers: dict = field(default_factory=dict)
    cookies: list = field(default_factory=list)
    comments: list = field(default_factory=list)
    forms: list = field(default_factory=list)
    hidden_fields: list = field(default_factory=list)
    error_patterns: list = field(default_factory=list)
    base64_candidates: list = field(default_factory=list)
    jwt_candidates: list = field(default_factory=list)
    technologies: list = field(default_factory=list)
    title: str = ""
    body_snippet: str = ""
    description: str = ""
    url_params: dict = field(default_factory=dict)


# Pattern → (category, confidence_boost, playbook_hint)
_CATEGORY_SIGNALS = [
    # SSTI
    (r"\{\{.*?\}\}", "ssti", 0.3, "Template injection probe: {{7*7}}, {{config}}"),
    (r"jinja|twig|erb|mako|ejs|smarty|vue", "ssti", 0.2, "Template engine detected — test SSTI"),
    # SQLi
    (r"mysql|mysqli|sql syntax|pdoexception|sqlite|postgresql", "sqli", 0.3, "SQL error detected — test UNION/blind SQLi"),
    (r"(?:query|search|id|user|page|item)=\d+", "sqli", 0.1, "URL parameter with numeric value — test SQLi"),
    # XSS
    (r"<script>|alert\(|onerror=|onload=", "xss", 0.2, "Script/HTML reflected — test XSS"),
    # LFI / Path Traversal
    (r"\.\./|\.\.\\|php://filter|file://|/etc/passwd", "lfi", 0.3, "Path traversal pattern — test LFI"),
    (r"include\(|require\(|file_get_contents", "lfi", 0.2, "PHP file inclusion — test LFI/RFI"),
    # SSRF
    (r"169\.254\.169\.254|127\.0\.0\.1|localhost|gopher://|dict://", "ssrf", 0.3, "SSRF pattern — test internal access"),
    (r"url=|uri=|redirect=|proxy=|fetch=", "ssrf", 0.1, "URL parameter — test SSRF"),
    # JWT
    (r"eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", "jwt", 0.4, "JWT token found — decode and test forgery"),
    (r"jsonwebtoken|jwt|bearer|authorization", "jwt", 0.2, "JWT/bearer auth — test token manipulation"),
    # Cookie forgery / session
    (r"flask|werkzeug|session=|signed cookie", "cookie_forgery", 0.3, "Flask/signed cookie — test forgery"),
    (r"role=|admin=|user=|is_admin|authenticated", "cookie_forgery", 0.2, "Session cookie with roles — test manipulation"),
    # Header injection
    (r"x-forwarded-for|x-real-ip|x-forwarded-host|host.*inject", "header_injection", 0.3, "Header injection — test X-Forwarded-For/Host"),
    # Command injection
    (r"system\(|exec\(|passthru|shell_exec|popen|`.*`", "command_inject", 0.3, "Command execution — test command injection"),
    # Deserialization
    (r"pickle|marshal|unserialize|yaml\.load|deserializ", "deserializ", 0.3, "Deserialization — test crafted objects"),
    # Base64
    (r"base64|编码|encode|decode", "base64", 0.2, "Base64 theme — decode all candidates"),
]


def _score_signals(signal: ChallengeSignal) -> dict[str, float]:
    """Score each category based on accumulated signals."""
    scores: dict[str, float] = {}

    # Combine all text sources for pattern matching
    text_pool = " ".join([
        signal.title,
        signal.description,
        signal.body_snippet[:3000],
        " ".join(signal.error_patterns),
        " ".join(signal.technologies),
        " ".join(str(c) for c in signal.comments[:10]),
        " ".join(str(f) for f in signal.forms[:5]),
        " ".join(f"{k}={v}" for k, v in list(signal.url_params.items())[:10]),
        " ".join(signal.jwt_candidates),
        " ".join(c.get("name", "") for c in signal.cookies),
        " ".join(f.get("name", "") for f in signal.hidden_fields),
    ]).lower()

    for pattern, category, boost, _hint in _CATEGORY_SIGNALS:
        if re.search(pattern, text_pool, re.IGNORECASE):
            scores[category] = scores.get(category, 0) + boost

    # Boost based on structural signals
    if signal.comments:
        # HTML comments often contain clues
        scores["source_leak"] = scores.get("source_leak", 0) + 0.1
    if signal.hidden_fields:
        scores["auth_bypass"] = scores.get("auth_bypass", 0) + 0.1
    if signal.forms:
        scores["sqli"] = scores.get("sqli", 0) + 0.05
        scores["xss"] = scores.get("xss", 0) + 0.05
    if signal.base64_candidates:
        scores["base64"] = scores.get("base64", 0) + 0.15
    if signal.jwt_candidates:
        scores["jwt"] = scores.get("jwt", 0) + 0.3

    return scores


def _build_playbook(category: str, scores: dict[str, float]) -> list[str]:
    """Generate ordered attack steps for the detected category."""
    playbook = []
    for _pattern, cat, _boost, hint in _CATEGORY_SIGNALS:
        if cat == category and hint:
            playbook.append(hint)
            break

    # Add cross-cutting hints from secondary categories
    sorted_cats = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    for cat, score in sorted_cats[1:4]:  # top 3 secondary
        if score >= 0.2:
            for _pattern, c, _boost, hint in _CATEGORY_SIGNALS:
                if c == cat and hint:
                    playbook.append(f"[secondary:{cat}] {hint}")
                    break

    # Universal first steps
    playbook.insert(0, "Read HTML source, comments, scripts, and hidden fields")
    playbook.insert(1, "Check response headers for Server, X-Powered-By, Set-Cookie")

    return playbook[:8]


def fallback_classification() -> dict:
    """Default classification when web recon fails."""
    return {
        "category": "unknown",
        "confidence": 0.0,
        "playbook": [
            "Read HTML source, comments, scripts, and hidden fields",
            "Check response headers for Server, X-Powered-By, Set-Cookie",
            "Try basic probes: robots.txt, .git/HEAD, .env",
            "Test common URL parameters for injection",
        ],
        "secondary_categories": [],
        "signals": {},
    }


class CTFClassifier:
    """Classifies CTF web challenges by analyzing web recon context."""

    def classify(self, web_context: dict, description: str = "") -> dict:
        """Classify challenge from web recon context and description."""
        if not web_context:
            return fallback_classification()

        signal = ChallengeSignal(
            headers=web_context.get("headers", {}),
            cookies=web_context.get("cookies", []),
            comments=web_context.get("comments", []) or web_context.get("html_comments", []),
            forms=web_context.get("forms", []),
            hidden_fields=web_context.get("hidden_fields", []),
            error_patterns=web_context.get("error_patterns", []),
            base64_candidates=[
                c.get("value", "") for c in web_context.get("base64_candidates", [])
            ],
            jwt_candidates=web_context.get("jwt_candidates", []),
            technologies=web_context.get("technologies", []),
            title=web_context.get("title", ""),
            body_snippet=web_context.get("body", "")[:3000],
            description=description,
            url_params=web_context.get("url_params", {}),
        )

        scores = _score_signals(signal)

        if not scores:
            return fallback_classification()

        # Primary category = highest score
        primary = max(scores, key=scores.get)
        confidence = min(scores[primary], 1.0)

        # Secondary categories
        secondary = [
            {"category": cat, "score": round(score, 2)}
            for cat, score in sorted(scores.items(), key=lambda x: x[1], reverse=True)
            if cat != primary and score >= 0.15
        ][:3]

        playbook = _build_playbook(primary, scores)

        return {
            "category": primary,
            "confidence": round(confidence, 2),
            "playbook": playbook,
            "secondary_categories": secondary,
            "signals": {cat: round(score, 2) for cat, score in scores.items()},
        }
