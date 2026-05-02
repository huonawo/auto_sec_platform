import base64
import re
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urljoin, urlparse


OUTPUT_LIMIT = 20000
BODY_SNIPPET_LIMIT = 5000
PROBE_PATHS = ("/robots.txt", "/.git/HEAD", "/.env", "/backup.zip")
_BASE64_RE = re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}\b")
_HEX_RE = re.compile(r"\b(?:0x)?[0-9a-fA-F]{16,}\b")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b")
_INTERESTING_RE = re.compile(
    r"(flag|ctf|secret|token|key|password|admin|debug|backup|hidden)",
    re.IGNORECASE,
)
_ERROR_PATTERNS = {
    "mysql": re.compile(r"(mysql|mysqli|sql syntax|pdoexception)", re.IGNORECASE),
    "php": re.compile(r"(php warning|php fatal|stack trace|include\(|require\()", re.IGNORECASE),
    "python": re.compile(r"(python|django|flask|werkzeug)", re.IGNORECASE),
    "traceback": re.compile(r"(traceback \(most recent call last\)|exception|stacktrace)", re.IGNORECASE),
}


def _bounded(text: str, limit: int = 500) -> str:
    text = " ".join(str(text or "").split())
    return text[:limit]


def _dedupe(items: list) -> list:
    seen = set()
    result = []
    for item in items:
        marker = repr(item)
        if marker in seen:
            continue
        seen.add(marker)
        result.append(item)
    return result


class _ContextHTMLParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.title = ""
        self._in_title = False
        self.links = []
        self.scripts = []
        self.comments = []
        self.forms = []
        self.hidden_fields = []
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        attrs_dict = {name.lower(): value or "" for name, value in attrs}
        tag = tag.lower()
        if tag == "title":
            self._in_title = True
        elif tag == "a" and attrs_dict.get("href"):
            self.links.append(urljoin(self.base_url, attrs_dict["href"]))
        elif tag == "script" and attrs_dict.get("src"):
            self.scripts.append(urljoin(self.base_url, attrs_dict["src"]))
        elif tag == "form":
            self._current_form = {
                "action": urljoin(self.base_url, attrs_dict.get("action", "")),
                "method": attrs_dict.get("method", "get").upper(),
                "inputs": [],
                "hidden_inputs": [],
            }
            self.forms.append(self._current_form)
        elif tag == "input" and self._current_form is not None:
            input_info = {
                "name": attrs_dict.get("name", ""),
                "type": attrs_dict.get("type", "text"),
                "value": attrs_dict.get("value", ""),
            }
            self._current_form["inputs"].append(input_info)
            if input_info["type"].lower() == "hidden":
                hidden = {"name": input_info["name"], "value": input_info["value"]}
                self._current_form["hidden_inputs"].append(hidden)
                self.hidden_fields.append(hidden)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "title":
            self._in_title = False
        elif tag == "form":
            self._current_form = None

    def handle_data(self, data):
        if self._in_title:
            self.title += data.strip()

    def handle_comment(self, data):
        comment = _bounded(data)
        if comment:
            self.comments.append(comment)


def parse_cookies(headers: dict) -> list[dict]:
    raw_cookie = ""
    for key, value in (headers or {}).items():
        if str(key).lower() == "set-cookie":
            raw_cookie = str(value)
            break
    if not raw_cookie:
        return []
    cookie = SimpleCookie()
    try:
        cookie.load(raw_cookie)
    except Exception:
        return []
    return [{"name": morsel.key, "value": morsel.value} for morsel in cookie.values()]


def extract_interesting_strings(body: str) -> list[dict]:
    results = []
    body = body or ""
    for match in _BASE64_RE.finditer(body):
        candidate = match.group(0)
        try:
            padded = candidate + ("=" * (-len(candidate) % 4))
            decoded = base64.b64decode(padded, validate=False).decode("utf-8")
        except Exception:
            continue
        if decoded.isprintable() and len(decoded.strip()) >= 4:
            results.append({"type": "base64", "value": candidate, "decoded": _bounded(decoded)})
    for line in body.splitlines():
        if _INTERESTING_RE.search(line):
            results.append({"type": "keyword", "value": _bounded(line)})
    return _dedupe(results)[:50]


def extract_base64_candidates(body: str) -> list[dict]:
    candidates = []
    for match in _BASE64_RE.finditer(body or ""):
        value = match.group(0)
        item = {"value": value}
        try:
            padded = value + ("=" * (-len(value) % 4))
            decoded = base64.b64decode(padded, validate=False).decode("utf-8")
            if decoded.isprintable():
                item["decoded"] = _bounded(decoded)
        except Exception:
            pass
        candidates.append(item)
    return _dedupe(candidates)[:50]


def extract_hex_candidates(body: str) -> list[str]:
    return _dedupe([match.group(0) for match in _HEX_RE.finditer(body or "")])[:50]


def extract_jwt_candidates(body: str) -> list[str]:
    return _dedupe([match.group(0) for match in _JWT_RE.finditer(body or "")])[:25]


def extract_error_patterns(body: str) -> list[str]:
    return [name for name, pattern in _ERROR_PATTERNS.items() if pattern.search(body or "")]


def extract_url_params(*urls: str) -> dict[str, list[str]]:
    params: dict[str, list[str]] = {}
    for url in urls:
        parsed = parse_qs(urlparse(str(url or "")).query, keep_blank_values=True)
        for key, values in parsed.items():
            params.setdefault(key, [])
            for value in values:
                if value not in params[key]:
                    params[key].append(value)
    return params


def build_web_context(
    *,
    target: str,
    final_url: str | None = None,
    status_code: int | None = None,
    headers: dict | None = None,
    body: str = "",
    errors: list[str] | None = None,
    warnings: list[str] | None = None,
    technologies: list[str] | None = None,
    redirects: list[str] | None = None,
) -> dict:
    base_url = final_url or target
    parser = _ContextHTMLParser(base_url)
    warning_items = list(warnings or [])
    try:
        parser.feed(body or "")
    except Exception as exc:
        warning_items.append(f"HTML parse warning: {exc}")

    return {
        "target": target,
        "final_url": final_url or target,
        "status_code": status_code,
        "status": status_code,
        "title": _bounded(parser.title, 200),
        "body": (body or "")[:BODY_SNIPPET_LIMIT],
        "headers": dict(headers or {}),
        "cookies": parse_cookies(headers or {}),
        "redirects": _dedupe(list(redirects or [])),
        "redirect_chain": _dedupe(list(redirects or [])),
        "technologies": _dedupe(list(technologies or [])),
        "links": _dedupe(parser.links)[:100],
        "forms": parser.forms[:25],
        "hidden_fields": _dedupe(parser.hidden_fields)[:50],
        "scripts": _dedupe(parser.scripts)[:100],
        "comments": _dedupe(parser.comments)[:50],
        "html_comments": _dedupe(parser.comments)[:50],
        "url_params": extract_url_params(target, final_url or target, *parser.links, *(form["action"] for form in parser.forms)),
        "base64_candidates": extract_base64_candidates(body),
        "hex_candidates": extract_hex_candidates(body),
        "jwt_candidates": extract_jwt_candidates(body),
        "error_patterns": extract_error_patterns(body),
        "server": dict(headers or {}).get("Server", ""),
        "x-powered-by": dict(headers or {}).get("X-Powered-By", ""),
        "fingerprint": {
            "server": dict(headers or {}).get("Server", ""),
            "x-powered-by": dict(headers or {}).get("X-Powered-By", ""),
        },
        "path_probes": {},
        "interesting_strings": extract_interesting_strings(body),
        "errors": list(errors or []),
        "warnings": warning_items,
    }


def context_from_httpx_record(target: str, record: dict) -> dict:
    technologies = record.get("tech") or record.get("technologies") or []
    if isinstance(technologies, str):
        technologies = [technologies]
    headers = record.get("headers") if isinstance(record.get("headers"), dict) else {}
    if record.get("webserver"):
        headers = {**headers, "Server": record.get("webserver")}
    context = build_web_context(
        target=target,
        final_url=record.get("final_url") or record.get("url") or target,
        status_code=record.get("status_code"),
        headers=headers,
        body=record.get("body", ""),
        technologies=technologies,
        redirects=record.get("chain") if isinstance(record.get("chain"), list) else [],
    )
    if record.get("title"):
        context["title"] = record.get("title")
    return context


def _response_url(response) -> str:
    return str(getattr(response, "url", ""))


def _response_headers(response) -> dict:
    return dict(getattr(response, "headers", {}) or {})


def _history_urls(response) -> list[str]:
    urls = []
    for item in getattr(response, "history", []) or []:
        url = _response_url(item)
        if url:
            urls.append(url)
    return urls


def _probe_paths(target: str, client) -> dict:
    probes = {}
    for path in PROBE_PATHS:
        url = urljoin(target.rstrip("/") + "/", path.lstrip("/"))
        try:
            response = client.head(url)
            probes[path] = {
                "url": url,
                "status": getattr(response, "status_code", None),
                "headers": _response_headers(response),
            }
        except Exception as exc:
            probes[path] = {"url": url, "status": None, "headers": {}, "error": str(exc)}
    return probes


def run_full_recon(target: str, client=None) -> dict:
    """Run low-intrusion web CTF reconnaissance and return structured signals."""
    owns_client = client is None
    if client is None:
        import httpx

        client = httpx.Client(follow_redirects=True, verify=False, timeout=15)
    try:
        response = client.get(target)
        headers = _response_headers(response)
        body = (getattr(response, "text", "") or "")[:OUTPUT_LIMIT]
        context = build_web_context(
            target=target,
            final_url=_response_url(response) or target,
            status_code=getattr(response, "status_code", None),
            headers=headers,
            body=body,
            redirects=_history_urls(response),
        )
        context["path_probes"] = _probe_paths(context["final_url"], client)
        return context
    except Exception as exc:
        context = build_web_context(target=target, errors=[f"full recon failed: {exc}"])
        context["path_probes"] = {}
        return context
    finally:
        if owns_client and hasattr(client, "close"):
            client.close()
