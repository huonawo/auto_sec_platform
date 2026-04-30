def normalize_scan_options(options: dict | None = None) -> dict:
    """Apply conservative defaults to every scanner invocation."""
    normalized = dict(options or {}) if isinstance(options, dict) else {}
    normalized.setdefault("authorized", False)
    normalized.setdefault("safe_mode", True)
    normalized.setdefault("allow_credential_dump", False)
    return normalized
