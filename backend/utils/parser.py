import re


def validate_target(target: str) -> str:
    """Validate that target is a URL or IP/CIDR. Raises ValueError if invalid."""
    target = target.strip()
    if not target:
        raise ValueError("target must not be empty")

    ip_re = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?$")
    url_re = re.compile(r"^(?:https?://)?[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+$")

    if ip_re.match(target):
        octets = target.split("/")[0].split(".")
        for o in octets:
            if int(o) > 255:
                raise ValueError(f"invalid IP octet: {o}")
        return target

    if url_re.match(target):
        return target

    raise ValueError(
        "target must be a valid URL (http(s)://...) or IP/CIDR (e.g. 192.168.1.0/24)"
    )
