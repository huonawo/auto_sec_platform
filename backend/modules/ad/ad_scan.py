import re
import subprocess


def _validate_domain(target: str) -> str:
    """Validate target is a plausible domain name."""
    target = target.strip()
    domain_re = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)+$")
    if not domain_re.match(target):
        raise ValueError(f"invalid domain name: {target}")
    return target


class ADScanner:
    def __init__(self, target: str):
        self.target = _validate_domain(target)

    def run(self, options: dict = None) -> dict:
        options = options or {}
        results = {"target": self.target, "domain_info": {}, "warnings": []}

        if not options.get("authorized"):
            results["warnings"].append(
                "AD scan requires options.authorized=True. "
                "Set authorized flag to confirm you have permission to scan this domain."
            )
            return results

        # BloodHound collection still requires the authorization gate above.
        collections = options.get("bloodhound_collections", "all")
        try:
            bh_result = subprocess.run(
                ["bloodhound-python", "-d", self.target, "-c", collections, "--zip"],
                capture_output=True, text=True, timeout=600,
            )
            if bh_result.returncode != 0:
                results["bloodhound_error"] = f"exit code {bh_result.returncode}: {bh_result.stderr.strip()}"
            else:
                results["bloodhound_output"] = bh_result.stdout
        except Exception as e:
            results["bloodhound_error"] = str(e)

        # Credential dumping is high-risk and stays disabled unless explicitly allowed.
        if options.get("enable_secretsdump"):
            if not options.get("allow_credential_dump"):
                results["warnings"].append(
                    "Credential dump requested but skipped. Set allow_credential_dump=True "
                    "only in a fully authorized lab or assessment scope."
                )
                return results

            try:
                impacket_result = subprocess.run(
                    ["secretsdump.py", f"anonymous@{self.target}"],
                    capture_output=True, text=True, timeout=300,
                )
                if impacket_result.returncode != 0:
                    results["impacket_error"] = f"exit code {impacket_result.returncode}: {impacket_result.stderr.strip()}"
                else:
                    results["impacket_output"] = impacket_result.stdout
            except Exception as e:
                results["impacket_error"] = str(e)

        return results
