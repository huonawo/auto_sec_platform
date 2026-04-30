import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_OUTPUT_DIR = "/workspace/output"


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def get_output_dir() -> Path:
    return Path(os.environ.get("AUTOSEC_OUTPUT_DIR", DEFAULT_OUTPUT_DIR)).resolve()


def ensure_output_dir() -> Path:
    output_dir = get_output_dir()
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def resolve_result_path(identifier: str) -> Path:
    if not identifier or not str(identifier).strip():
        raise ValueError("result file identifier is required")

    value = str(identifier).strip()
    output_dir = ensure_output_dir()
    candidate = Path(value)

    if candidate.is_absolute():
        resolved = candidate.resolve()
    else:
        if "/" in value or "\\" in value or Path(value).name != value:
            raise ValueError("result filename must not include path separators")
        resolved = (output_dir / value).resolve()

    try:
        resolved.relative_to(output_dir)
    except ValueError as exc:
        raise ValueError("result file must be within the output directory") from exc

    return resolved


def _safe_prefix(scan_type: str) -> str:
    return "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in scan_type)


def _collect_messages(payload: Any, suffix: str) -> list[str]:
    messages: list[str] = []
    if isinstance(payload, dict):
        for key, value in payload.items():
            key_lower = str(key).lower()
            if key_lower == suffix and isinstance(value, list):
                messages.extend(str(item) for item in value if item)
            elif key_lower == suffix and value:
                messages.append(str(value))
            elif key_lower.endswith(f"_{suffix[:-1]}") and value:
                messages.append(f"{key}: {value}")
            elif isinstance(value, (dict, list)):
                messages.extend(_collect_messages(value, suffix))
    elif isinstance(payload, list):
        for item in payload:
            messages.extend(_collect_messages(item, suffix))
    return messages


def collect_errors(payload: Any) -> list[str]:
    return _collect_messages(payload, "errors")


def collect_warnings(payload: Any) -> list[str]:
    return _collect_messages(payload, "warnings")


def build_result_record(
    scan_type: str,
    *,
    target: str,
    result: dict | None = None,
    status: str = "completed",
    task_id: str | None = None,
    started_at: str | None = None,
    completed_at: str | None = None,
    source_file: str | None = None,
    analysis: dict | None = None,
    errors: list[str] | None = None,
    warnings: list[str] | None = None,
) -> dict:
    payload = analysis if analysis is not None else result or {}
    record = {
        "target": target,
        "scan_type": scan_type,
        "status": status,
        "started_at": started_at or now_iso(),
        "completed_at": completed_at or now_iso(),
        "task_id": task_id,
        "output_file": None,
        "result": result or {},
        "errors": list(errors or []) + collect_errors(payload),
        "warnings": list(warnings or []) + collect_warnings(payload),
        "authorization_notice": "Use only for authorized security testing or lab environments.",
    }
    if source_file:
        record["source_file"] = source_file
    if analysis is not None:
        record["analysis"] = analysis
    return record


def save_result_record(
    scan_type: str,
    *,
    target: str,
    result: dict | None = None,
    status: str = "completed",
    task_id: str | None = None,
    started_at: str | None = None,
    completed_at: str | None = None,
    source_file: str | None = None,
    analysis: dict | None = None,
    errors: list[str] | None = None,
    warnings: list[str] | None = None,
) -> str:
    output_dir = ensure_output_dir()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    path = output_dir / f"{_safe_prefix(scan_type)}_{ts}.json"
    record = build_result_record(
        scan_type,
        target=target,
        result=result,
        status=status,
        task_id=task_id,
        started_at=started_at,
        completed_at=completed_at,
        source_file=source_file,
        analysis=analysis,
        errors=errors,
        warnings=warnings,
    )
    record["output_file"] = str(path)
    with path.open("w", encoding="utf-8") as f:
        json.dump(record, f, indent=2, ensure_ascii=False)
    return str(path)


def read_result_file(identifier: str) -> dict:
    path = resolve_result_path(identifier)
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def list_result_records(page: int = 1, limit: int = 20) -> list[dict]:
    output_dir = ensure_output_dir()
    files = sorted(
        (path for path in output_dir.iterdir() if path.suffix == ".json" and path.is_file()),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    start = max(page - 1, 0) * limit
    page_files = files[start : start + limit]

    records = []
    for path in page_files:
        try:
            data = read_result_file(path.name)
            records.append(
                {
                    "file": path.name,
                    "modified_at": datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds"),
                    "scan_type": data.get("scan_type", "unknown") if isinstance(data, dict) else "unknown",
                    "target": data.get("target", "") if isinstance(data, dict) else "",
                    "status": data.get("status", "unknown") if isinstance(data, dict) else "unknown",
                    "data": data,
                }
            )
        except Exception as exc:
            records.append(
                {
                    "file": path.name,
                    "modified_at": datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds"),
                    "scan_type": "unknown",
                    "target": "",
                    "status": "error",
                    "error": f"failed to parse: {exc}",
                }
            )
    return records


def count_result_files() -> int:
    output_dir = ensure_output_dir()
    return sum(1 for path in output_dir.iterdir() if path.suffix == ".json" and path.is_file())
