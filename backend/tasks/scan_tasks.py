import os

from celery import Celery
from utils.results import (
    ensure_output_dir,
    now_iso,
    read_result_file,
    resolve_result_path,
    save_result_record,
)
from utils.safety import normalize_scan_options

REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD")
if not REDIS_PASSWORD:
    raise RuntimeError("REDIS_PASSWORD environment variable is required")

celery_app = Celery(
    "autosec",
    broker=f"redis://:{REDIS_PASSWORD}@redis:6379/0",
    backend=f"redis://:{REDIS_PASSWORD}@redis:6379/1",
)

OUTPUT_DIR = str(ensure_output_dir())


def _task_id(task_self) -> str:
    return getattr(getattr(task_self, "request", None), "id", None)


def _run_scanner(task_self, scan_type: str, target: str, scanner_cls, options: dict = None):
    started_at = now_iso()
    safe_options = normalize_scan_options(options)
    errors = []
    status = "completed"
    try:
        scanner = scanner_cls(target)
        result = scanner.run(safe_options)
    except Exception as exc:
        result = {}
        status = "failed"
        errors.append(str(exc))

    path = save_result_record(
        scan_type,
        target=target,
        result=result,
        status=status,
        task_id=_task_id(task_self),
        started_at=started_at,
        completed_at=now_iso(),
        errors=errors,
    )
    return {
        "status": status,
        "output_file": path,
        "filename": os.path.basename(path),
        "errors": errors,
    }


# ── Scan Tasks ──────────────────────────────────────────────────────────────────

@celery_app.task(bind=True)
def run_web_scan(self, target: str, options: dict = None):
    from modules.webscan.webscan import WebScanner
    return _run_scanner(self, "web", target, WebScanner, options)


@celery_app.task(bind=True)
def run_cve_scan(self, target: str, options: dict = None):
    from modules.cve.cve_scan import CVEScanner
    return _run_scanner(self, "cve", target, CVEScanner, options)


@celery_app.task(bind=True)
def run_intranet_scan(self, target: str, options: dict = None):
    from modules.intranet.intranet_scan import IntranetScanner
    return _run_scanner(self, "intranet", target, IntranetScanner, options)


@celery_app.task(bind=True)
def run_ad_scan(self, target: str, options: dict = None):
    from modules.ad.ad_scan import ADScanner
    return _run_scanner(self, "ad", target, ADScanner, options)


# ── Recon & Persistence Tasks ───────────────────────────────────────────────────

@celery_app.task(bind=True)
def run_recon_scan(self, target: str, options: dict = None):
    from modules.recon.recon import ReconScanner
    return _run_scanner(self, "recon", target, ReconScanner, options)


@celery_app.task(bind=True)
def run_persistence_scan(self, target: str, options: dict = None):
    from modules.persistence.persistence import PersistenceScanner
    return _run_scanner(self, "persistence", target, PersistenceScanner, options)


# ── AI Analysis Task ────────────────────────────────────────────────────────────

@celery_app.task(bind=True)
def run_ai_analysis(self, file_path: str, model: str = "default"):
    from ai.ai_analysis import AIAnalyzer

    real_path = resolve_result_path(file_path)
    analyzer = AIAnalyzer(model)
    scan_data = read_result_file(str(real_path))
    result = analyzer.analyze(scan_data)
    path = save_result_record(
        "ai_analysis",
        target=scan_data.get("target", real_path.name),
        result={"source_file": real_path.name},
        status="completed",
        task_id=_task_id(self),
        started_at=now_iso(),
        completed_at=now_iso(),
        source_file=real_path.name,
        analysis=result,
    )
    return {"status": "completed", "output_file": path, "filename": os.path.basename(path)}
