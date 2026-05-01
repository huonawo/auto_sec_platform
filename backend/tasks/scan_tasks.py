import json
import os
from datetime import datetime

from celery import Celery

REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD")
if not REDIS_PASSWORD:
    raise RuntimeError("REDIS_PASSWORD environment variable is required")

celery_app = Celery(
    "autosec",
    broker=f"redis://:{REDIS_PASSWORD}@redis:6379/0",
    backend=f"redis://:{REDIS_PASSWORD}@redis:6379/1",
)

OUTPUT_DIR = "/workspace/output"
os.makedirs(OUTPUT_DIR, exist_ok=True)


def _save_result(name: str, data: dict) -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(OUTPUT_DIR, f"{name}_{ts}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return path


# ── Scan Tasks ──────────────────────────────────────────────────────────────────

@celery_app.task(bind=True)
def run_web_scan(self, target: str, options: dict = None):
    from modules.webscan.webscan import WebScanner
    scanner = WebScanner(target)
    result = scanner.run(options or {})
    path = _save_result("web_scan", {"target": target, "scan_type": "web", "result": result})
    return {"status": "completed", "output_file": path}


@celery_app.task(bind=True)
def run_cve_scan(self, target: str, options: dict = None):
    from modules.cve.cve_scan import CVEScanner
    scanner = CVEScanner(target)
    result = scanner.run(options or {})
    path = _save_result("cve_scan", {"target": target, "scan_type": "cve", "result": result})
    return {"status": "completed", "output_file": path}


@celery_app.task(bind=True)
def run_intranet_scan(self, target: str, options: dict = None):
    from modules.intranet.intranet_scan import IntranetScanner
    scanner = IntranetScanner(target)
    result = scanner.run(options or {})
    path = _save_result("intranet_scan", {"target": target, "scan_type": "intranet", "result": result})
    return {"status": "completed", "output_file": path}


@celery_app.task(bind=True)
def run_ad_scan(self, target: str, options: dict = None):
    from modules.ad.ad_scan import ADScanner
    scanner = ADScanner(target)
    result = scanner.run(options or {})
    path = _save_result("ad_scan", {"target": target, "scan_type": "ad", "result": result})
    return {"status": "completed", "output_file": path}


# ── Recon & Persistence Tasks ───────────────────────────────────────────────────

@celery_app.task(bind=True)
def run_recon_scan(self, target: str, options: dict = None):
    from modules.recon.recon import ReconScanner
    scanner = ReconScanner(target)
    result = scanner.run(options or {})
    path = _save_result("recon_scan", {"target": target, "scan_type": "recon", "result": result})
    return {"status": "completed", "output_file": path}


@celery_app.task(bind=True)
def run_persistence_scan(self, target: str, options: dict = None):
    from modules.persistence.persistence import PersistenceScanner
    scanner = PersistenceScanner(target)
    result = scanner.run(options or {})
    path = _save_result("persistence_scan", {"target": target, "scan_type": "persistence", "result": result})
    return {"status": "completed", "output_file": path}


# ── AI Analysis Task ────────────────────────────────────────────────────────────

@celery_app.task(bind=True)
def run_ai_analysis(self, file_path: str, model: str = "default"):
    from ai.ai_analysis import AIAnalyzer

    real_path = os.path.realpath(file_path)
    real_output = os.path.realpath(OUTPUT_DIR)
    if not real_path.startswith(real_output + os.sep):
        raise ValueError("file_path must be within the output directory")

    analyzer = AIAnalyzer(model)
    with open(real_path, "r") as f:
        scan_data = json.load(f)
    result = analyzer.analyze(scan_data)
    path = _save_result("ai_analysis", {"source_file": file_path, "analysis": result})
    return {"status": "completed", "output_file": path}
