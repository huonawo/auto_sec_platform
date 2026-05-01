import os
import re

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator, model_validator
from typing import Optional

from utils.results import (
    count_result_files,
    get_output_dir,
    list_result_records,
    read_result_file,
    resolve_result_path,
)

OUTPUT_DIR = str(get_output_dir())

app = FastAPI(title="AutoSec Platform", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Target Validation ──────────────────────────────────────────────────────────

_TARGET_RE = re.compile(
    r"^(?:https?://)?"
    r"(?:[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+)$"
)

_IP_RE = re.compile(
    r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?$"
)


def _validate_target(v: str) -> str:
    v = v.strip()
    if not v:
        raise ValueError("target must not be empty")
    if _IP_RE.match(v):
        return v
    if _TARGET_RE.match(v):
        return v
    raise ValueError(
        "target must be a valid URL (http(s)://...) or IP/CIDR (e.g. 192.168.1.0/24)"
    )


# ── Request Models ──────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str
    scan_type: Optional[str] = "web"
    options: Optional[dict] = None

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        return _validate_target(v)


class AIAnalyzeRequest(BaseModel):
    file_path: Optional[str] = None
    filename: Optional[str] = None
    model: Optional[str] = "default"

    @model_validator(mode="after")
    def validate_source(self):
        identifier = self.filename or self.file_path
        if not identifier:
            raise ValueError("filename or file_path is required")
        resolve_result_path(identifier)
        return self


# ── Health Check ────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "ok", "service": "AutoSec Platform"}


@app.get("/health")
def health():
    return {"status": "healthy"}


# ── Scan Endpoints ──────────────────────────────────────────────────────────────

@app.post("/scan/web")
def scan_web(req: ScanRequest):
    from tasks.scan_tasks import run_web_scan
    task = run_web_scan.delay(req.target, req.options)
    return {"task_id": task.id, "status": "queued", "target": req.target}


@app.post("/scan/cve")
def scan_cve(req: ScanRequest):
    from tasks.scan_tasks import run_cve_scan
    task = run_cve_scan.delay(req.target, req.options)
    return {"task_id": task.id, "status": "queued", "target": req.target}


@app.post("/scan/intranet")
def scan_intranet(req: ScanRequest):
    from tasks.scan_tasks import run_intranet_scan
    task = run_intranet_scan.delay(req.target, req.options)
    return {"task_id": task.id, "status": "queued", "target": req.target}


@app.post("/scan/ad")
def scan_ad(req: ScanRequest):
    from tasks.scan_tasks import run_ad_scan
    task = run_ad_scan.delay(req.target, req.options)
    return {"task_id": task.id, "status": "queued", "target": req.target}


@app.post("/scan/recon")
def scan_recon(req: ScanRequest):
    from tasks.scan_tasks import run_recon_scan
    task = run_recon_scan.delay(req.target, req.options)
    return {"task_id": task.id, "status": "queued", "target": req.target}


@app.post("/scan/persistence")
def scan_persistence(req: ScanRequest):
    from tasks.scan_tasks import run_persistence_scan
    task = run_persistence_scan.delay(req.target, req.options)
    return {"task_id": task.id, "status": "queued", "target": req.target}


# ── AI Analysis Endpoints ───────────────────────────────────────────────────────

@app.post("/ai/analyze")
def ai_analyze(req: AIAnalyzeRequest):
    from tasks.scan_tasks import run_ai_analysis
    identifier = req.filename or req.file_path
    task = run_ai_analysis.delay(identifier, req.model)
    return {"task_id": task.id, "status": "queued", "file": os.path.basename(identifier)}


# ── Task Status ─────────────────────────────────────────────────────────────────

@app.get("/task/{task_id}")
def get_task_status(task_id: str):
    from tasks.scan_tasks import celery_app
    result = celery_app.AsyncResult(task_id)
    return {
        "task_id": task_id,
        "status": result.status,
        "result": result.result if result.ready() else None,
    }


# ── Results ─────────────────────────────────────────────────────────────────────

@app.get("/results")
def list_results(page: int = 1, limit: int = 20):
    return {
        "results": list_result_records(page=page, limit=limit),
        "total": count_result_files(),
        "page": page,
        "limit": limit,
    }


@app.get("/results/{filename}")
def get_result(filename: str):
    try:
        path = resolve_result_path(filename)
    except ValueError:
        raise HTTPException(status_code=403, detail="Access denied")

    if not path.is_file():
        raise HTTPException(status_code=404, detail="Result not found")

    try:
        return {"file": path.name, "data": read_result_file(path.name)}
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to parse result file")
