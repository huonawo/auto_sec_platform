import json
import os
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional

import redis

from tasks.scan_tasks import (
    run_web_scan,
    run_cve_scan,
    run_intranet_scan,
    run_ad_scan,
    run_recon_scan,
    run_persistence_scan,
    run_ai_analysis,
)


class ScanType(str, Enum):
    WEB = "web"
    CVE = "cve"
    INTRANET = "intranet"
    AD = "ad"
    RECON = "recon"
    PERSISTENCE = "persistence"
    AI_ANALYSIS = "ai_analysis"


SCAN_TASKS = {
    ScanType.WEB: run_web_scan,
    ScanType.CVE: run_cve_scan,
    ScanType.INTRANET: run_intranet_scan,
    ScanType.AD: run_ad_scan,
    ScanType.RECON: run_recon_scan,
    ScanType.PERSISTENCE: run_persistence_scan,
}

REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD")
if not REDIS_PASSWORD:
    raise RuntimeError("REDIS_PASSWORD environment variable is required")

_redis = redis.Redis(
    host="redis",
    port=6379,
    password=REDIS_PASSWORD,
    db=2,
    decode_responses=True,
)

JOB_PREFIX = "autosec:job:"
JOB_TTL = 86400  # 24 hours


@dataclass
class ScanJob:
    target: str
    scan_type: ScanType
    options: dict = field(default_factory=dict)
    task_id: Optional[str] = None
    status: str = "pending"
    result: Optional[dict] = None


def _job_key(task_id: str) -> str:
    return f"{JOB_PREFIX}{task_id}"


class Orchestrator:
    def start_scan(self, target: str, scan_type: ScanType, options: dict = None) -> ScanJob:
        task_fn = SCAN_TASKS.get(scan_type)
        if not task_fn:
            raise ValueError(f"Unknown scan type: {scan_type}")

        job = ScanJob(target=target, scan_type=scan_type, options=options or {})
        result = task_fn.delay(target, options)
        job.task_id = result.id
        job.status = "queued"
        _redis.setex(_job_key(result.id), JOB_TTL, json.dumps(asdict(job), default=str))
        return job

    def start_ai_analysis(self, file_path: str, model: str = "default") -> ScanJob:
        result = run_ai_analysis.delay(file_path, model)
        job = ScanJob(target=file_path, scan_type=ScanType.AI_ANALYSIS, task_id=result.id, status="queued")
        _redis.setex(_job_key(result.id), JOB_TTL, json.dumps(asdict(job), default=str))
        return job

    def get_job(self, task_id: str) -> Optional[ScanJob]:
        raw = _redis.get(_job_key(task_id))
        if not raw:
            return None
        data = json.loads(raw)
        data["scan_type"] = ScanType(data["scan_type"])
        return ScanJob(**data)

    def update_job_status(self, task_id: str, status: str, result: dict = None) -> None:
        job = self.get_job(task_id)
        if job:
            job.status = status
            if result is not None:
                job.result = result
            _redis.setex(_job_key(task_id), JOB_TTL, json.dumps(asdict(job), default=str))
