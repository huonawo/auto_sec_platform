# Windows-Side Development Workflow

This document covers the Windows-side project folder only. Kali image/toolchain work is intentionally out of scope for this pass.

## What This Side Owns

- FastAPI source code under `backend/`
- Celery task definitions under `backend/tasks/`
- AI analysis rules under `backend/ai/`
- PyQt5 GUI under `frontend/gui/`
- Result files under `output/`
- Local tests under `tests/`
- Helper scripts under `scripts/`

## Configuration

Environment variables:

- `REDIS_PASSWORD`: required when running Docker Compose backend/worker.
- `AUTOSEC_OUTPUT_DIR`: optional override for result storage. Defaults to `/workspace/output` in containers.

GUI configuration:

- `frontend/gui/config.json` stores the API URL and polling interval.
- The GUI now uses backend result filenames from `/results` for AI analysis instead of asking for container paths.

## Run Backend Locally

Install dependencies first:

```bash
pip install -r backend/requirements.txt
```

Run the API from the backend folder:

```bash
cd backend
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

For local non-Docker development, set:

```bash
set AUTOSEC_OUTPUT_DIR=%CD%\..\output
```

## Run The GUI

Install GUI dependencies:

```bash
pip install PyQt5 requests
```

Start:

```bash
python frontend/gui/main_gui.py
```

The GUI can:

- Start `web`, `cve`, `intranet`, `ad`, `recon`, and `persistence` scan tasks.
- Refresh result history from the backend.
- Run AI analysis for a selected raw scan result.
- Export JSON and HTML reports with scan metadata, AI analysis, warnings, errors, and the authorization notice.

## Result Flow

1. A scan task writes a normalized JSON result to the output directory.
2. `GET /results` returns newest results first.
3. The GUI displays the latest result by default.
4. AI analysis is triggered with a result filename.
5. The AI task writes a second normalized `ai_analysis` result.

Normalized result records include:

- `target`
- `scan_type`
- `status`
- `started_at`
- `completed_at`
- `task_id`
- `output_file`
- `result`
- `errors`
- `warnings`
- `authorization_notice`

## Verification

Run preflight first:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\preflight.ps1
```

Pure Python tests:

```bash
python -m unittest discover -s tests -v
```

Compile check:

```bash
python -m compileall backend frontend plugins tests
```

Full API/GUI runtime verification still requires installing project dependencies such as FastAPI, Celery, Redis client, and PyQt5.

When Docker is installed, use the helper after `docker compose up -d`:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\docker_health.ps1
```

On Kali, use the read-only audit script to find outdated files, missing safety changes, Docker issues, and API connectivity problems:

```bash
bash scripts/kali_audit.sh
```

## Current Boundary

The backend/worker image declares the minimum current scan toolchain: `nmap`, ProjectDiscovery `httpx`, and ProjectDiscovery `nuclei`. The separate `docker/kali/` tool container is still available for broader future tooling, but this pass does not wire in full Metasploit, default credential dumping, persistence execution, plugins, distributed nodes, or external LLMs.

High-risk actions remain disabled by default:

- AD credential dumping requires both `enable_secretsdump=True` and `allow_credential_dump=True`.
- Persistence scanning returns advisory checks and does not execute `psexec.py`.
- All scan results retain an authorization notice.
