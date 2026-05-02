# Repository Guidelines

## Project Overview

AutoSec Platform is an automated penetration testing platform intended only for authorized security testing, lab environments, and educational use.

The system is split into:

- `backend/`: FastAPI API, Celery tasks, scan orchestration, scan modules, AI analysis, and parsing utilities.
- `frontend/gui/`: PyQt5 desktop GUI that talks to the backend REST API.
- `docker/kali/`: Kali-based tooling image for security tools.
- `plugins/`: PentestGPT and Shannon integration stubs.
- `output/`: Generated scan results and reports.

## Safety Boundary

Do not add functionality that enables unauthorized access, stealth, persistence, credential theft, evasion, or destructive actions against real targets. Keep changes scoped to authorized testing workflows, validation, reporting, defensive analysis, or lab use.

When adding scan capabilities, preserve target validation and prefer explicit user-provided targets. Avoid broad default scans.

## Common Commands

Build and start the full stack:

```bash
docker-compose build
docker-compose up -d
```

Check containers:

```bash
docker-compose ps
```

Run the backend locally:

```bash
pip install -r backend/requirements.txt
cd backend
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

Run the Celery worker locally:

```bash
cd backend
celery -A tasks.scan_tasks worker --loglevel=info
```

Run the GUI:

```bash
pip install pyqt5 requests
python frontend/gui/main_gui.py
```

## Environment

Copy `.env.example` to `.env` and set `REDIS_PASSWORD` before running Docker Compose. The backend and worker require this value.

## Development Notes

- Backend import paths assume commands are run from `backend/` for local FastAPI/Celery execution.
- Docker mounts `./backend` into `/workspace/backend` and `./output` into `/workspace/output`.
- Results are JSON files under `/workspace/output` inside containers and `output/` on the host.
- API endpoints include `/scan/web`, `/scan/cve`, `/scan/intranet`, `/scan/ad`, `/scan/recon`, `/scan/persistence`, `/ai/analyze`, `/task/{task_id}`, and `/results`.
- Existing docs contain some mojibake box-drawing characters. Avoid spreading those into new files; use plain ASCII unless a touched file already requires otherwise.

## Testing And Verification

For code changes, use the most relevant verification available:

- Run unit tests:

```bash
python -m unittest discover -s tests -v
```

- Compile-check Python files when practical:

```bash
python -m compileall backend frontend plugins tests
```

- For API behavior, start services and check:

```bash
curl http://localhost:8000/health
```

- For GUI changes, run `python frontend/gui/main_gui.py` and verify the affected flow manually.

## Coding Style

- Prefer small, focused Python modules and clear data structures.
- Keep validation close to API boundaries.
- Handle external tool failures gracefully and include useful error details in saved results.
- Do not commit generated output, caches, local secrets, or environment-specific config.
