# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**AutoSec Platform** — automated penetration testing platform for authorized security testing and lab environments. Backend is Python (FastAPI + Celery), frontend is PyQt5 Windows GUI, and Docker provides the Kali toolchain.

## Commands

```bash
# Docker build & run (all 6 services: backend, worker, redis, kali, pentestgpt, shannon)
docker compose build && docker compose up -d

# Tests (unittest, no pytest)
python -m unittest discover -s tests -v

# Syntax check all Python
python -m compileall backend frontend plugins tests

# Local backend (no Docker, from repo root)
pip install -r backend/requirements.txt
cd backend && uvicorn api.main:app --reload --host 0.0.0.0 --port 8000

# Local Celery worker
cd backend && celery -A tasks.scan_tasks worker --loglevel=info

# Windows GUI
python frontend/gui/main_gui.py

# Scale workers
docker compose up -d --scale worker=3
```

## Architecture

**Data flow:** GUI → REST API (FastAPI, port 8000) → Orchestrator → Celery task → Scanner module → JSON result file in `output/` → GUI polls `/task/{id}` and fetches `/results/{filename}`.

**6 Docker services** in `docker-compose.yml`: `backend` (FastAPI), `worker` (Celery), `redis` (broker, no host port), `kali` (full toolchain, tty mode), `pentestgpt` (port 8001), `shannon` (port 8002).

**Scan modules** (`backend/modules/`): Each has a class with constructor `(target: str)` and `run(options: dict) -> dict`. Tools called via `subprocess.run()`. Modules: `recon` (nmap -sS -sV), `webscan` (httpx + nuclei), `cve` (nmap --script vuln), `intranet` (nmap -sn), `ad` (BloodHound + Impacket), `persistence` (advisory only, never executes psexec), `ctf` (ReAct-loop agent).

**AI pipeline** (`backend/ai/`): `AIAnalyzer` orchestrates: `VulnClassifier` (keyword matching) → `RiskScorer` (CVSS-based 0-10) → `PathPlanner` (defensive validation workflows, not exploitation). Falls back to rule-based local processing when `AI_API_KEY` is unset. `LLMClient` wraps OpenAI-compatible API (default: mimo-v2.5-pro on xiaomimimo.com).

**Automated pentest** (`/pentest/auto`): Sync 4-stage pipeline — web scan → AI analysis → PentestGPT (port 8001) → Shannon (port 8002).

**CTF solver** (`/ctf/solve`): ReAct agent using PentestGPT for reasoning, Shannon for command review, `CTFExecutor` for execution with auto-fixes and regex flag detection. Streams via SSE. Loads skill knowledge from `~/.claude/skills/ctf-skills/`.

## Key Patterns

- **Orchestrator** (`backend/core/orchestrator.py`): Maps scan type strings to Celery task functions, tracks job state in Redis db=2 with 24h TTL.
- **Celery tasks** (`backend/tasks/scan_tasks.py`): Instantiate scanner, call `run()`, save timestamped JSON to `/workspace/output/`.
- **Plugin architecture**: PentestGPT and Shannon are independent FastAPI services. Each has its own `LLMClient` copy (duplicated, not shared from a module).
- **Safety enforcement** (`backend/utils/safety.py`): `normalize_scan_options()` forces `authorized=False`, `safe_mode=True`, `allow_credential_dump=False` by default. AD scan requires explicit `authorized=True`. Credential dumping requires both `enable_secretsdump=True` AND `allow_credential_dump=True`.
- **Target validation** (`backend/utils/parser.py`): Regex-based URL/IP/CIDR validation prevents injection.
- **Result path safety** (`backend/utils/results.py`): Path traversal prevention ensures files stay within output directory.

## Configuration

- `.env` required: `REDIS_PASSWORD` (must match across all services), `AI_API_KEY` or `MIMO_API_KEY` for LLM features. See `.env.example`.
- `frontend/gui/config.json` (gitignored): `api_url`, `poll_interval_ms`, `result_limit`. See `config.example.json`.
- No linter, formatter, or CI config exists. Tests use `unittest` (not pytest).
