# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**AutoSec Platform** - An automated penetration testing platform for authorized security testing and lab environments.

## Architecture

- **Backend**: FastAPI + Celery (async task scheduling) with Redis as broker
- **Docker**: Kali Linux container with security tools (nmap, Metasploit, BloodHound, Impacket, nuclei, httpx, katana, dirsearch)
- **AI Module**: Vulnerability risk scoring, classification, and attack path planning
- **Frontend**: Windows GUI (PyQt5) that communicates with backend via REST API
- **Plugins**: PentestGPT and Shannon automation plugins

## Directory Structure

```
auto_sec_platform/
├── backend/
│   ├── api/main.py          # FastAPI endpoints
│   ├── core/orchestrator.py # Task orchestration
│   ├── tasks/scan_tasks.py  # Celery async tasks
│   ├── modules/             # Scan modules (recon, webscan, cve, intranet, ad, persistence)
│   ├── ai/                  # AI analysis (risk scoring, classification, path planning)
│   └── utils/parser.py      # Data parsing utilities
├── frontend/gui/main_gui.py # PyQt5 Windows GUI
├── docker/kali/Dockerfile   # Kali container setup
├── plugins/                 # PentestGPT/Shannon plugins
├── output/                  # Scan results and reports
└── docker-compose.yml       # Service orchestration
```

## Key Commands

```bash
# Build and start services
docker-compose build
docker-compose up

# Start backend API
uvicorn api.main:app --host 0.0.0.0 --port 8000

# Start Celery worker
celery -A tasks.scan_tasks worker --loglevel=info

# Run Windows GUI
python frontend/gui/main_gui.py
```

## Development Notes

- Only for authorized penetration testing or lab environments
- Backend exposes REST API: /scan/web, /ai/analyze, /results
- Celery handles async scan tasks to keep GUI responsive
- AI module can use external AI or local LLM (GPT4All/MPT)
- Output directory stores scan results and generated reports
