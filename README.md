# AutoSec Platform

Automated penetration testing platform for authorized security testing and lab environments.

> **Warning**: This tool is for authorized penetration testing or lab environments only. Unauthorized use is illegal.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Windows GUI (PyQt5)                                         │
│  - Target input, scan control, vuln table, attack paths      │
│  - JSON/HTML report export                                    │
└────────────────────────┬────────────────────────────────────┘
                         │ REST API (port 8000)
┌────────────────────────▼────────────────────────────────────┐
│  FastAPI Backend + Celery Worker                              │
│  - /scan/web, /scan/cve, /scan/intranet, /scan/ad            │
│  - /ai/analyze, /results, /task/{id}                          │
├──────────────────────────────────────────────────────────────┤
│  AI Analysis Module                                           │
│  - Risk scoring (CVSS-based)                                  │
│  - Vulnerability classification                               │
│  - Attack path planning                                       │
├──────────────────────────────────────────────────────────────┤
│  Scan Modules                                                 │
│  - webscan: httpx + nuclei                                    │
│  - cve: nmap --script vuln                                    │
│  - intranet: nmap host discovery                              │
│  - ad: BloodHound + Impacket                                  │
├──────────────────────────────────────────────────────────────┤
│  Redis (broker)                                               │
└──────────────────────────────────────────────────────────────┘
```

## Prerequisites

- Docker + Docker Compose
- Python 3.10+ (for Windows GUI)
- Network access between Windows host and Docker host

## Quick Start

### 1. Build and start services

```bash
cd auto_sec_platform
docker-compose build
docker-compose up -d
```

Verify services are running:

```bash
docker-compose ps
```

Expected output: `backend`, `worker`, `redis`, `kali` containers running.

### 2. Test the API

```bash
curl http://localhost:8000/
# {"status":"ok","service":"AutoSec Platform"}
```

### 3. Run Windows GUI

On Windows machine:

```bash
pip install pyqt5 requests
python frontend/gui/main_gui.py
```

Configure API address in **Settings → API Configuration** if the Docker host is not localhost.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Health check |
| `GET` | `/health` | Health check |
| `POST` | `/scan/web` | Web scan (httpx + nuclei) |
| `POST` | `/scan/cve` | CVE vulnerability scan |
| `POST` | `/scan/intranet` | Intranet host discovery |
| `POST` | `/scan/ad` | Active Directory scan |
| `POST` | `/ai/analyze` | AI vulnerability analysis |
| `GET` | `/task/{task_id}` | Query task status |
| `GET` | `/results` | List all scan results |
| `GET` | `/results/{filename}` | Get specific result |

### Request Examples

**Web scan:**
```bash
curl -X POST http://localhost:8000/scan/web \
  -H "Content-Type: application/json" \
  -d '{"target": "http://example.com"}'
```

**AI analysis:**
```bash
curl -X POST http://localhost:8000/ai/analyze \
  -H "Content-Type: application/json" \
  -d '{"file_path": "/workspace/output/web_scan_20260430_120000.json"}'
```

**Check task status:**
```bash
curl http://localhost:8000/task/{task_id}
```

## GUI Usage

1. Enter target URL or IP in the input field
2. Select scan type (web / cve / intranet / ad)
3. Click **Start Scan** — task queued, GUI polls for results
4. Once complete, vulnerability table and attack paths populate automatically
5. Click **Run AI Analysis** to get risk scores and attack path recommendations
6. Export results via **File → Export JSON Report** or **Export HTML Report**

### GUI Features

- **Vulnerability Table**: Color-coded by severity (critical/high/medium/low)
- **Attack Paths**: Step-by-step exploitation chains with priorities
- **Summary**: Vulnerability count breakdown by severity
- **Log Window**: Real-time operation log with timestamps
- **Settings**: Configurable API URL (persisted to `config.json`)

## Directory Structure

```
auto_sec_platform/
├── backend/
│   ├── api/main.py          # FastAPI endpoints
│   ├── core/orchestrator.py # Task orchestration
│   ├── tasks/scan_tasks.py  # Celery async tasks
│   ├── modules/
│   │   ├── recon/           # Port and service enumeration
│   │   ├── webscan/         # httpx + nuclei scanning
│   │   ├── cve/             # CVE vulnerability scanning
│   │   ├── intranet/        # Network host discovery
│   │   ├── ad/              # Active Directory scanning
│   │   └── persistence/     # Persistence mechanism detection
│   ├── ai/
│   │   ├── ai_analysis.py   # Analysis orchestrator
│   │   └── model/
│   │       ├── risk_score.py      # CVSS-based risk scoring
│   │       ├── vuln_classifier.py # Vulnerability classification
│   │       └── path_planner.py    # Attack path planning
│   ├── utils/parser.py      # Data parsing utilities
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/gui/
│   └── main_gui.py          # PyQt5 Windows GUI
├── docker/kali/
│   └── Dockerfile           # Kali Linux toolchain image
├── plugins/
│   ├── pentestgpt_plugin.py # PentestGPT integration
│   └── shannon_plugin.py    # Shannon integration
├── output/                  # Scan results and reports
├── docker-compose.yml
└── README.md
```

## Toolchain (Kali Container)

- **nmap**: Port scanning, service detection, vulnerability scripts
- **httpx**: HTTP probing and technology detection
- **nuclei**: Template-based vulnerability scanning
- **Metasploit**: Exploitation framework
- **BloodHound**: Active Directory attack path analysis
- **Impacket**: Windows protocol interaction (psexec, secretsdump, etc.)
- **dirsearch**: Directory and file brute-forcing

## Plugins

| Plugin | Container | Description |
|--------|-----------|-------------|
| PentestGPT | `pentestgpt` | AI-guided penetration testing |
| Shannon | `shannon` | Automated attack automation |

## Development

### Run backend locally (without Docker)

```bash
pip install -r backend/requirements.txt
cd backend
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

### Run Celery worker locally

```bash
cd backend
celery -A tasks.scan_tasks worker --loglevel=info
```

### Scale workers

```bash
docker-compose up -d --scale worker=3
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| GUI cannot connect | Verify Docker host IP in Settings → API Configuration |
| Task stays "PENDING" | Check `docker-compose logs worker` for errors |
| Port 8000 conflict | Change port mapping in `docker-compose.yml` |
| Redis connection refused | Ensure `redis` container is running: `docker-compose ps` |

## License

For authorized security testing and educational use only.
