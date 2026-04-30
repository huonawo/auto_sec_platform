#!/usr/bin/env bash

# Read-only Kali-side audit for AutoSec Platform.
# It checks code freshness, required files, Docker runtime, and backend API health.

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_URL="${AUTOSEC_BACKEND_URL:-http://127.0.0.1:8000}"
EXPECTED_COMMIT=""
CHECK_RUNTIME=1

while [ "$#" -gt 0 ]; do
  case "$1" in
    --expected-commit)
      EXPECTED_COMMIT="${2:-}"
      shift 2
      ;;
    --backend-url)
      BACKEND_URL="${2:-}"
      shift 2
      ;;
    --no-runtime)
      CHECK_RUNTIME=0
      shift
      ;;
    -h|--help)
      cat <<'EOF'
Usage: scripts/kali_audit.sh [options]

Options:
  --expected-commit <sha>  Warn when the local git commit does not match.
  --backend-url <url>      Backend base URL, default http://127.0.0.1:8000.
  --no-runtime             Skip Docker/API runtime checks.
EOF
      exit 0
      ;;
    *)
      echo "[FAIL] Unknown argument: $1"
      exit 1
      ;;
  esac
done

failures=0
warnings=0

ok() {
  printf '[OK]   %s\n' "$1"
}

warn() {
  warnings=$((warnings + 1))
  printf '[WARN] %s\n' "$1"
}

fail() {
  failures=$((failures + 1))
  printf '[FAIL] %s\n' "$1"
}

has_command() {
  command -v "$1" >/dev/null 2>&1
}

check_file() {
  if [ -e "$ROOT/$1" ]; then
    ok "Found $1"
  else
    fail "Missing $1"
  fi
}

check_contains() {
  file="$1"
  pattern="$2"
  label="$3"
  if [ ! -f "$ROOT/$file" ]; then
    fail "Cannot inspect missing file: $file"
    return
  fi
  if grep -q "$pattern" "$ROOT/$file"; then
    ok "$label"
  else
    fail "$label is missing"
  fi
}

check_not_contains() {
  file="$1"
  pattern="$2"
  label="$3"
  if [ ! -f "$ROOT/$file" ]; then
    fail "Cannot inspect missing file: $file"
    return
  fi
  if grep -q "$pattern" "$ROOT/$file"; then
    fail "$label"
  else
    ok "$label"
  fi
}

echo "AutoSec Kali audit"
echo "Workspace: $ROOT"
echo "Backend URL: $BACKEND_URL"
echo ""

cd "$ROOT" || exit 1

echo "== Commands =="
for cmd in git docker curl; do
  if has_command "$cmd"; then
    ok "$cmd is available"
  else
    fail "$cmd is not installed or not on PATH"
  fi
done

if has_command docker && docker compose version >/dev/null 2>&1; then
  ok "docker compose is available"
elif has_command docker; then
  fail "docker compose is not available"
fi

echo ""
echo "== Git =="
if has_command git && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  current_commit="$(git rev-parse --short HEAD 2>/dev/null || true)"
  ok "Current commit: $current_commit"
  if [ -n "$EXPECTED_COMMIT" ] && [ "$current_commit" != "$EXPECTED_COMMIT" ]; then
    warn "Expected commit $EXPECTED_COMMIT but found $current_commit"
  fi
  if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
    warn "Working tree has local changes"
  else
    ok "Working tree is clean"
  fi
else
  warn "Not a git checkout; commit comparison skipped"
fi

echo ""
echo "== Required files =="
check_file ".env.example"
check_file "docker-compose.yml"
check_file "backend/Dockerfile"
check_file "backend/utils/safety.py"
check_file "backend/modules/ad/ad_scan.py"
check_file "backend/modules/persistence/persistence.py"
check_file "scripts/docker_health.ps1"
check_file "scripts/preflight.ps1"
check_file "tests/test_scanner_safety.py"
check_file "tests/test_safety_options.py"

echo ""
echo "== Safety and runtime markers =="
check_contains "backend/utils/safety.py" "allow_credential_dump" "Unified safety options include allow_credential_dump"
check_contains "backend/modules/ad/ad_scan.py" "allow_credential_dump" "AD secretsdump requires allow_credential_dump marker"
check_not_contains "backend/modules/persistence/persistence.py" "psexec.py" "Persistence scanner does not call psexec.py"
check_contains "backend/modules/persistence/persistence.py" "not_executed" "Persistence scanner returns advisory status"
check_contains "backend/Dockerfile" "nmap" "Worker image includes nmap marker"
check_contains "backend/Dockerfile" "projectdiscovery/httpx" "Worker image includes ProjectDiscovery httpx marker"
check_contains "backend/Dockerfile" "projectdiscovery/nuclei" "Worker image includes ProjectDiscovery nuclei marker"
check_contains "docker-compose.yml" "/health" "Backend healthcheck marker exists"
check_contains "docker-compose.yml" "inspect ping" "Worker healthcheck marker exists"

echo ""
echo "== Environment =="
if [ -f "$ROOT/.env" ]; then
  ok ".env exists"
  redis_password="$(grep -E '^[[:space:]]*REDIS_PASSWORD[[:space:]]*=' "$ROOT/.env" | head -n1 | cut -d= -f2- | xargs || true)"
  if [ -z "$redis_password" ]; then
    fail "REDIS_PASSWORD is empty in .env"
  elif [ "$redis_password" = "change_me_to_a_strong_password" ]; then
    warn "REDIS_PASSWORD still uses the placeholder value"
  else
    ok "REDIS_PASSWORD is set"
  fi
else
  warn ".env is missing; copy .env.example to .env before docker compose up"
fi

if [ "$CHECK_RUNTIME" -eq 1 ]; then
  echo ""
  echo "== Docker/API runtime =="
  if has_command docker; then
    if docker info >/dev/null 2>&1; then
      ok "Docker daemon is reachable"
      if docker compose config -q >/dev/null 2>&1; then
        ok "docker compose config is valid"
      else
        fail "docker compose config is invalid"
      fi
      docker compose ps 2>/dev/null || warn "docker compose ps failed or services are not created yet"
    else
      fail "Docker daemon is not reachable"
    fi
  fi

  if has_command curl; then
    if curl -fsS "$BACKEND_URL/health" >/dev/null 2>&1; then
      ok "Backend health endpoint is reachable"
    else
      fail "Backend health endpoint is not reachable: $BACKEND_URL/health"
    fi

    if curl -fsS "$BACKEND_URL/results?limit=1" >/dev/null 2>&1; then
      ok "Backend results endpoint is reachable"
    else
      fail "Backend results endpoint is not reachable: $BACKEND_URL/results?limit=1"
    fi
  fi
fi

echo ""
echo "Summary: $failures failure(s), $warnings warning(s)"
if [ "$failures" -gt 0 ]; then
  echo ""
  echo "Suggested next steps:"
  echo "  1. If files are missing, update or replace the Kali checkout from the Windows project."
  echo "  2. If Docker/API checks fail, run: docker compose up -d"
  echo "  3. Then run this audit again."
  exit 1
fi

exit 0
