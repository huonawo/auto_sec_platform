param(
    [string]$BackendUrl = "http://localhost:8000/health"
)

$ErrorActionPreference = "Continue"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $root

$failures = 0

function Fail {
    param([string]$Message)
    $script:failures += 1
    Write-Host "[FAIL] $Message" -ForegroundColor Red
}

function Ok {
    param([string]$Message)
    Write-Host "[OK]   $Message" -ForegroundColor Green
}

function Warn {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Load-RedisPassword {
    if ($env:REDIS_PASSWORD) {
        return $env:REDIS_PASSWORD
    }

    $envPath = Join-Path $root ".env"
    if (-not (Test-Path $envPath)) {
        return $null
    }

    $line = Get-Content $envPath | Where-Object { $_ -match "^\s*REDIS_PASSWORD\s*=" } | Select-Object -First 1
    if (-not $line) {
        return $null
    }

    return (($line -split "=", 2)[1]).Trim()
}

Write-Host "AutoSec Docker health check" -ForegroundColor Cyan
Write-Host "Workspace: $root"
Write-Host ""

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Fail "Docker was not found. Install Docker Desktop and re-run this script."
    exit 1
}

$redisPassword = Load-RedisPassword
if (-not $redisPassword -or $redisPassword -eq "change_me_to_a_strong_password") {
    Warn "REDIS_PASSWORD is missing or still uses the placeholder value."
}

Write-Host "Docker Compose services:"
docker compose ps
if ($LASTEXITCODE -ne 0) {
    Fail "docker compose ps failed"
}

try {
    $response = Invoke-RestMethod -Uri $BackendUrl -TimeoutSec 5
    if ($response.status -eq "healthy") {
        Ok "Backend health endpoint returned healthy"
    } else {
        Fail "Backend health endpoint returned unexpected status: $($response | ConvertTo-Json -Compress)"
    }
} catch {
    Fail "Backend health endpoint failed: $($_.Exception.Message)"
}

if ($redisPassword) {
    docker compose exec -T redis redis-cli -a $redisPassword ping 2>$null
    if ($LASTEXITCODE -eq 0) {
        Ok "Redis ping succeeded"
    } else {
        Fail "Redis ping failed"
    }
}

$workerLogs = docker compose logs --tail 120 worker 2>$null
if ($LASTEXITCODE -ne 0) {
    Fail "Unable to read worker logs"
} elseif ($workerLogs -match "ready|celery|worker") {
    Ok "Worker logs are present"
} else {
    Warn "Worker logs did not include an obvious ready marker"
}

Write-Host ""
if ($failures -gt 0) {
    Write-Host "Summary: $failures failure(s)" -ForegroundColor Red
    exit 1
}

Write-Host "Summary: health checks completed" -ForegroundColor Green
exit 0
