param(
    [switch]$Strict
)

$ErrorActionPreference = "Continue"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $root

$failures = 0
$warnings = 0

function Add-Result {
    param(
        [string]$Name,
        [bool]$Ok,
        [string]$Message,
        [bool]$Required = $true
    )

    if ($Ok) {
        Write-Host "[OK]   $Name - $Message" -ForegroundColor Green
        return
    }

    if ($Required) {
        $script:failures += 1
        Write-Host "[FAIL] $Name - $Message" -ForegroundColor Red
    } else {
        $script:warnings += 1
        Write-Host "[WARN] $Name - $Message" -ForegroundColor Yellow
    }
}

function Has-Command {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

Write-Host "AutoSec Platform preflight" -ForegroundColor Cyan
Write-Host "Workspace: $root"
Write-Host ""

Add-Result "Git" (Has-Command "git") "required for version control"
Add-Result "Python" (Has-Command "python") "required for local API/GUI/test runs"
Add-Result "Docker" (Has-Command "docker") "required for Docker Compose runtime" -Required:$false

$envPath = Join-Path $root ".env"
$envExamplePath = Join-Path $root ".env.example"
Add-Result ".env.example" (Test-Path $envExamplePath) "template is present"
Add-Result ".env" (Test-Path $envPath) "copy .env.example to .env and set REDIS_PASSWORD" -Required:$false

if (Test-Path $envPath) {
    $envContent = Get-Content $envPath -Raw
    $hasRedis = $envContent -match "REDIS_PASSWORD\s*=\s*\S+"
    $usesPlaceholder = $envContent -match "change_me_to_a_strong_password"
    Add-Result "REDIS_PASSWORD" ($hasRedis -and -not $usesPlaceholder) "set a non-placeholder Redis password" -Required:$false
}

$guiExample = Join-Path $root "frontend\gui\config.example.json"
$guiConfig = Join-Path $root "frontend\gui\config.json"
Add-Result "GUI config example" (Test-Path $guiExample) "frontend/gui/config.example.json is present"
Add-Result "GUI local config" (Test-Path $guiConfig) "copy config.example.json to config.json if needed" -Required:$false

$backendDockerfile = Join-Path $root "backend\Dockerfile"
$dockerCompose = Join-Path $root "docker-compose.yml"
Add-Result "Backend Dockerfile" (Test-Path $backendDockerfile) "worker/backend build file is present"
Add-Result "Docker Compose" (Test-Path $dockerCompose) "compose file is present"

if (Test-Path $backendDockerfile) {
    $dockerfile = Get-Content $backendDockerfile -Raw
    Add-Result "Worker nmap" ($dockerfile -match "nmap") "worker image includes nmap"
    Add-Result "Worker httpx" ($dockerfile -match "projectdiscovery/httpx") "worker image installs ProjectDiscovery httpx"
    Add-Result "Worker nuclei" ($dockerfile -match "projectdiscovery/nuclei") "worker image installs ProjectDiscovery nuclei"
}

if (Test-Path $dockerCompose) {
    $compose = Get-Content $dockerCompose -Raw
    Add-Result "Backend healthcheck" ($compose -match "healthcheck" -and $compose -match "/health") "backend healthcheck is configured"
    Add-Result "Worker healthcheck" ($compose -match "inspect ping") "worker healthcheck is configured"
}

try {
    $port8000 = Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue
    Add-Result "Port 8000" (-not $port8000) "port 8000 is available" -Required:$false
} catch {
    Add-Result "Port 8000" $true "port check skipped: $($_.Exception.Message)" -Required:$false
}

Write-Host ""
Write-Host "Summary: $failures failure(s), $warnings warning(s)"

if ($failures -gt 0 -or ($Strict -and $warnings -gt 0)) {
    exit 1
}
exit 0
