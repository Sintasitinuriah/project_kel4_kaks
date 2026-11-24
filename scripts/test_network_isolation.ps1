<#
.SYNOPSIS
    Verifikasi Layer 1: Segmentasi Jaringan VPC 3-Tier (Defense-in-Depth)
.DESCRIPTION
    Menguji bahwa:
    1. private_app_net dan private_db_net bersifat internal: true
    2. Web App (5000) dan PostgreSQL (5432) tidak terekspos ke host
    3. Kontainer WAF tidak dapat menjangkau PostgreSQL secara langsung (isolasi east-west)
    4. Kontainer Web App dan DB tidak memiliki akses keluar ke internet (internal: true)
    5. Jalur sah Host -> WAF -> Web App -> DB berjalan normal (HTTP 200)
#>

param(
    [int]$WafPort = 8080
)

$ErrorActionPreference = "Continue"

function Write-Result {
    param([string]$Name, [bool]$Passed, [string]$Detail)
    if ($Passed) {
        Write-Host "[PASS] $Name" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] $Name" -ForegroundColor Red
    }
    if ($Detail) {
        Write-Host "       $Detail" -ForegroundColor DarkGray
    }
}

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  LAYER 1 TEST: VERIFIKASI ISOLASI JARINGAN VPC (DOCKER COMPOSE)" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# 1. Periksa properti internal pada 3 jaringan Docker
$pubInternal = (docker network inspect did_public_net --format "{{.Internal}}") 2>$null
$appInternal = (docker network inspect did_private_app_net --format "{{.Internal}}") 2>$null
$dbInternal  = (docker network inspect did_private_db_net --format "{{.Internal}}") 2>$null

Write-Result "public_net bersifat eksternal (Internal=false)" ($pubInternal -eq "false") "Internal=$pubInternal"
Write-Result "private_app_net bersifat internal (Internal=true)" ($appInternal -eq "true") "Internal=$appInternal"
Write-Result "private_db_net bersifat internal (Internal=true)" ($dbInternal -eq "true") "Internal=$dbInternal"

# 2. Pastikan kontainer WebApp dan PostgreSQL TIDAK mem-publish port ke host
$webappPorts = (docker port did_webapp) 2>$null
$dbPorts     = (docker port did_postgres) 2>$null
$dbNets      = (docker inspect did_postgres --format "{{range `$k, `$v := .NetworkSettings.Networks}}{{`$k}} {{end}}") 2>$null

Write-Result "Kontainer Web App (did_webapp) TIDAK mengekspos port ke host" ([string]::IsNullOrWhiteSpace($webappPorts)) "docker port did_webapp -> '$(if ($webappPorts) { $webappPorts } else { '<tidak ada>' })'"
Write-Result "Kontainer PostgreSQL (did_postgres) TIDAK mengekspos port ke host" ([string]::IsNullOrWhiteSpace($dbPorts)) "docker port did_postgres -> '$(if ($dbPorts) { $dbPorts } else { '<tidak ada>' })'"
Write-Result "Kontainer PostgreSQL HANYA terhubung ke private_db_net" ($dbNets.Trim() -eq "did_private_db_net") "Networks: $($dbNets.Trim())"

# 3. Pastikan kontainer WAF TIDAK dapat menghubungi db:5432 (East-West Isolation)
$wafToDb = docker exec did_waf sh -c "nc -z -w 2 db 5432 2>&1" 2>&1
$wafBlocked = ($LASTEXITCODE -ne 0)
Write-Result "WAF (did_waf) TIDAK dapat menjangkau DB (db:5432)" $wafBlocked "Output: $wafToDb"

# 4. Pastikan kontainer webapp TIDAK memiliki akses internet keluar (internal: true)
$appToInet = docker exec did_webapp python -c "import socket; s=socket.create_connection(('1.1.1.1', 443), timeout=2); s.close()" 2>&1
$appNoInet = ($LASTEXITCODE -ne 0)
Write-Result "Web App (did_webapp) terisolasi dari internet keluar" $appNoInet "Diharapkan gagal karena hanya di jaringan internal: true"

# 5. Pastikan jalur sah Host -> WAF -> WebApp -> DB berhasil
try {
    $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$WafPort/health" -UseBasicParsing -TimeoutSec 5
    Write-Result "Jalur sah Host -> WAF:$WafPort/health -> WebApp -> DB" ($resp.StatusCode -eq 200) "HTTP $($resp.StatusCode): $($resp.Content)"
} catch {
    Write-Result "Jalur sah Host -> WAF:$WafPort/health -> WebApp -> DB" $false "Error: $($_.Exception.Message)"
}
