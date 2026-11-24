<#
.SYNOPSIS
    Verifikasi Layer 2 (WAF), Layer 3 (Parameterized Queries), dan Layer 4 (DB Least Privilege)
.DESCRIPTION
    Menjalankan matriks skenario serangan SQL Injection terhadap endpoint /vulnerable dan /secure
    melalui WAF untuk membuktikan pertahanan berlapis pada mode WAF aktif saat ini.
#>

param(
    [string]$BaseUrl = "http://127.0.0.1:8080"
)

$ErrorActionPreference = "Continue"

function Invoke-HttpRaw {
    param(
        [string]$Method,
        [string]$Url,
        [hashtable]$FormBody = $null
    )
    try {
        if ($Method -eq "POST") {
            $resp = Invoke-WebRequest -Uri $Url -Method Post -Body $FormBody -UseBasicParsing -TimeoutSec 8
        } else {
            $resp = Invoke-WebRequest -Uri $Url -Method Get -UseBasicParsing -TimeoutSec 8
        }
        return [PSCustomObject]@{
            StatusCode   = [int]$resp.StatusCode
            Content      = $resp.Content
            DefenseLayer = $resp.Headers["X-Defense-Layer"]
        }
    } catch {
        $webResp = $_.Exception.Response
        if ($webResp) {
            $status = [int]$webResp.StatusCode
            $reader = New-Object System.IO.StreamReader($webResp.GetResponseStream())
            $body = $reader.ReadToEnd()
            return [PSCustomObject]@{
                StatusCode   = $status
                Content      = $body
                DefenseLayer = $webResp.Headers["X-Defense-Layer"]
            }
        }
        return [PSCustomObject]@{
            StatusCode   = 0
            Content      = $_.Exception.Message
            DefenseLayer = $null
        }
    }
}

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  DEFENSE-IN-DEPTH SQL INJECTION SCENARIO TEST SUITE" -ForegroundColor Cyan
Write-Host "  Target: $BaseUrl" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# Cek status health & mode WAF saat ini
$health = Invoke-HttpRaw -Method "GET" -Url "$BaseUrl/health"
Write-Host "`n[INFO] Health Endpoint (HTTP $($health.StatusCode)): $($health.Content)" -ForegroundColor Yellow

# 1. Request normal pada /secure/products
$rNormal = Invoke-HttpRaw -Method "GET" -Url "$BaseUrl/secure/products?q=Cloud"
Write-Host "`n1. [NORMAL] GET /secure/products?q=Cloud" -ForegroundColor White
Write-Host "   Status: HTTP $($rNormal.StatusCode) | Layer Header: $($rNormal.DefenseLayer)" -ForegroundColor Green

# 2. SQLi Auth Bypass pada /vulnerable/login vs /secure/login
$sqliLogin = @{ username = "' OR '1'='1' --"; password = "wrong" }

$rVulnLogin = Invoke-HttpRaw -Method "POST" -Url "$BaseUrl/vulnerable/login" -FormBody $sqliLogin
Write-Host "`n2a. [ATTACK] POST /vulnerable/login (Payload: ' OR '1'='1' --)" -ForegroundColor White
if ($rVulnLogin.StatusCode -eq 403) {
    Write-Host "   -> DIBLOKIR oleh Layer 2 WAF (HTTP 403 Forbidden)" -ForegroundColor Green
} elseif ($rVulnLogin.Content -match "Login Berhasil!") {
    Write-Host "   -> BYPASS BERHASIL (Ekspektasi saat WAF=DetectionOnly/Off pada /vulnerable)" -ForegroundColor Yellow
} else {
    Write-Host "   -> Status: HTTP $($rVulnLogin.StatusCode)" -ForegroundColor DarkGray
}

$rSecLogin = Invoke-HttpRaw -Method "POST" -Url "$BaseUrl/secure/login" -FormBody $sqliLogin
Write-Host "2b. [ATTACK] POST /secure/login (Payload: ' OR '1'='1' --)" -ForegroundColor White
if ($rSecLogin.StatusCode -eq 403) {
    Write-Host "   -> DIBLOKIR oleh Layer 2 WAF (HTTP 403 Forbidden)" -ForegroundColor Green
} elseif ($rSecLogin.Content -notmatch "Login Berhasil!") {
    Write-Host "   -> AMAN! Ditolak oleh Layer 3 Parameterized Query (HTTP $($rSecLogin.StatusCode))" -ForegroundColor Green
} else {
    Write-Host "   -> [FAIL] Seharusnya tidak berhasil login!" -ForegroundColor Red
}

# 3. SQLi UNION SELECT pada /vulnerable/products vs /secure/products
$unionPayload = [System.Uri]::EscapeDataString("' UNION SELECT id, username, password, 0, 0, email FROM users --")

$rVulnUnion = Invoke-HttpRaw -Method "GET" -Url "$BaseUrl/vulnerable/products?q=$unionPayload"
Write-Host "`n3a. [ATTACK] GET /vulnerable/products (UNION SELECT users)" -ForegroundColor White
if ($rVulnUnion.StatusCode -eq 403) {
    Write-Host "   -> DIBLOKIR oleh Layer 2 WAF (HTTP 403 Forbidden)" -ForegroundColor Green
} elseif ($rVulnUnion.Content -match "AdminCloud#2026") {
    Write-Host "   -> DATA USER BOCOR (Ekspektasi saat WAF=DetectionOnly/Off pada /vulnerable)" -ForegroundColor Yellow
} else {
    Write-Host "   -> Status: HTTP $($rVulnUnion.StatusCode)" -ForegroundColor DarkGray
}

$rSecUnion = Invoke-HttpRaw -Method "GET" -Url "$BaseUrl/secure/products?q=$unionPayload"
Write-Host "3b. [ATTACK] GET /secure/products (UNION SELECT users)" -ForegroundColor White
if ($rSecUnion.StatusCode -eq 403) {
    Write-Host "   -> DIBLOKIR oleh Layer 2 WAF (HTTP 403 Forbidden)" -ForegroundColor Green
} elseif ($rSecUnion.Content -notmatch "AdminCloud#2026") {
    Write-Host "   -> AMAN! Tidak ada kebocoran data (Layer 3 Parameterized Query)" -ForegroundColor Green
} else {
    Write-Host "   -> [FAIL] Data bocor pada endpoint /secure!" -ForegroundColor Red
}

# 4. Destructive DDL (DROP TABLE) - Uji Layer 2 & Layer 4 (DB Least Privilege)
$dropPayload = [System.Uri]::EscapeDataString("'; DROP TABLE products; --")
$rDrop = Invoke-HttpRaw -Method "GET" -Url "$BaseUrl/vulnerable/products?q=$dropPayload"
Write-Host "`n4. [ATTACK DESTRUKTIF] GET /vulnerable/products (Payload: '; DROP TABLE products; --)" -ForegroundColor White
if ($rDrop.StatusCode -eq 403) {
    Write-Host "   -> DIBLOKIR oleh Layer 2 WAF (HTTP 403 Forbidden)" -ForegroundColor Green
} elseif ($rDrop.DefenseLayer -eq "DB-Least-Privilege" -or $rDrop.Content -match "must be owner of table") {
    Write-Host "   -> DIBLOKIR oleh Layer 4 PostgreSQL Least Privilege! (must be owner of table products)" -ForegroundColor Magenta
} else {
    Write-Host "   -> Status: HTTP $($rDrop.StatusCode)" -ForegroundColor DarkGray
}

# 5. Destructive DML (DELETE FROM users) - Uji Layer 2 & Layer 4 (DB Least Privilege)
$delPayload = [System.Uri]::EscapeDataString("'; DELETE FROM users; --")
$rDel = Invoke-HttpRaw -Method "GET" -Url "$BaseUrl/vulnerable/products?q=$delPayload"
Write-Host "`n5. [ATTACK DESTRUKTIF] GET /vulnerable/products (Payload: '; DELETE FROM users; --)" -ForegroundColor White
if ($rDel.StatusCode -eq 403) {
    Write-Host "   -> DIBLOKIR oleh Layer 2 WAF (HTTP 403 Forbidden)" -ForegroundColor Green
} elseif ($rDel.DefenseLayer -eq "DB-Least-Privilege" -or $rDel.Content -match "permission denied for table") {
    Write-Host "   -> DIBLOKIR oleh Layer 4 PostgreSQL Least Privilege! (permission denied for table users)" -ForegroundColor Magenta
} else {
    Write-Host "   -> Status: HTTP $($rDel.StatusCode)" -ForegroundColor DarkGray
}

# 6. Verifikasi integritas tabel products pasca serangan destruktif
$rIntegrity = Invoke-HttpRaw -Method "GET" -Url "$BaseUrl/secure/products"
$intact = ($rIntegrity.StatusCode -eq 200 -and $rIntegrity.Content -match "Cloud WAF Enterprise")
Write-Host "`n6. [INTEGRITY CHECK] Verifikasi tabel products tetap utuh:" -ForegroundColor White
if ($intact) {
    Write-Host "   -> [PASS] Seluruh data katalog products tetap utuh!" -ForegroundColor Green
} else {
    Write-Host "   -> [FAIL] Katalog products tidak dapat dibaca!" -ForegroundColor Red
}
