# Starts Mini Cloud and opens a free public HTTPS link (Cloudflare quick tunnel).
# Close this window or press Ctrl+C to take the public link down; the app keeps
# running locally until you run:  docker compose down
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

# 1. Docker must be running
docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Docker isn't running. Start Docker Desktop, wait for 'Engine running', then run this again." -ForegroundColor Red
    exit 1
}

# 2. First run: create .env with random secrets
if (-not (Test-Path .env)) {
    function New-Secret([int]$bytes) {
        $b = New-Object byte[] $bytes
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
        -join ($b | ForEach-Object { $_.ToString("x2") })
    }
    @(
        "POSTGRES_USER=minicloud"
        "POSTGRES_PASSWORD=$(New-Secret 16)"
        "POSTGRES_DB=minicloud"
        "JWT_SECRET=$(New-Secret 32)"
        "MINIO_ROOT_USER=minicloud"
        "MINIO_ROOT_PASSWORD=$(New-Secret 16)"
        "MINIO_BUCKET=user-files"
    ) | Set-Content -Encoding ascii .env
    Write-Host "Created .env with random secrets."
}

# 3. Start the stack
docker compose up --build -d
if ($LASTEXITCODE -ne 0) { exit 1 }

# 4. Wait until Nginx answers
Write-Host "Waiting for Mini Cloud..." -NoNewline
for ($i = 0; $i -lt 30; $i++) {
    try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 http://localhost:8080/ | Out-Null; break } catch { Start-Sleep 2; Write-Host "." -NoNewline }
}
Write-Host " up at http://localhost:8080"

# 5. Public link
$cf = (Get-Command cloudflared -ErrorAction SilentlyContinue).Source
if (-not $cf) { $cf = "${env:ProgramFiles(x86)}\cloudflared\cloudflared.exe" }
if (-not (Test-Path $cf)) {
    Write-Host "cloudflared not found. Install it with:  winget install Cloudflare.cloudflared" -ForegroundColor Yellow
    exit 0
}
Write-Host ""
Write-Host "Opening a public link. Look for the line ending in .trycloudflare.com below." -ForegroundColor Green
Write-Host "Register your admin account BEFORE sharing the link (first account = admin)." -ForegroundColor Green
Write-Host ""
& $cf tunnel --no-autoupdate --url http://localhost:8080
