[CmdletBinding()]
param (
    [Parameter(Position = 0)]
    [ValidateSet("live", "simulator", "sim")]
    [string]$Mode = "live",

    [Parameter(Position = 1)]
    [string]$Interface = ""
)

$ROOT = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Item -LiteralPath .).FullName }
$PYTHON = "$ROOT\backend\venv\Scripts\python.exe"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Project Garud - NetForecast" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# 1. Start Backend (Port 8000)
$backendPort = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue
if ($backendPort) {
    Write-Host "[1/4] Backend is already running on http://localhost:8000" -ForegroundColor Green
} else {
    Write-Host "[1/4] Starting Backend API..." -ForegroundColor Yellow
    Start-Process powershell -ArgumentList @(
        "-NoExit"
        "-ExecutionPolicy", "Bypass"
        "-Command"
        "Set-Location '$ROOT\backend'; & '$PYTHON' -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000"
    )

    Write-Host "Waiting for backend to become ready..."
    $timeout = 20
    $count = 0
    do {
        Start-Sleep -Seconds 1
        $count++
        $backendPort = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue
    } while ((-not $backendPort) -and ($count -lt $timeout))

    if ($backendPort) {
        Write-Host "Backend is ready on http://localhost:8000!" -ForegroundColor Green
    } else {
        Write-Host "Warning: Backend took longer than expected to start. Proceeding..." -ForegroundColor Yellow
    }
}
Write-Host ""

# 2. Start Frontend (Port 5173)
$frontendPort = Get-NetTCPConnection -LocalPort 5173 -State Listen -ErrorAction SilentlyContinue
if ($frontendPort) {
    Write-Host "[2/4] Frontend is already running on http://localhost:5173" -ForegroundColor Green
} else {
    Write-Host "[2/4] Starting Frontend (Vite)..." -ForegroundColor Yellow
    Start-Process powershell -ArgumentList @(
        "-NoExit"
        "-ExecutionPolicy", "Bypass"
        "-Command"
        "Set-Location '$ROOT\frontend'; npm run dev"
    )
    Start-Sleep -Seconds 2
    Write-Host "Frontend server initiated!" -ForegroundColor Green
}
Write-Host ""

# 3. Sync backend system mode with -Mode so /ingest's live/simulated gate
#    (backend/app/routes/ingest.py) actually matches what we're about to launch --
#    the backend defaults to "live", so without this, the simulator's flows
#    (tagged source: "simulated") get rejected with HTTP 403 on every single flow.
$targetMode = if ($Mode -in @("simulator", "sim")) { "simulated" } else { "live" }
try {
    $modeResp = Invoke-RestMethod -Method Post -Uri "http://localhost:8000/system/mode" `
        -ContentType "application/json" -Body (@{ mode = $targetMode } | ConvertTo-Json) -TimeoutSec 5
    Write-Host "Backend system mode set to '$($modeResp.mode)'." -ForegroundColor Cyan
} catch {
    Write-Warning "Could not set backend system mode to '$targetMode': $($_.Exception.Message)"
}
Write-Host ""

# 4. Detect Active Network Interface & Npcap
$activeAdapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1
$ifaceName = if ($Interface) { $Interface } elseif ($activeAdapter) { $activeAdapter.Name } else { "auto" }
$activeIP = if ($activeAdapter) {
    (Get-NetIPAddress -InterfaceAlias $activeAdapter.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
} else { "Auto-detect" }

$hasNpcap = (Get-Service -Name npcap -ErrorAction SilentlyContinue) -or 
            (Test-Path "C:\Windows\System32\Npcap\wpcap.dll") -or 
            (Test-Path "C:\Windows\System32\wpcap.dll")

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# 5. Start Live Capture or Simulator
if ($Mode -in @("simulator", "sim")) {
    Write-Host "[4/4] Starting Traffic Simulator (Demo Mode)..." -ForegroundColor Cyan
    Start-Process powershell -ArgumentList @(
        "-NoExit"
        "-ExecutionPolicy", "Bypass"
        "-Command"
        "Set-Location '$ROOT'; & '$PYTHON' demo\traffic_simulator.py --api http://localhost:8000 --sessions 4 --speed 1"
    )
} else {
    Write-Host "[4/4] Starting Live Packet Capture..." -ForegroundColor Yellow
    Write-Host "Target Interface : $ifaceName (IP: $activeIP)" -ForegroundColor Cyan
    if (-not $hasNpcap) {
        Write-Host "Packet Driver    : Windows native Raw Sockets (Npcap not detected)" -ForegroundColor DarkYellow
    } else {
        Write-Host "Packet Driver    : Npcap Layer-2 Sniffer" -ForegroundColor Green
    }

    if ($isAdmin) {
        # Current shell is Administrator: launch live capture directly
        Start-Process powershell -ArgumentList @(
            "-NoExit"
            "-ExecutionPolicy", "Bypass"
            "-Command"
            "Set-Location '$ROOT'; & '$PYTHON' capture\live_capture.py --interface '$ifaceName' --api http://localhost:8000"
        )
        Write-Host "Live capture started with Administrator privileges." -ForegroundColor Green
    } else {
        # Elevated Administrator is required for Windows raw socket/packet capture
        Write-Host "Elevating live capture to Administrator via UAC..." -ForegroundColor Cyan
        try {
            Start-Process powershell -Verb RunAs -ArgumentList @(
                "-NoExit"
                "-ExecutionPolicy", "Bypass"
                "-Command"
                "Set-Location '$ROOT'; & '$PYTHON' capture\live_capture.py --interface '$ifaceName' --api http://localhost:8000"
            )
            Write-Host "Live capture window opened as Administrator." -ForegroundColor Green
        } catch {
            Write-Warning "UAC elevation was declined. Running live capture in current user privileges..."
            Start-Process powershell -ArgumentList @(
                "-NoExit"
                "-ExecutionPolicy", "Bypass"
                "-Command"
                "Set-Location '$ROOT'; & '$PYTHON' capture\live_capture.py --interface '$ifaceName' --api http://localhost:8000"
            )
        }
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  All services operational!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "SOC Analyst Dashboard : http://localhost:5173" -ForegroundColor White
Write-Host "FastAPI Backend API   : http://localhost:8000" -ForegroundColor White
Write-Host "API Interactive Docs  : http://localhost:8000/docs" -ForegroundColor White
Write-Host "Active Capture Source : $ifaceName ($activeIP)" -ForegroundColor White
Write-Host ""
Write-Host "Tips:" -ForegroundColor DarkGray
Write-Host "- To run with Traffic Simulator instead: .\start_all.ps1 -Mode simulator" -ForegroundColor DarkGray
Write-Host "- For full Layer-2 WiFi capture without raw sockets, install Npcap: https://npcap.com/#download" -ForegroundColor DarkGray
Write-Host ""