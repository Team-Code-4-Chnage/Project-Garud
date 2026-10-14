[CmdletBinding()]
param (
    [Parameter(Position = 0)]
    [ValidateSet("live", "simulator", "sim")]
    [string]$Mode = "live",

    [Parameter(Position = 1)]
    [string]$Interface = ""
)

$ROOT = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Item -LiteralPath .).FullName }
$BACKEND = Join-Path $ROOT "backend"
$VENV = Join-Path $BACKEND "venv"
$PYTHON = Join-Path $VENV "Scripts\python.exe"
$REQUIREMENTS = Join-Path $BACKEND "requirements.txt"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Project Garud - NetForecast" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

function Get-Python312 {
    $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($launcher) {
        & $launcher.Source -3.12 -c "import sys; sys.exit(0 if sys.version_info[:2] == (3, 12) else 1)" 2>$null
        if ($LASTEXITCODE -eq 0) {
            return @{
                Path = $launcher.Source
                Arguments = @("-3.12")
            }
        }
    }

    $python = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($python) {
        & $python.Source -c "import sys; sys.exit(0 if sys.version_info[:2] == (3, 12) else 1)" 2>$null
        if ($LASTEXITCODE -eq 0) {
            return @{
                Path = $python.Source
                Arguments = @()
            }
        }
    }

    $knownPaths = @(
        (Join-Path $env:LocalAppData "Programs\Python\Python312\python.exe"),
        (Join-Path $env:ProgramFiles "Python312\python.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Python312\python.exe")
    )
    foreach ($path in $knownPaths) {
        if (Test-Path -LiteralPath $path) {
            & $path -c "import sys; sys.exit(0 if sys.version_info[:2] == (3, 12) else 1)" 2>$null
            if ($LASTEXITCODE -eq 0) {
                return @{
                    Path = $path
                    Arguments = @()
                }
            }
        }
    }

    return $null
}

function Get-NodeTools {
    $node = Get-Command node.exe -ErrorAction SilentlyContinue
    $npm = Get-Command npm.cmd -ErrorAction SilentlyContinue
    if ($node -and $npm) {
        return @{
            Node = $node.Source
            Npm = $npm.Source
        }
    }

    $nodePaths = @(
        (Join-Path $env:ProgramFiles "nodejs\node.exe"),
        (Join-Path $env:LocalAppData "Programs\nodejs\node.exe")
    )
    foreach ($nodePath in $nodePaths) {
        if (Test-Path -LiteralPath $nodePath) {
            $nodeDirectory = Split-Path -Parent $nodePath
            $npmPath = Join-Path $nodeDirectory "npm.cmd"
            if (Test-Path -LiteralPath $npmPath) {
                return @{
                    Node = $nodePath
                    Npm = $npmPath
                }
            }
        }
    }

    return $null
}

function Add-NodeToPath {
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$NodeTools
    )

    $nodeDirectory = Split-Path -Parent $NodeTools.Node
    if (($env:Path -split ";") -notcontains $nodeDirectory) {
        $env:Path = "$nodeDirectory;$env:Path"
    }
}

Write-Host "[0/4] Checking Node.js and npm environment..." -ForegroundColor Yellow
$nodeTools = Get-NodeTools
if (-not $nodeTools) {
    Write-Host "Node.js and npm were not found. Downloading the latest Node.js 22 Windows installer..." -ForegroundColor Yellow
    try {
        $release = Invoke-RestMethod -Uri "https://nodejs.org/dist/index.json" -ErrorAction Stop |
            Where-Object {
                $_.version -match '^v22\.' -and $_.files -contains "win-x64-msi"
            } |
            Select-Object -First 1
    } catch {
        throw "Could not retrieve the Node.js 22 release information: $($_.Exception.Message)"
    }

    if (-not $release) {
        throw "Could not find a Node.js 22 Windows x64 installer."
    }

    $installer = Join-Path $env:TEMP "node-$($release.version)-x64.msi"
    $installerUrl = "https://nodejs.org/dist/$($release.version)/node-$($release.version)-x64.msi"
    try {
        Invoke-WebRequest -Uri $installerUrl -OutFile $installer -UseBasicParsing -ErrorAction Stop
        $installProcess = Start-Process -FilePath "msiexec.exe" `
            -ArgumentList "/i `"$installer`" /passive /norestart" `
            -Verb RunAs -Wait -PassThru
        if ($installProcess.ExitCode -notin @(0, 3010)) {
            throw "Node.js installation failed with exit code $($installProcess.ExitCode)."
        }
    } catch {
        throw "Could not install Node.js 22: $($_.Exception.Message)"
    } finally {
        if (Test-Path -LiteralPath $installer) {
            Remove-Item -LiteralPath $installer -Force
        }
    }

    $nodeTools = Get-NodeTools
    if (-not $nodeTools) {
        throw "Node.js was installed, but node.exe and npm.cmd could not be located. Restart PowerShell and run this script again."
    }
}
Add-NodeToPath -NodeTools $nodeTools
& $nodeTools.Node --version
if ($LASTEXITCODE -ne 0) {
    throw "Node.js was found but could not be executed."
}
& $nodeTools.Npm --version
if ($LASTEXITCODE -ne 0) {
    throw "npm was found but could not be executed."
}
Write-Host "Node.js and npm are ready." -ForegroundColor Green
Write-Host ""

Write-Host "[0/4] Checking Python 3.12 environment..." -ForegroundColor Yellow
$python312 = Get-Python312
if (-not $python312) {
    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($winget) {
        Write-Host "Python 3.12 was not found. Installing it with winget..." -ForegroundColor Yellow
        & $winget.Source install --id Python.Python.3.12 --exact --scope user `
            --accept-source-agreements --accept-package-agreements
        if ($LASTEXITCODE -ne 0) {
            throw "Python 3.12 installation failed with exit code $LASTEXITCODE."
        }
    } elseif ($launcher) {
        Write-Host "Python 3.12 was not found. Installing it with the Python launcher..." -ForegroundColor Yellow
        & $launcher.Source install 3.12
        if ($LASTEXITCODE -ne 0) {
            throw "Python 3.12 installation failed with exit code $LASTEXITCODE."
        }
    } else {
        throw "Python 3.12 is not installed and neither winget nor the Python launcher is available."
    }

    $python312 = Get-Python312
    if (-not $python312) {
        throw "Python 3.12 was installed, but it could not be located. Restart PowerShell and run this script again."
    }
}

$venvPython = $PYTHON
$venvIsPython312 = $false
if (Test-Path -LiteralPath $venvPython) {
    & $venvPython -c "import sys; sys.exit(0 if sys.version_info[:2] == (3, 12) else 1)" 2>$null
    $venvIsPython312 = ($LASTEXITCODE -eq 0)
}

if (-not $venvIsPython312) {
    if (Test-Path -LiteralPath $VENV) {
        Write-Host "Existing backend venv is not Python 3.12. Recreating it..." -ForegroundColor Yellow
        Remove-Item -LiteralPath $VENV -Recurse -Force
    }

    Write-Host "Creating backend venv with Python 3.12..." -ForegroundColor Yellow
    & $python312.Path @($python312.Arguments) -m venv $VENV
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $venvPython)) {
        throw "Failed to create the backend virtual environment with Python 3.12."
    }
}

$activate = Join-Path $VENV "Scripts\Activate.ps1"
if (-not (Test-Path -LiteralPath $activate)) {
    throw "The backend virtual environment activation script was not created."
}

. $activate
Write-Host "Installing backend requirements..." -ForegroundColor Yellow
& $venvPython -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) {
    throw "Failed to upgrade pip in the backend virtual environment."
}
& $venvPython -m pip install -r $REQUIREMENTS
if ($LASTEXITCODE -ne 0) {
    throw "Failed to install backend requirements."
}
Write-Host "Python 3.12 backend environment is ready." -ForegroundColor Green
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
if (-not (Test-Path "$ROOT\frontend\node_modules\leaflet")) {
    Write-Host "[2/4] Installing missing frontend dependencies..." -ForegroundColor Yellow
    Push-Location "$ROOT\frontend"
    & $nodeTools.Npm install --silent
    $npmExitCode = $LASTEXITCODE
    Pop-Location
    if ($npmExitCode -ne 0) {
        throw "Failed to install frontend dependencies with npm (exit code $npmExitCode)."
    }
}

$frontendPort = Get-NetTCPConnection -LocalPort 5173 -State Listen -ErrorAction SilentlyContinue
if ($frontendPort) {
    Write-Host "[2/4] Frontend is already running on http://localhost:5173" -ForegroundColor Green
} else {
    Write-Host "[2/4] Starting Frontend (Vite)..." -ForegroundColor Yellow
    Start-Process powershell -ArgumentList @(
        "-NoExit"
        "-ExecutionPolicy", "Bypass"
        "-Command"
        "Set-Location '$ROOT\frontend'; & '$($nodeTools.Npm)' run dev"
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