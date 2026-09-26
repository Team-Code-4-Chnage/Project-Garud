<#
.SYNOPSIS
    Project Garud — Fully Automated Lab Setup, Campaign Data Collection & Model Retraining
    SIH 2026 — PS26153 (NTRO) | Team: Code 4 Change

.DESCRIPTION
    End-to-end automation for Windows. Self-elevates to Administrator, auto-installs
    all missing software (VirtualBox, Wireshark, 7-Zip, Python packages), sets up an
    isolated VM lab, collects multi-stage attack campaign data, and retrains the model.

    Phases:
      0  — Self-elevation + prerequisite auto-install
      1  — VirtualBox host-only network (192.168.56.0/24, isolated)
      2  — VM download & import (Kali attacker, Metasploitable2 victim + peer)
      3  — VM configuration (network, SSH keys, attack tools, snapshots)
      4  — Lab config validation (dry-run)
      5  — Multi-stage campaign dataset collection
      6  — Flow extraction from PCAPs
      7  — Merge lab flows with CIC-IDS training data
      8  — Model retraining (LSTM world model, focal loss)
      9  — Post-hoc logit calibration
     10  — Artifact verification & tests

.EXAMPLE
    # Full first-time run (will auto-install everything):
    powershell -ExecutionPolicy Bypass -File .\lab_setup_and_retrain.ps1

    # VMs already configured, just collect + retrain:
    powershell -ExecutionPolicy Bypass -File .\lab_setup_and_retrain.ps1 -SkipNetwork -SkipVMSetup

    # Dataset already collected, only retrain:
    powershell -ExecutionPolicy Bypass -File .\lab_setup_and_retrain.ps1 -SkipToTraining
#>

[CmdletBinding()]
param (
    [int]$Runs = 5,
    [int]$Epochs = 25,
    [string]$DatasetDir = "dataset",
    [ValidateSet("finetune", "scratch")]
    [string]$TrainMode = "finetune",
    [switch]$FreezeLSTM,
    [switch]$SkipNetwork,
    [switch]$SkipVMSetup,
    [switch]$SkipCollection,
    [switch]$SkipToTraining
)

# ═══════════════════════════════════════════════════════════════════════
# SELF-ELEVATION TO ADMINISTRATOR
# ═══════════════════════════════════════════════════════════════════════
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Requesting Administrator privileges (required for VirtualBox, packet capture)..." -ForegroundColor Yellow
    $argList = @("-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"")
    # Forward all explicit parameters
    if ($Runs -ne 5)        { $argList += "-Runs"; $argList += $Runs }
    if ($Epochs -ne 25)     { $argList += "-Epochs"; $argList += $Epochs }
    if ($DatasetDir -ne "dataset") { $argList += "-DatasetDir"; $argList += "`"$DatasetDir`"" }
    if ($TrainMode -ne "finetune") { $argList += "-TrainMode"; $argList += $TrainMode }
    if ($FreezeLSTM)        { $argList += "-FreezeLSTM" }
    if ($SkipNetwork)       { $argList += "-SkipNetwork" }
    if ($SkipVMSetup)       { $argList += "-SkipVMSetup" }
    if ($SkipCollection)    { $argList += "-SkipCollection" }
    if ($SkipToTraining)    { $argList += "-SkipToTraining" }
    try {
        Start-Process powershell -Verb RunAs -ArgumentList $argList -Wait
    } catch {
        Write-Host "ERROR: Administrator elevation was declined. Cannot continue." -ForegroundColor Red
        exit 1
    }
    exit 0
}

# ═══════════════════════════════════════════════════════════════════════
# INIT — Constants, Paths, Helpers
# ═══════════════════════════════════════════════════════════════════════
$ErrorActionPreference = "Continue"   # VBoxManage prints to stderr on success; "Stop" would abort
$ProgressPreference    = "SilentlyContinue"  # speeds up Invoke-WebRequest by 10x

$SCRIPT_DIR = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Item -LiteralPath .).FullName }
$ROOT       = (Resolve-Path (Join-Path $SCRIPT_DIR "..")).Path   # setup/ is inside project root
$LAB_DIR   = Join-Path $ROOT "lab"
$DATA_DIR  = Join-Path $ROOT "data"
$ARTIFACTS = Join-Path $ROOT "backend\artifacts"
$DATASET   = Join-Path $ROOT $DatasetDir
$LOG_DIR   = Join-Path $LAB_DIR "logs"
$TIMESTAMP = Get-Date -Format "yyyyMMdd_HHmmss"
$LOG_FILE  = Join-Path $LOG_DIR "lab_run_$TIMESTAMP.log"
$VM_DL_DIR = Join-Path $LAB_DIR "vm_downloads"

$LAB_CONFIG_PATH = Join-Path $LAB_DIR "lab_config.json"

# Lab network
$LAB_GATEWAY = "192.168.56.1"
$LAB_NETMASK = "255.255.255.0"

# VMs
$ATTACKER_VM   = "kali-lab"
$ATTACKER_IP   = "192.168.56.10"
$ATTACKER_USER = "kali"
$ATTACKER_PASS = "kali"
$VICTIM_VM     = "target-victim"
$VICTIM_IP     = "192.168.56.20"
$PEER_VM       = "target-peer"
$PEER_IP       = "192.168.56.21"

# Ensure directories exist
foreach ($d in @($LOG_DIR, $DATASET, $VM_DL_DIR)) {
    New-Item -ItemType Directory -Path $d -Force -ErrorAction SilentlyContinue | Out-Null
}

# ── Helpers ──
function Log { param([string]$Msg, [string]$Color = "White")
    $ts = Get-Date -Format "HH:mm:ss"
    Write-Host "  [$ts] $Msg" -ForegroundColor $Color
    Add-Content -Path $LOG_FILE -Value "[$ts] $Msg" -ErrorAction SilentlyContinue
}
function OK   { param([string]$Msg) Log "✓ $Msg" "Green"   }
function WARN { param([string]$Msg) Log "⚠ $Msg" "DarkYellow" }
function FAIL { param([string]$Msg) Log "✗ $Msg" "Red"     }
function Banner { param([string]$Phase, [string]$Title)
    Write-Host ""
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   $Phase — $Title" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
}
function Has  { param([string]$Cmd) return [bool](Get-Command $Cmd -ErrorAction SilentlyContinue) }

function Refresh-Path {
    # Reload PATH so newly winget-installed tools are visible without restarting
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("Path", "User")
}

function Get-Py {
    $venvPy = Join-Path $ROOT "backend\venv\Scripts\python.exe"
    if (Test-Path $venvPy) { return $venvPy }
    if (Has "python") { return "python" }
    if (Has "python3") { return "python3" }
    throw "Python not found."
}

# ── Banner ──
Write-Host ""
Write-Host "  ██████╗  █████╗ ██████╗ ██╗   ██╗██████╗ " -ForegroundColor Red
Write-Host "  ██╔════╝ ██╔══██╗██╔══██╗██║   ██║██╔══██╗" -ForegroundColor Red
Write-Host "  ██║  ███╗███████║██████╔╝██║   ██║██║  ██║" -ForegroundColor Yellow
Write-Host "  ██║   ██║██╔══██║██╔══██╗██║   ██║██║  ██║" -ForegroundColor Yellow
Write-Host "  ╚██████╔╝██║  ██║██║  ██║╚██████╔╝██████╔╝" -ForegroundColor Green
Write-Host "   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ " -ForegroundColor Green
Write-Host ""
Write-Host "  Lab Harness + Campaign Collection + Model Retrain" -ForegroundColor White
Write-Host "  SIH 2026 PS:26153 (NTRO) • Running as Administrator" -ForegroundColor DarkGray
Write-Host "  Log: $LOG_FILE" -ForegroundColor DarkGray
Write-Host ""

# If SkipToTraining, jump straight to Phase 7
if ($SkipToTraining) {
    $SkipNetwork    = $true
    $SkipVMSetup    = $true
    $SkipCollection = $true
}

# ═══════════════════════════════════════════════════════════════════════
# PHASE 0 — AUTO-INSTALL ALL PREREQUISITES
# ═══════════════════════════════════════════════════════════════════════
Banner "PHASE 0" "Auto-Install Prerequisites"

# ── winget (needed for installs) ──
if (-not (Has "winget")) {
    WARN "winget not found. Will attempt manual installs. Consider updating Windows."
}

# ── VirtualBox ──
if (Has "VBoxManage") {
    $vbv = (& VBoxManage --version 2>$null) -replace '\r?\n',''
    OK "VirtualBox $vbv"
} else {
    Log "Installing VirtualBox via winget..." "Yellow"
    if (Has "winget") {
        winget install -e --id Oracle.VirtualBox --accept-package-agreements --accept-source-agreements --silent 2>$null
        Refresh-Path
    }
    if (-not (Has "VBoxManage")) {
        # Try adding default install path
        $vbPath = "C:\Program Files\Oracle\VirtualBox"
        if (Test-Path "$vbPath\VBoxManage.exe") {
            $env:Path += ";$vbPath"
            OK "VirtualBox found at $vbPath"
        } else {
            FAIL "VirtualBox install failed. Download manually: https://www.virtualbox.org/wiki/Downloads"
            FAIL "After installing, re-run this script."
            exit 1
        }
    } else {
        OK "VirtualBox installed successfully."
    }
}

# ── Wireshark / dumpcap ──
$script:DUMPCAP = "dumpcap"
if (Has "dumpcap") {
    OK "dumpcap on PATH."
} elseif (Test-Path "C:\Program Files\Wireshark\dumpcap.exe") {
    $script:DUMPCAP = "C:\Program Files\Wireshark\dumpcap.exe"
    $env:Path += ";C:\Program Files\Wireshark"
    OK "dumpcap at $script:DUMPCAP"
} else {
    Log "Installing Wireshark via winget..." "Yellow"
    if (Has "winget") {
        winget install -e --id WiresharkFoundation.Wireshark --accept-package-agreements --accept-source-agreements --silent 2>$null
        Refresh-Path
    }
    if (Test-Path "C:\Program Files\Wireshark\dumpcap.exe") {
        $script:DUMPCAP = "C:\Program Files\Wireshark\dumpcap.exe"
        $env:Path += ";C:\Program Files\Wireshark"
        OK "Wireshark installed."
    } else {
        FAIL "Wireshark install failed. Download: https://www.wireshark.org/download.html"
        FAIL "Npcap (bundled) is needed for packet capture."
        exit 1
    }
}

# ── 7-Zip ──
$script:SEVENZIP = "7z"
if (Has "7z") {
    OK "7-Zip on PATH."
} elseif (Test-Path "C:\Program Files\7-Zip\7z.exe") {
    $script:SEVENZIP = "C:\Program Files\7-Zip\7z.exe"
    $env:Path += ";C:\Program Files\7-Zip"
    OK "7-Zip at default path."
} else {
    Log "Installing 7-Zip via winget..." "Yellow"
    if (Has "winget") {
        winget install -e --id 7zip.7zip --accept-package-agreements --accept-source-agreements --silent 2>$null
        Refresh-Path
    }
    if (Test-Path "C:\Program Files\7-Zip\7z.exe") {
        $script:SEVENZIP = "C:\Program Files\7-Zip\7z.exe"
        $env:Path += ";C:\Program Files\7-Zip"
        OK "7-Zip installed."
    } else {
        WARN "7-Zip install failed. You may need it to extract Kali .7z. Install: https://www.7-zip.org"
    }
}

# ── SSH ──
if (Has "ssh") {
    OK "OpenSSH client available."
} else {
    Log "Enabling OpenSSH client..." "Yellow"
    try {
        Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0 -ErrorAction Stop
        OK "OpenSSH client enabled."
    } catch {
        FAIL "Could not enable OpenSSH. Enable it in Settings → Apps → Optional Features → OpenSSH Client."
        exit 1
    }
}

# ── Python + venv ──
if (-not (Has "python")) {
    Log "Installing Python via winget..." "Yellow"
    if (Has "winget") {
        winget install -e --id Python.Python.3.12 --accept-package-agreements --accept-source-agreements --silent 2>$null
        Refresh-Path
    }
}
if (-not (Has "python")) {
    FAIL "Python not found. Install Python 3.11+ from https://python.org and check 'Add to PATH'."
    exit 1
}
$pyVer = & python --version 2>&1
OK "Python: $pyVer"

# ── Create backend venv if missing ──
$VENV_PY = Join-Path $ROOT "backend\venv\Scripts\python.exe"
if (-not (Test-Path $VENV_PY)) {
    Log "Creating backend virtualenv..." "Yellow"
    & python -m venv (Join-Path $ROOT "backend\venv")
    if (-not (Test-Path $VENV_PY)) {
        FAIL "Could not create backend/venv. Check Python installation."
        exit 1
    }
    OK "Virtual environment created."
}
$PY = $VENV_PY

# ── Install Python packages in venv ──
Log "Checking Python packages in venv..." "Yellow"
$pipPkgs = @(
    "torch --index-url https://download.pytorch.org/whl/cpu",
    "pandas", "numpy", "scapy", "shap", "tqdm", "matplotlib",
    "scikit-learn", "uvicorn", "fastapi", "aiosqlite", "sqlalchemy",
    "slowapi", "python-multipart"
)
# Check what's already installed
$installed = & $PY -m pip list --format=freeze 2>$null
$reqFile = Join-Path $ROOT "backend\requirements.txt"
if (Test-Path $reqFile) {
    Log "Installing from backend/requirements.txt..." "Yellow"
    & $PY -m pip install -q -r $reqFile 2>$null
}

# Ensure critical packages are present
foreach ($pkg in @("torch", "scapy", "shap")) {
    $check = & $PY -c "import $pkg" 2>&1
    if ($LASTEXITCODE -ne 0) {
        Log "Installing $pkg..." "Yellow"
        if ($pkg -eq "torch") {
            & $PY -m pip install -q torch --index-url https://download.pytorch.org/whl/cpu
        } else {
            & $PY -m pip install -q $pkg
        }
    }
}
OK "Python packages ready."

# ═══════════════════════════════════════════════════════════════════════
# PHASE 1 — VIRTUALBOX HOST-ONLY NETWORK
# ═══════════════════════════════════════════════════════════════════════

if (-not $SkipNetwork) {
    Banner "PHASE 1" "VirtualBox Host-Only Network"

    # Find existing host-only interface with 192.168.56.x
    $HOSTONLY_NAME = ""
    $hoOutput = & VBoxManage list hostonlyifs 2>$null
    if ($hoOutput) {
        $hoText = ($hoOutput | Out-String)
        if ($hoText -match "192\.168\.56\.") {
            # Parse the Name field before the IP line
            $lines = $hoText -split "`r?`n"
            for ($i = 0; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -match "^Name:\s+(.+)$") {
                    $candidateName = $Matches[1].Trim()
                }
                if ($lines[$i] -match "192\.168\.56\.") {
                    $HOSTONLY_NAME = $candidateName
                    break
                }
            }
        }
    }

    if ($HOSTONLY_NAME) {
        OK "Host-only adapter exists: '$HOSTONLY_NAME'"
    } else {
        Log "Creating host-only adapter..." "Yellow"
        $createOut = & VBoxManage hostonlyif create 2>&1 | Out-String
        # Parse: "Interface 'VirtualBox Host-Only Ethernet Adapter #N' was successfully created"
        if ($createOut -match "Interface '([^']+)'") {
            $HOSTONLY_NAME = $Matches[1]
        } else {
            # Fallback: list again and pick the last one
            $hoOutput2 = & VBoxManage list hostonlyifs 2>$null | Out-String
            $lines2 = $hoOutput2 -split "`r?`n"
            foreach ($l in $lines2) {
                if ($l -match "^Name:\s+(.+)$") { $HOSTONLY_NAME = $Matches[1].Trim() }
            }
        }

        if (-not $HOSTONLY_NAME) {
            FAIL "Could not create host-only adapter. Open VirtualBox → Tools → Network and create one manually."
            exit 1
        }

        & VBoxManage hostonlyif ipconfig "$HOSTONLY_NAME" --ip $LAB_GATEWAY --netmask $LAB_NETMASK 2>$null
        OK "Created: '$HOSTONLY_NAME' ($LAB_GATEWAY/$LAB_NETMASK)"
    }

    # Disable DHCP on this network
    & VBoxManage dhcpserver modify --ifname "$HOSTONLY_NAME" --disable 2>$null
    OK "DHCP disabled (static IPs only)."

    # Store for later phases
    $script:HOSTONLY = $HOSTONLY_NAME
} else {
    Log "Phase 1 skipped." "DarkGray"
    # Detect existing adapter for later use
    $hoOutput = & VBoxManage list hostonlyifs 2>$null | Out-String
    $lines = $hoOutput -split "`r?`n"
    foreach ($l in $lines) {
        if ($l -match "^Name:\s+(.+)$") { $script:HOSTONLY = $Matches[1].Trim() }
    }
}

# ═══════════════════════════════════════════════════════════════════════
# PHASE 2 — VM DOWNLOAD & IMPORT
# ═══════════════════════════════════════════════════════════════════════

if (-not $SkipVMSetup) {
    Banner "PHASE 2" "VM Download & Import"

    $existingVMs = (& VBoxManage list vms 2>$null) | Out-String

    # ── Kali ──
    if ($existingVMs -match [regex]::Escape("`"$ATTACKER_VM`"")) {
        OK "VM '$ATTACKER_VM' already exists."
    } else {
        $kaliOva = Get-ChildItem -Path $VM_DL_DIR -Filter "*.ova" -ErrorAction SilentlyContinue | Select-Object -First 1
        $kali7z  = Get-ChildItem -Path $VM_DL_DIR -Filter "kali*.7z" -ErrorAction SilentlyContinue | Select-Object -First 1
        $kaliVbox = Get-ChildItem -Path $VM_DL_DIR -Filter "*.vbox" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1

        if (-not $kaliOva -and -not $kaliVbox) {
            if ($kali7z) {
                Log "Extracting Kali .7z archive..." "Yellow"
                & $script:SEVENZIP x $kali7z.FullName -o"$VM_DL_DIR" -y 2>$null
                $kaliOva = Get-ChildItem -Path $VM_DL_DIR -Filter "*.ova" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                $kaliVbox = Get-ChildItem -Path $VM_DL_DIR -Filter "*.vbox" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            } else {
                Log "Downloading Kali Linux VirtualBox image (~3.5 GB)..." "Yellow"
                Write-Host "    This may take 10-30 minutes depending on your connection." -ForegroundColor Gray
                $kaliUrl = "https://cdimage.kali.org/kali-2024.4/kali-linux-2024.4-virtualbox-amd64.7z"
                $kaliDest = Join-Path $VM_DL_DIR "kali-linux-2024.4-virtualbox-amd64.7z"
                try {
                    # Use BITS for resume-capable download, or curl for progress
                    if (Has "curl.exe") {
                        & curl.exe -L -o $kaliDest --progress-bar $kaliUrl
                    } else {
                        Start-BitsTransfer -Source $kaliUrl -Destination $kaliDest -Description "Downloading Kali Linux"
                    }
                    Log "Extracting Kali .7z..." "Yellow"
                    & $script:SEVENZIP x $kaliDest -o"$VM_DL_DIR" -y 2>$null
                    $kaliOva = Get-ChildItem -Path $VM_DL_DIR -Filter "*.ova" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                    $kaliVbox = Get-ChildItem -Path $VM_DL_DIR -Filter "*.vbox" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                } catch {
                    WARN "Auto-download failed: $_"
                    Write-Host ""
                    Write-Host "    Download Kali manually from: https://www.kali.org/get-kali/" -ForegroundColor Magenta
                    Write-Host "    Choose 'Virtual Machines' → 'VirtualBox (64-bit)'" -ForegroundColor Magenta
                    Write-Host "    Place the .7z or extracted .ova in: $VM_DL_DIR" -ForegroundColor Magenta
                    Write-Host "    Then re-run this script." -ForegroundColor Magenta
                    Write-Host ""
                }
            }
        }

        # Import whichever format we found
        if ($kaliOva) {
            Log "Importing Kali OVA as '$ATTACKER_VM'..." "Yellow"
            & VBoxManage import $kaliOva.FullName --vsys 0 --vmname $ATTACKER_VM 2>&1 | Out-Null
            OK "Kali imported."
        } elseif ($kaliVbox) {
            Log "Registering Kali .vbox as '$ATTACKER_VM'..." "Yellow"
            & VBoxManage registervm $kaliVbox.FullName 2>$null
            # Rename if needed
            $origName = $kaliVbox.BaseName
            if ($origName -ne $ATTACKER_VM) {
                & VBoxManage modifyvm $origName --name $ATTACKER_VM 2>$null
            }
            OK "Kali registered."
        } else {
            WARN "No Kali image found. Place .ova or .7z in $VM_DL_DIR and re-run."
        }
    }

    # ── Metasploitable2 (Victim) ──
    if ($existingVMs -match [regex]::Escape("`"$VICTIM_VM`"")) {
        OK "VM '$VICTIM_VM' already exists."
    } else {
        $msVmdk = Get-ChildItem -Path $VM_DL_DIR -Filter "*etasploitable*.vmdk" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        $msZip  = Get-ChildItem -Path $VM_DL_DIR -Filter "*etasploitable*.zip" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1

        if (-not $msVmdk -and -not $msZip) {
            Log "Downloading Metasploitable2 (~800 MB)..." "Yellow"
            $msUrl = "https://sourceforge.net/projects/metasploitable/files/Metasploitable2/metasploitable-linux-2.0.0.zip/download"
            $msDest = Join-Path $VM_DL_DIR "metasploitable-linux-2.0.0.zip"
            try {
                if (Has "curl.exe") {
                    & curl.exe -L -o $msDest --progress-bar $msUrl
                } else {
                    Start-BitsTransfer -Source $msUrl -Destination $msDest -Description "Downloading Metasploitable2"
                }
            } catch {
                WARN "Auto-download failed. Download manually from:"
                Write-Host "    https://sourceforge.net/projects/metasploitable/" -ForegroundColor Magenta
                Write-Host "    Place the .zip in: $VM_DL_DIR" -ForegroundColor Magenta
            }
            $msZip = Get-ChildItem -Path $VM_DL_DIR -Filter "*etasploitable*.zip" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        }

        if ($msZip -and -not $msVmdk) {
            Log "Extracting Metasploitable2..." "Yellow"
            Expand-Archive -Path $msZip.FullName -DestinationPath $VM_DL_DIR -Force -ErrorAction SilentlyContinue
            $msVmdk = Get-ChildItem -Path $VM_DL_DIR -Filter "*.vmdk" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        }

        if ($msVmdk) {
            Log "Creating VM '$VICTIM_VM' from VMDK..." "Yellow"
            & VBoxManage createvm --name $VICTIM_VM --ostype "Linux26" --register 2>$null
            & VBoxManage modifyvm $VICTIM_VM --memory 1024 --cpus 1 --audio-enabled off 2>$null
            & VBoxManage storagectl $VICTIM_VM --name "SATA" --add sata --controller IntelAHCI 2>$null
            & VBoxManage storageattach $VICTIM_VM --storagectl "SATA" --port 0 --device 0 --type hdd --medium $msVmdk.FullName 2>$null
            OK "Metasploitable2 VM created."
        } else {
            WARN "No Metasploitable VMDK found."
        }
    }

    # ── Peer (clone of victim) ──
    if ($existingVMs -match [regex]::Escape("`"$PEER_VM`"")) {
        OK "VM '$PEER_VM' already exists."
    } else {
        $victimCheck = (& VBoxManage list vms 2>$null) | Out-String
        if ($victimCheck -match [regex]::Escape("`"$VICTIM_VM`"")) {
            Log "Cloning '$VICTIM_VM' → '$PEER_VM'..." "Yellow"
            & VBoxManage clonevm $VICTIM_VM --name $PEER_VM --register --mode machine 2>$null
            OK "Peer VM cloned."
        } else {
            WARN "Cannot clone peer: '$VICTIM_VM' not found."
        }
    }

    # ═══════════════════════════════════════════════════════════════════
    # PHASE 3 — VM CONFIGURATION
    # ═══════════════════════════════════════════════════════════════════
    Banner "PHASE 3" "VM Configuration (Network, SSH, Snapshots)"

    if (-not $script:HOSTONLY) {
        # Detect from VBox
        $hoOut = & VBoxManage list hostonlyifs 2>$null | Out-String
        $hoLines = $hoOut -split "`r?`n"
        foreach ($hl in $hoLines) {
            if ($hl -match "^Name:\s+(.+)$") { $script:HOSTONLY = $Matches[1].Trim() }
        }
    }
    $hoName = $script:HOSTONLY
    if (-not $hoName) { $hoName = "VirtualBox Host-Only Ethernet Adapter" }

    $allVMs = @(
        @{ Name = $ATTACKER_VM; IP = $ATTACKER_IP },
        @{ Name = $VICTIM_VM;   IP = $VICTIM_IP },
        @{ Name = $PEER_VM;     IP = $PEER_IP }
    )

    foreach ($vm in $allVMs) {
        $vmName = $vm.Name
        $vmCheck = (& VBoxManage list vms 2>$null) | Out-String
        if (-not ($vmCheck -match [regex]::Escape("`"$vmName`""))) {
            WARN "'$vmName' not found — skipping."
            continue
        }

        Log "Configuring '$vmName'..." "Yellow"
        & VBoxManage controlvm $vmName poweroff 2>$null
        Start-Sleep -Seconds 2

        # Set host-only adapter on nic1, disable nic2-4
        & VBoxManage modifyvm $vmName --nic1 hostonly 2>$null
        & VBoxManage modifyvm $vmName --hostonlyadapter1 "$hoName" 2>$null
        & VBoxManage modifyvm $vmName --nic2 none --nic3 none --nic4 none 2>$null
        OK "  $vmName → host-only ($hoName), isolated."
    }

    # Boot VMs
    Log "Booting all VMs headless..." "Yellow"
    foreach ($vm in $allVMs) {
        $vmCheck = (& VBoxManage list vms 2>$null) | Out-String
        if ($vmCheck -match [regex]::Escape("`"$($vm.Name)`"")) {
            & VBoxManage startvm $vm.Name --type headless 2>$null
        }
    }
    Log "Waiting 60s for VMs to boot..." "Yellow"
    Start-Sleep -Seconds 60

    # ── Manual network config instructions (Guest Additions may not be installed) ──
    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
    Write-Host "  ║  NETWORK SETUP: Log into each VM console and run:                ║" -ForegroundColor Magenta
    Write-Host "  ║                                                                   ║" -ForegroundColor Magenta
    Write-Host "  ║  Kali ($ATTACKER_VM) — user: kali / kali                         ║" -ForegroundColor Magenta
    Write-Host "  ║    sudo ip addr flush dev eth0                                    ║" -ForegroundColor Magenta
    Write-Host "  ║    sudo ip addr add $ATTACKER_IP/24 dev eth0                     ║" -ForegroundColor Magenta
    Write-Host "  ║    sudo ip link set eth0 up                                       ║" -ForegroundColor Magenta
    Write-Host "  ║                                                                   ║" -ForegroundColor Magenta
    Write-Host "  ║  Victim ($VICTIM_VM) — user: msfadmin / msfadmin                 ║" -ForegroundColor Magenta
    Write-Host "  ║    sudo ifconfig eth0 $VICTIM_IP netmask $LAB_NETMASK up         ║" -ForegroundColor Magenta
    Write-Host "  ║                                                                   ║" -ForegroundColor Magenta
    Write-Host "  ║  Peer ($PEER_VM) — user: msfadmin / msfadmin                     ║" -ForegroundColor Magenta
    Write-Host "  ║    sudo ifconfig eth0 $PEER_IP netmask $LAB_NETMASK up           ║" -ForegroundColor Magenta
    Write-Host "  ║                                                                   ║" -ForegroundColor Magenta
    Write-Host "  ║  On Kali, also install tools:                                     ║" -ForegroundColor Magenta
    Write-Host "  ║    sudo apt update && sudo apt install -y nmap hydra sshpass \     ║" -ForegroundColor Magenta
    Write-Host "  ║      smbclient snmp apache2-utils curl                            ║" -ForegroundColor Magenta
    Write-Host "  ║                                                                   ║" -ForegroundColor Magenta
    Write-Host "  ║  Verify: from Kali, ping $VICTIM_IP and $PEER_IP                 ║" -ForegroundColor Magenta
    Write-Host "  ║  Verify isolation: ping 8.8.8.8 should FAIL                       ║" -ForegroundColor Magenta
    Write-Host "  ╚═══════════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "  Press ENTER when all VMs are configured..." -ForegroundColor White -NoNewline
    Read-Host

    # ── SSH key setup ──
    Log "Setting up SSH key auth (host → Kali)..." "Yellow"
    $sshDir  = Join-Path $env:USERPROFILE ".ssh"
    $sshKey  = Join-Path $sshDir "id_rsa"
    $sshPub  = "$sshKey.pub"

    if (-not (Test-Path $sshDir)) { New-Item -ItemType Directory -Path $sshDir -Force | Out-Null }

    if (-not (Test-Path $sshKey)) {
        Log "Generating SSH keypair..." "Yellow"
        # Windows ssh-keygen: use empty string for no passphrase
        & ssh-keygen -t rsa -b 4096 -f $sshKey -N "" -q
        OK "SSH key generated: $sshKey"
    } else {
        OK "SSH key exists: $sshKey"
    }

    # Copy key to Kali
    Log "Copying SSH public key to Kali..." "Yellow"
    Write-Host "    You will be prompted for the Kali password: kali" -ForegroundColor Gray
    $pubKeyContent = Get-Content $sshPub -Raw
    $pubKeyContent = $pubKeyContent.Trim()
    # Windows doesn't have ssh-copy-id; pipe key via ssh
    $copyCmd = "mkdir -p ~/.ssh && echo '$pubKeyContent' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && chmod 700 ~/.ssh"
    try {
        & ssh -o StrictHostKeyChecking=no "$ATTACKER_USER@$ATTACKER_IP" $copyCmd
        OK "SSH key deployed."
    } catch {
        WARN "SSH key copy failed. You'll be prompted for password during collection."
    }

    # Verify SSH
    $sshTest = & ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$ATTACKER_USER@$ATTACKER_IP" "echo GARUD_OK" 2>$null
    if ($sshTest -match "GARUD_OK") {
        OK "SSH passwordless auth verified."
    } else {
        WARN "SSH key auth test failed. Collection will prompt for password."
    }

    # ── Verify isolation ──
    $isoTest = & ssh -o BatchMode=yes -o ConnectTimeout=5 "$ATTACKER_USER@$ATTACKER_IP" "ping -c 1 -W 3 8.8.8.8 2>/dev/null && echo LEAK || echo SAFE" 2>$null
    if ($isoTest -match "SAFE") {
        OK "Lab is isolated — Kali has no internet access."
    } elseif ($isoTest -match "LEAK") {
        FAIL "SECURITY: Kali can reach the internet! Remove NAT adapters from all VMs."
    }

    # ── Take clean snapshots ──
    Log "Taking 'clean' snapshots..." "Yellow"
    foreach ($vm in $allVMs) {
        $vmCheck = (& VBoxManage list vms 2>$null) | Out-String
        if ($vmCheck -match [regex]::Escape("`"$($vm.Name)`"")) {
            & VBoxManage snapshot $vm.Name delete "clean" 2>$null
            Start-Sleep -Seconds 2
            & VBoxManage snapshot $vm.Name take "clean" --description "Clean baseline" 2>$null
            OK "  Snapshot 'clean' → $($vm.Name)"
        }
    }

    # Power off (harness manages lifecycle)
    foreach ($vm in $allVMs) {
        & VBoxManage controlvm $vm.Name poweroff 2>$null
    }
    Start-Sleep -Seconds 3
    OK "Phase 3 complete."
} else {
    Log "Phases 2-3 skipped." "DarkGray"
}

# ═══════════════════════════════════════════════════════════════════════
# PHASE 4 — LAB CONFIG VALIDATION
# ═══════════════════════════════════════════════════════════════════════

Banner "PHASE 4" "Lab Config Validation"

# Update lab_config.json
Log "Updating lab_config.json..." "Yellow"

$labConfig = Get-Content $LAB_CONFIG_PATH -Raw | ConvertFrom-Json

# Detect dumpcap interface for VirtualBox
$dcapList = & $script:DUMPCAP -D 2>$null | Out-String
$captureIface = ""
if ($dcapList) {
    $dcapLines = $dcapList -split "`r?`n"
    foreach ($dl in $dcapLines) {
        if ($dl -match "VirtualBox|Host-Only|vboxnet") {
            # Windows format: "3. \Device\NPF_{GUID} (VirtualBox Host-Only Ethernet Adapter)"
            if ($dl -match "(\\Device\\NPF_\{[^}]+\})") {
                $captureIface = $Matches[1]
            } elseif ($dl -match "^\d+\.\s+(\S+)") {
                $captureIface = $Matches[1]
            }
            break
        }
    }
}

if ($captureIface) {
    OK "Capture interface: $captureIface"
    $labConfig.capture.interface = $captureIface
} else {
    WARN "Could not auto-detect capture interface. Run: & '$script:DUMPCAP' -D"
    WARN "Then update lab_config.json 'capture.interface' manually."
}

# Set dumpcap path and run count
$labConfig.capture.dumpcap = $script:DUMPCAP
$labConfig.runs = $Runs

# Write back
$labConfig | ConvertTo-Json -Depth 10 | Set-Content $LAB_CONFIG_PATH -Encoding UTF8
OK "Config saved ($Runs runs)."

# Dry-run validation
Log "Running dry-run..." "Yellow"
& $PY (Join-Path $LAB_DIR "collect_dataset.py") --config $LAB_CONFIG_PATH --dry-run
if ($LASTEXITCODE -eq 0) {
    OK "Dry-run passed."
} else {
    FAIL "Dry-run failed. Check lab_config.json, ensure VBoxManage/dumpcap/ssh are on PATH."
    exit 1
}

# ═══════════════════════════════════════════════════════════════════════
# PHASE 5 — CAMPAIGN DATASET COLLECTION
# ═══════════════════════════════════════════════════════════════════════

if (-not $SkipCollection) {
    Banner "PHASE 5" "Campaign Dataset Collection ($Runs runs)"

    $estMinutes = $Runs * 25
    Log "Estimated time: ~$estMinutes minutes" "Yellow"
    Write-Host "    Kill chain: Benign → Recon → Cred → Access → Discovery → Lateral → C2 → Collect → Exfil → Impact" -ForegroundColor DarkGray

    # Reset lab
    & $PY (Join-Path $LAB_DIR "reset_lab.py") --config $LAB_CONFIG_PATH 2>$null

    $t0 = Get-Date
    & $PY (Join-Path $LAB_DIR "collect_dataset.py") --config $LAB_CONFIG_PATH --out $DATASET
    $elapsed = [math]::Round(((Get-Date) - $t0).TotalMinutes, 1)

    $collectedRuns = (Get-ChildItem -Path $DATASET -Directory -Filter "run_*" -ErrorAction SilentlyContinue |
        Where-Object { Test-Path (Join-Path $_.FullName "traffic.pcap") }).Count
    OK "Collected $collectedRuns runs in $elapsed minutes."
} else {
    Log "Phase 5 skipped." "DarkGray"
}

# ═══════════════════════════════════════════════════════════════════════
# PHASE 6 — FLOW EXTRACTION
# ═══════════════════════════════════════════════════════════════════════

Banner "PHASE 6" "Flow Extraction"

$pcapRuns = Get-ChildItem -Path $DATASET -Directory -Filter "run_*" -ErrorAction SilentlyContinue |
    Where-Object { Test-Path (Join-Path $_.FullName "traffic.pcap") }

if ($pcapRuns.Count -eq 0) {
    WARN "No captured runs in $DATASET. Skipping extraction."
} else {
    Log "Extracting flows from $($pcapRuns.Count) runs..." "Yellow"
    & $PY (Join-Path $LAB_DIR "extract_flows.py") --dataset $DATASET
    if ($LASTEXITCODE -ne 0) { FAIL "Extraction failed."; exit 1 }

    $totalFlows = 0
    Get-ChildItem -Path $DATASET -Recurse -Filter "flows.csv" | ForEach-Object {
        $n = (Get-Content $_.FullName | Measure-Object -Line).Lines - 1
        $totalFlows += $n
        Log "  $($_.Directory.Name): $n flows" "Gray"
    }
    OK "$totalFlows flows extracted."
}

# ═══════════════════════════════════════════════════════════════════════
# PHASE 7 — MERGE LAB + CIC-IDS DATA
# ═══════════════════════════════════════════════════════════════════════

Banner "PHASE 7" "Merge Lab + CIC-IDS Data"

$baseFlows    = Join-Path $ROOT "real_flows.csv"
$combinedCSV  = Join-Path $ROOT "combined_flows.csv"
$mergeScript  = Join-Path $LAB_DIR "merge_lab_flows.py"

# If base data doesn't exist, build it
if (-not (Test-Path $baseFlows)) {
    WARN "real_flows.csv not found. Building from CIC-IDS2017..."
    $rawDir = Join-Path $DATA_DIR "raw_cicids"
    if (-not (Test-Path $rawDir)) {
        Log "Downloading CIC-IDS2017 dataset..." "Yellow"
        & $PY (Join-Path $DATA_DIR "download_cicids.py") 2>$null
    }
    if (Test-Path $rawDir) {
        & $PY (Join-Path $DATA_DIR "preprocess_cicids.py") --input-dir $rawDir --output $baseFlows --sample 40000
        & $PY (Join-Path $DATA_DIR "augment_lateral_movement.py") --target $baseFlows 2>$null
        & $PY (Join-Path $DATA_DIR "augment_initial_access.py") --target $baseFlows 2>$null
        & $PY (Join-Path $DATA_DIR "fix_initial_access_sessions.py") --target $baseFlows 2>$null
    }
}

# Merge
if (Test-Path $mergeScript) {
    if (Test-Path $baseFlows) {
        & $PY $mergeScript --dataset $DATASET --base $baseFlows --output $combinedCSV
    } else {
        & $PY $mergeScript --dataset $DATASET --output $combinedCSV
    }
    if ($LASTEXITCODE -eq 0) {
        OK "Merged → $combinedCSV"
    } else {
        WARN "Merge had issues. Falling back to base data only."
        $combinedCSV = $baseFlows
    }
} else {
    WARN "merge_lab_flows.py not found. Using base data."
    $combinedCSV = $baseFlows
}

# ═══════════════════════════════════════════════════════════════════════
# PHASE 8 — MODEL RETRAINING (Fine-Tune or From-Scratch)
# ═══════════════════════════════════════════════════════════════════════

Banner "PHASE 8" "Model Retraining — Mode: $TrainMode ($Epochs epochs)"

# Backup current artifacts
$backupDir = Join-Path $ARTIFACTS "backup_$TIMESTAMP"
if (Test-Path $ARTIFACTS) {
    Copy-Item -Path $ARTIFACTS -Destination $backupDir -Recurse -Force
    OK "Backup → $backupDir"
}

$trainData = $combinedCSV
if (-not (Test-Path $trainData)) { $trainData = $baseFlows }
if (-not (Test-Path $trainData)) {
    FAIL "No training data found. Cannot retrain."
    exit 1
}

$finetuneScript = Join-Path $SCRIPT_DIR "finetune_model.py"
$scratchScript  = Join-Path $SCRIPT_DIR "train_from_scratch.py"

$t0 = Get-Date

if ($TrainMode -eq "finetune") {
    # ── FINE-TUNE (recommended) ──
    Log "Mode: FINE-TUNE — preserving existing detection (F1=0.862)" "Cyan"
    Log "  LR: 1e-4 (10x lower), patience: 5, gradient clipping: ON" "DarkGray"
    if ($FreezeLSTM) {
        Log "  LSTM backbone: FROZEN (head-only training)" "DarkGray"
    } else {
        Log "  LSTM backbone: trainable (full fine-tune)" "DarkGray"
    }

    $ftArgs = @(
        $finetuneScript,
        "--data", $trainData,
        "--artifacts", $ARTIFACTS,
        "--out", $ARTIFACTS,
        "--epochs", $Epochs,
        "--lr", "1e-4",
        "--batch-size", "128",
        "--focal-gamma", "2.0",
        "--class-weight-max", "6.0",
        "--patience", "5",
        "--augment-stages", "Exfiltration",
        "--augment-sessions", "300"
    )
    if ($FreezeLSTM) { $ftArgs += "--freeze-lstm" }

    & $PY @ftArgs

} else {
    # ── TRAIN FROM SCRATCH ──
    Log "Mode: FROM SCRATCH — rebuilding model entirely" "Cyan"
    Log "  LR: 1e-3, epochs: $Epochs, full architecture rebuild" "DarkGray"

    & $PY $scratchScript `
        --data $trainData `
        --out $ARTIFACTS `
        --epochs $Epochs `
        --batch-size 128 `
        --hidden-size 256 `
        --num-layers 2 `
        --dropout 0.25 `
        --lr 1e-3 `
        --weight-decay 1e-4 `
        --class-weight-max 6.0 `
        --stage-loss focal `
        --focal-gamma 2.0 `
        --stage-target current `
        --augment-stages "Exfiltration" `
        --augment-sessions 300
}

$trainMins = [math]::Round(((Get-Date) - $t0).TotalMinutes, 1)

if ($LASTEXITCODE -ne 0) {
    FAIL "Training failed. Restore from: $backupDir"
    Write-Host "    Copy-Item -Path '$backupDir\*' -Dest '$ARTIFACTS' -Recurse -Force" -ForegroundColor Gray
    exit 1
}
OK "Training complete in $trainMins minutes (mode: $TrainMode)."

# ═══════════════════════════════════════════════════════════════════════
# PHASE 9 — LOGIT CALIBRATION
# ═══════════════════════════════════════════════════════════════════════

Banner "PHASE 9" "Post-Hoc Stage Logit Calibration"

$calibScript = Join-Path $ROOT "experiments\calibrate_stage_logits.py"
if (Test-Path $calibScript) {
    & $PY $calibScript
    if ($LASTEXITCODE -eq 0) {
        OK "Calibration complete."
        Write-Host ""
        Write-Host "  ┌─────────────────────────────────────────────────────────┐" -ForegroundColor Yellow
        Write-Host "  │  Copy the 'Final bias' values printed above into:      │" -ForegroundColor Yellow
        Write-Host "  │  backend\artifacts\config.json → 'stage_logit_bias'    │" -ForegroundColor Yellow
        Write-Host "  └─────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
    } else {
        WARN "Calibration had issues. Model works without calibration."
    }
} else {
    WARN "Calibration script not found. Skipping."
}

# ═══════════════════════════════════════════════════════════════════════
# PHASE 10 — VERIFICATION
# ═══════════════════════════════════════════════════════════════════════

Banner "PHASE 10" "Artifact Verification & Tests"

foreach ($f in @("world_model.pt", "scaler.pkl", "config.json")) {
    $p = Join-Path $ARTIFACTS $f
    if (Test-Path $p) {
        $sz = [math]::Round((Get-Item $p).Length / 1KB, 1)
        OK "  $f ($sz KB)"
    } else {
        FAIL "  $f MISSING!"
    }
}

# Run tests
Log "Running test suite..." "Yellow"
& $PY -m pytest (Join-Path $ROOT "backend\tests") -v --tb=short 2>&1 | ForEach-Object {
    if ($_ -match "PASSED")   { Write-Host "  $_" -ForegroundColor Green }
    elseif ($_ -match "FAIL") { Write-Host "  $_" -ForegroundColor Red }
    else                       { Write-Host "  $_" -ForegroundColor Gray }
}
if ($LASTEXITCODE -eq 0) { OK "All tests passed." }
else { WARN "Some tests failed — may need fixture updates for new model." }

# ═══════════════════════════════════════════════════════════════════════
# DONE
# ═══════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║              LAB + RETRAIN COMPLETE                         ║" -ForegroundColor Green
Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Lab runs      : $((Get-ChildItem -Path $DATASET -Directory -Filter 'run_*' -ErrorAction SilentlyContinue).Count)" -ForegroundColor Cyan
Write-Host "  Training data : $trainData" -ForegroundColor Cyan
Write-Host "  Model artifacts: $ARTIFACTS" -ForegroundColor Cyan
Write-Host "  Backup         : $backupDir" -ForegroundColor DarkGray
Write-Host "  Log            : $LOG_FILE" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Next steps:" -ForegroundColor White
Write-Host "    1. Copy calibration biases into config.json" -ForegroundColor Yellow
Write-Host "    2. powershell -File .\start_all.ps1" -ForegroundColor Yellow
Write-Host "    3. Upload a lab PCAP:  curl -X POST http://localhost:8000/ingest/pcap -F 'file=@$DATASET\run_001\traffic.pcap'" -ForegroundColor DarkGray
Write-Host ""
