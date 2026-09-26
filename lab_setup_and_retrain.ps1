<#
.SYNOPSIS
    Redirector — The full lab setup has moved to setup\lab_setup_and_retrain.ps1

.DESCRIPTION
    This file forwards to setup\lab_setup_and_retrain.ps1 with all arguments.
    The setup\ folder contains the complete lab harness pipeline.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\lab_setup_and_retrain.ps1
    powershell -ExecutionPolicy Bypass -File .\lab_setup_and_retrain.ps1 -TrainMode finetune
    powershell -ExecutionPolicy Bypass -File .\lab_setup_and_retrain.ps1 -SkipToTraining
#>

$setupScript = Join-Path $PSScriptRoot "setup\lab_setup_and_retrain.ps1"

if (-not (Test-Path $setupScript)) {
    Write-Host "ERROR: setup\lab_setup_and_retrain.ps1 not found." -ForegroundColor Red
    exit 1
}

Write-Host "Forwarding to setup\lab_setup_and_retrain.ps1..." -ForegroundColor Cyan
& $setupScript @args
