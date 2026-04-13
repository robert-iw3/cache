#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Master Orchestrator for Kernel C2 Beacon Hunter v3.0

.DESCRIPTION
    This script automates the entire lifecycle of the C2 Hunter project:
    1. Validates Admin privileges and Python installation.
    2. Runs the Kernel ETW installer.
    3. Spawns the Monitor script (with the ML daemon) in a new window.
    4. Spawns the Active Defense script in a new window.
    5. Waits for the user to trigger a shutdown, then safely cleans up the environment.

.EXAMPLE
    # To run with active defense enabled (will kill processes/block IPs):
    .\Start-C2Hunter.ps1

    # To run in dry-run mode (defender will only log actions without enforcing):
    .\Start-C2Hunter.ps1 -DryRunDefense

    # To adjust the confidence threshold for active defense actions:
    .\Start-C2Hunter.ps1 -ConfidenceThreshold 80

    # To adjust the batch analysis interval for the monitor engine:
    .\Start-C2Hunter.ps1 -BatchAnalysisIntervalSeconds 60
#>

param (
    [switch]$DryRunDefense,
    [int]$ConfidenceThreshold = 75,
    [int]$BatchAnalysisIntervalSeconds = 30
)

$ScriptDir = Split-Path $PSCommandPath -Parent
Set-Location $ScriptDir

$Host.UI.RawUI.WindowTitle = "C2 Hunter Master Orchestrator"
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "  Kernel C2 Beacon Hunter v3.0 - Orchestrator" -ForegroundColor Cyan
Write-Host "===================================================`n" -ForegroundColor Cyan

# --- 1. Pre-flight Checks ---
Write-Host "[*] Checking prerequisites..." -ForegroundColor Gray
try {
    $null = python --version 2>&1
    Write-Host "    [+] Python found." -ForegroundColor Green
} catch {
    Write-Host "    [!] Python not found in PATH. The ML Daemon will fail to start." -ForegroundColor Red
    Write-Host "    Please install Python and run 'pip install -r requirements.txt'." -ForegroundColor Red
    exit
}

# --- 2. Installation / Setup ---
Write-Host "`n[*] Initializing Kernel Telemetry (ETW & Pktmon)..." -ForegroundColor Gray
$InstallScript = Join-Path $ScriptDir "InstallKernelC2Hunter.ps1"
if (Test-Path $InstallScript) {
    & $InstallScript
} else {
    Write-Host "    [!] Could not find InstallKernelC2Hunter.ps1!" -ForegroundColor Red
    exit
}

try {
    # --- 3. Spawn Monitor Engine ---
    Write-Host "`n[*] Spawning Monitor Engine & ML Daemon..." -ForegroundColor Gray
    $MonitorScript = Join-Path $ScriptDir "MonitorKernelC2BeaconHunter_v3.ps1"
    $MonitorArgs = "-NoExit -Command `"& '$MonitorScript' -BatchAnalysisIntervalSeconds $BatchAnalysisIntervalSeconds -Format JSONL`""
    $MonitorProcess = Start-Process powershell.exe -ArgumentList $MonitorArgs -PassThru -WindowStyle Normal

    # --- 4. Spawn Active Defense Engine ---
    Write-Host "[*] Spawning Active Defense Engine..." -ForegroundColor Gray
    $DefendScript = Join-Path $ScriptDir "c2_defend.ps1"
    $DefendArgsStr = "& '$DefendScript' -ConfidenceThreshold $ConfidenceThreshold"
    if ($DryRunDefense) { $DefendArgsStr += " -DryRun" }

    $DefendArgs = "-NoExit -Command `"$DefendArgsStr`""
    $DefendProcess = Start-Process powershell.exe -ArgumentList $DefendArgs -PassThru -WindowStyle Normal

    # --- 5. Lifecycle Management ---
    Write-Host "`n===================================================" -ForegroundColor Cyan
    Write-Host " [+] System is LIVE and Monitoring." -ForegroundColor Green
    if ($DryRunDefense) { Write-Host " [+] Defender is in DRY-RUN mode." -ForegroundColor Yellow }
    else { Write-Host " [!] Defender is ARMED (Will kill processes/block IPs)." -ForegroundColor Red }
    Write-Host "===================================================`n" -ForegroundColor Cyan

    Write-Host "Press [ENTER] to safely shutdown and clean up the environment..." -ForegroundColor White
    Read-Host
    } finally {
        # --- 6. Teardown / Cleanup ---
        Write-Host "`n[*] Commencing Teardown Sequence..." -ForegroundColor Yellow

        if ($MonitorProcess -and -not $MonitorProcess.HasExited) {
            Write-Host "    [-] Stopping Monitor Engine..." -ForegroundColor Gray
            Stop-Process -Id $MonitorProcess.Id -Force
        }
        if ($DefendProcess -and -not $DefendProcess.HasExited) {
            Write-Host "    [-] Stopping Active Defense Engine..." -ForegroundColor Gray
            Stop-Process -Id $DefendProcess.Id -Force
        }

        Write-Host "    [-] Removing Kernel Telemetry..." -ForegroundColor Gray
        $UninstallScript = Join-Path $ScriptDir "UninstallKernelC2Hunter.ps1"
        if (Test-Path $UninstallScript) {
            & $UninstallScript
        }

    Write-Host "`n[+] Environment safely restored. Goodbye!" -ForegroundColor Green
}

Start-Sleep -Seconds 2