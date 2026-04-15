<#
.SYNOPSIS
    Ultimate End-to-End Orchestrator for Kernel C2 Beacon Hunter.
    Handles environment setup, execution, pausing, and complete deep-clean teardown.
    Defaults to DRY-RUN mode for safe baselining.
#>

#Requires -RunAsAdministrator

param (
    [switch]$ArmedMode,
    [int]$ConfidenceThreshold = 75,
    [switch]$PurgeLogsOnExit = $true
)

$ScriptDir = Split-Path $PSCommandPath -Parent
Set-Location $ScriptDir

$Host.UI.RawUI.WindowTitle = "C2 Hunter - Full Lifecycle Manager"

Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "  C2 Hunter End-to-End Lifecycle Manager" -ForegroundColor Cyan
Write-Host "===================================================`n" -ForegroundColor Cyan

$MonitorProcess = $null
$DefendProcess = $null
$PythonInstallerUrl = "https://www.python.org/ftp/python/3.12.2/python-3.12.2-amd64.exe"

try {
    # ==========================================
    # PHASE 1: ENVIRONMENT SETUP
    # ==========================================
    Write-Host "[1/5] Preparing Environment..." -ForegroundColor Yellow

    Write-Host "      [*] Unblocking downloaded scripts (Mark of the Web)..." -ForegroundColor DarkGray
    Get-ChildItem -Path $ScriptDir -Filter "*.ps1" -Recurse | Unblock-File -ErrorAction SilentlyContinue
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

    $MachinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $UserPath    = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:PATH    = "$MachinePath;$UserPath"
    $env:PATH    = ($env:PATH -split ';' | Where-Object { $_ -notmatch 'WindowsApps' -and $_ -match '\S' }) -join ';'

    try {
        $null = python --version 2>&1
        Write-Host "      [+] Python is installed." -ForegroundColor Green
    } catch {
        Write-Host "      [-] Python not found. Installing Python 3.12 unattended..." -ForegroundColor DarkYellow
        $InstallerPath = "$env:TEMP\python-installer.exe"
        Invoke-WebRequest -Uri $PythonInstallerUrl -OutFile $InstallerPath

        # Install python
        Start-Process -FilePath $InstallerPath -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0" -Wait -NoNewWindow
        Remove-Item $InstallerPath -Force

        # RE-REFRESH PATH safely to pick up the newly installed Python
        $MachinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
        $UserPath    = [Environment]::GetEnvironmentVariable('Path', 'User')
        $env:PATH    = "$MachinePath;$UserPath"
        $env:PATH    = ($env:PATH -split ';' | Where-Object { $_ -notmatch 'WindowsApps' -and $_ -match '\S' }) -join ';'
    }

    Write-Host "      [*] Checking Python dependencies..." -ForegroundColor DarkGray
    $ReqPath = Join-Path $ScriptDir "requirements.txt"
    if (Test-Path $ReqPath) {
        python -m pip install -r $ReqPath --quiet 2>&1 | Out-Null
    } else {
        python -m pip install scikit-learn numpy joblib scipy --quiet 2>&1 | Out-Null
    }
    Write-Host "      [+] Environment Ready.`n" -ForegroundColor Green


    # ==========================================
    # PHASE 2: DEPLOY KERNEL TELEMETRY
    # ==========================================
    Write-Host "[2/5] Initializing Kernel Tracing..." -ForegroundColor Yellow
    $InstallScript = Join-Path $ScriptDir "InstallKernelC2Hunter.ps1"
    if (Test-Path $InstallScript) {
        & $InstallScript
    } else {
        throw "Missing InstallKernelC2Hunter.ps1"
    }
    Write-Host "      [+] Telemetry Active.`n" -ForegroundColor Green


    # ==========================================
    # PHASE 3: EXECUTE DAEMONS
    # ==========================================
    Write-Host "[3/5] Spawning Hunter & Defender Daemons..." -ForegroundColor Yellow

    $MonitorScript = Join-Path $ScriptDir "MonitorKernelC2BeaconHunter_v3.ps1"
    $MonitorArgs = "-NoExit -Command `"& '$MonitorScript' -Format JSONL`""
    $MonitorProcess = Start-Process powershell.exe -ArgumentList $MonitorArgs -PassThru -WindowStyle Normal

    $DefendScript = Join-Path $ScriptDir "c2_defend.ps1"
    $DefendArgsStr = "& '$DefendScript' -ConfidenceThreshold $ConfidenceThreshold"

    # SAFETY DEFAULT: Enforce DryRun unless ArmedMode is explicitly passed
    if (-not $ArmedMode) { $DefendArgsStr += " -DryRun" }

    $DefendProcess = Start-Process powershell.exe -ArgumentList "-NoExit -Command `"$DefendArgsStr`"" -PassThru -WindowStyle Normal

    Write-Host "      [+] Daemons Running.`n" -ForegroundColor Green

    # ==========================================
    # PHASE 4: THE PAUSE
    # ==========================================
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host " [!] COLLECTION IS LIVE AND RUNNING [!]" -ForegroundColor Green
    if (-not $ArmedMode) {
        Write-Host " [*] DEFENDER IS IN DRY-RUN MODE (Safe Baselining)." -ForegroundColor Yellow
    } else {
        Write-Host " [!] DEFENDER IS ARMED (Will kill processes & block IPs)." -ForegroundColor Red
    }
    Write-Host "===================================================`n" -ForegroundColor Cyan

    Write-Host "Press [ENTER] to safely STOP capture and UNINSTALL the environment..." -ForegroundColor White
    Read-Host

} finally {
    # ==========================================
    # PHASE 5: GUARANTEED TEARDOWN
    # ==========================================
    Write-Host "`n[5/5] Commencing Deep Clean & Teardown..." -ForegroundColor Yellow

    if ($MonitorProcess -and -not $MonitorProcess.HasExited) { Stop-Process -Id $MonitorProcess.Id -Force }
    if ($DefendProcess -and -not $DefendProcess.HasExited) { Stop-Process -Id $DefendProcess.Id -Force }
    Write-Host "      [-] Daemons terminated." -ForegroundColor DarkGray

    $UninstallScript = Join-Path $ScriptDir "UninstallKernelC2Hunter.ps1"
    if (Test-Path $UninstallScript) {
        & $UninstallScript
    } else {
        logman stop "C2KernelTrace" -ets 2>&1 | Out-Null
        logman delete "C2KernelTrace" -ets 2>&1 | Out-Null
        pktmon stop 2>&1 | Out-Null
    }
    Write-Host "      [-] Kernel tracing stopped and deleted." -ForegroundColor DarkGray

    try {
        python -m pip uninstall scikit-learn numpy joblib scipy -y --quiet 2>&1 | Out-Null
        Write-Host "      [-] Python ML dependencies purged." -ForegroundColor DarkGray
    } catch { }

    if ($PurgeLogsOnExit) {
        $Artifacts = @("C:\Temp\C2KernelMonitoring_v3.jsonl", "C:\Temp\C2KernelMonitoring_v3.json", "C:\Temp\C2KernelMonitoring_v3.jsonl.bak", "C:\Temp\C2Kernel.etl")
        foreach ($file in $Artifacts) {
            if (Test-Path $file) { Remove-Item $file -Force -ErrorAction SilentlyContinue }
        }
        Write-Host "      [-] Logs and ETW artifacts purged." -ForegroundColor DarkGray
    }

    Write-Host "`n[+] Environment successfully restored to pre-flight state. Goodbye!" -ForegroundColor Green
}