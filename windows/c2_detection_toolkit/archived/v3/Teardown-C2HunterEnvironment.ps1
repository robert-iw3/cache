#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Complete Environment Teardown for Kernel C2 Beacon Hunter.
    Removes ML dependencies, stops kernel tracing, and cleans up artifacts.
#>

$ScriptDir = Split-Path $PSCommandPath -Parent

Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "  C2 Hunter - Environment Teardown" -ForegroundColor Cyan
Write-Host "===================================================`n" -ForegroundColor Cyan

# 1. Stop Kernel Telemetry (Calling your existing uninstaller)
Write-Host "[*] Halting Kernel Telemetry (ETW/Pktmon)..." -ForegroundColor Yellow
$UninstallScript = Join-Path $ScriptDir "UninstallKernelC2Hunter.ps1"
if (Test-Path $UninstallScript) {
    & $UninstallScript
} else {
    # Fallback just in case the script is missing
    logman stop "C2KernelTrace" -ets 2>&1 | Out-Null
    logman delete "C2KernelTrace" -ets 2>&1 | Out-Null
    pktmon stop 2>&1 | Out-Null
}
Write-Host "    [+] Telemetry stopped." -ForegroundColor Green

# 2. Uninstall Python Dependencies
Write-Host "`n[*] Removing Python ML Dependencies..." -ForegroundColor Yellow
try {
    # We use -y to auto-confirm the uninstallation
    python -m pip uninstall scikit-learn numpy joblib scipy -y --quiet
    Write-Host "    [+] Specific ML packages (scikit-learn, numpy, joblib, scipy) removed." -ForegroundColor Green
} catch {
    Write-Host "    [-] Could not remove Python packages. Python might not be in PATH." -ForegroundColor DarkYellow
}

# 3. Clean up Artifacts and Logs
Write-Host "`n[*] Cleaning up artifacts and logs..." -ForegroundColor Yellow
$Artifacts = @(
    #"C:\Temp\C2KernelMonitoring_v3.jsonl",
    "C:\Temp\C2Kernel.etl",
    "$env:TEMP\python-installer.exe"
)

foreach ($file in $Artifacts) {
    if (Test-Path $file) {
        Remove-Item $file -Force -ErrorAction SilentlyContinue
        Write-Host "    [-] Deleted: $file" -ForegroundColor Gray
    }
}
Write-Host "    [+] Artifact cleanup complete." -ForegroundColor Green

Write-Host "`n===================================================" -ForegroundColor Cyan
Write-Host " [+] Environment successfully torn down!" -ForegroundColor Green
Write-Host " [+] Note: Python itself was left installed as other apps may rely on it." -ForegroundColor DarkGray
Write-Host "===================================================`n" -ForegroundColor Cyan