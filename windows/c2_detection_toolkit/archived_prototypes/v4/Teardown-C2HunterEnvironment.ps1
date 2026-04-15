<#
.SYNOPSIS
    V4 Environment Teardown. Removes ML dependencies and cleans artifacts.
#>
#Requires -RunAsAdministrator

$ScriptDir = Split-Path $PSCommandPath -Parent

Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "  C2 Hunter - V4 Environment Teardown" -ForegroundColor Cyan
Write-Host "===================================================`n" -ForegroundColor Cyan

# 1. Kill any zombie sessions
Write-Host "[*] Halting Kernel Telemetry..." -ForegroundColor Yellow
logman stop "C2RealTimeSession" -ets 2>&1 | Out-Null
logman delete "C2RealTimeSession" -ets 2>&1 | Out-Null
Write-Host "    [+] Real-Time Session stopped." -ForegroundColor Green

# 2. Uninstall Python Dependencies
Write-Host "`n[*] Removing Python ML Dependencies..." -ForegroundColor Yellow
try {
    python -m pip uninstall scikit-learn numpy joblib scipy -y --quiet
    Write-Host "    [+] Specific ML packages removed." -ForegroundColor Green
} catch { Write-Host "    [-] Could not remove Python packages." -ForegroundColor DarkYellow }

# 3. Clean up Artifacts
Write-Host "`n[*] Cleaning up artifacts and logs..." -ForegroundColor Yellow
$Artifacts = @("C:\Temp\TraceEventPackage", "C:\Temp\TraceEvent.zip", "C:\Temp\C2Kernel.etl", "C:\Temp\TraceEventSupport.zip")
foreach ($file in $Artifacts) {
    if (Test-Path $file) { Remove-Item $file -Recurse -Force -ErrorAction SilentlyContinue }
}
Write-Host "    [+] Artifact cleanup complete." -ForegroundColor Green
Write-Host "`n===================================================" -ForegroundColor Cyan
Write-Host " [+] Environment successfully torn down!" -ForegroundColor Green
Write-Host "===================================================`n" -ForegroundColor Cyan