<#
.SYNOPSIS
    C2 Hunter End-to-End Lifecycle Manager (V4) - A PowerShell script to orchestrate
    the full lifecycle of the C2 Hunter project, including environment setup,
    daemon management, and graceful teardown.
#>
#Requires -RunAsAdministrator

param (
    [switch]$DryRunDefense,
    [int]$ConfidenceThreshold = 75,
    [int]$BatchAnalysisIntervalSeconds = 30
)
$ScriptDir = Split-Path $PSCommandPath -Parent
Set-Location $ScriptDir
$Host.UI.RawUI.WindowTitle = "C2 Hunter Master Orchestrator (V4)"

Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "  Kernel C2 Beacon Hunter v4.0 - Orchestrator" -ForegroundColor Cyan
Write-Host "===================================================`n" -ForegroundColor Cyan

Write-Host "[*] Spawning V4 Monitor Engine & ML Daemon..." -ForegroundColor Gray
$MonitorScript = Join-Path $ScriptDir "MonitorKernelC2BeaconHunter_v4.ps1"
$MonitorArgs = "-NoExit -Command `"& '$MonitorScript' -BatchAnalysisIntervalSeconds $BatchAnalysisIntervalSeconds`""
$MonitorProcess = Start-Process powershell.exe -ArgumentList $MonitorArgs -PassThru -WindowStyle Normal

Write-Host "[*] Spawning Active Defense Engine..." -ForegroundColor Gray
$DefendScript = Join-Path $ScriptDir "c2_defend.ps1"
$DefendArgsStr = "& '$DefendScript' -LogPath 'C:\Temp\C2KernelMonitoring_v4.jsonl' -ConfidenceThreshold $ConfidenceThreshold"
if ($DryRunDefense) { $DefendArgsStr += " -DryRun" }
$DefendProcess = Start-Process powershell.exe -ArgumentList "-NoExit -Command `"$DefendArgsStr`"" -PassThru -WindowStyle Normal

Write-Host "`n===================================================" -ForegroundColor Cyan
Write-Host " [+] V4 Real-Time System is LIVE and Monitoring." -ForegroundColor Green
Write-Host "===================================================`n" -ForegroundColor Cyan

Write-Host "Press [ENTER] to safely shutdown..." -ForegroundColor White
Read-Host

Write-Host "`n[*] Commencing Teardown Sequence..." -ForegroundColor Yellow
if ($MonitorProcess -and -not $MonitorProcess.HasExited) { Stop-Process -Id $MonitorProcess.Id -Force }
if ($DefendProcess -and -not $DefendProcess.HasExited) { Stop-Process -Id $DefendProcess.Id -Force }
logman stop "C2RealTimeSession" -ets 2>&1 | Out-Null
Write-Host "`n[+] Environment safely restored. Goodbye!" -ForegroundColor Green
Start-Sleep -Seconds 2