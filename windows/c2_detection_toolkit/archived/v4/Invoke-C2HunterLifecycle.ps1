<#
.SYNOPSIS
    C2 Hunter End-to-End Lifecycle Manager (V4) - A PowerShell script to orchestrate the full lifecycle of the C2 Hunter project,
    including environment setup, daemon management, and graceful teardown.
.DESCRIPTION
    This script manages the entire lifecycle of the C2 Hunter project, from initial setup to final teardown.
    It performs the following key functions:
    1. Environment Preparation: Unblocks script files, sets execution policy, and bootstraps Python and ML dependencies.
    2. Daemon Management: Spawns the MonitorKernelC2BeaconHunter_v4.ps1 and c2_defend.ps1 scripts in separate PowerShell windows,
       allowing for real-time monitoring and defense.
    3. User Interaction: Provides clear console output to guide the user through the process and indicates the status of the collection
       and defense mechanisms.
    4. Graceful Teardown: On user command, it safely stops the monitoring and defense processes, stops the ETW session, and optionally
       purges project artifacts while preserving telemetry logs for SIEM analysis.
.PARAMETER ArmedMode
    A switch parameter that, when set, arms the defender to take active mitigation actions. If not set, the defender operates in dry-run
    mode, only logging potential threats without taking action.
.PARAMETER ConfidenceThreshold
    An integer parameter that sets the confidence threshold for the defender's decision-making process. The default value is 75, meaning
    that only detections with a confidence score of 75 or higher will be considered for mitigation (if ArmedMode is enabled).
.PARAMETER PurgeLogsOnExit
    A switch parameter that, when set, purges project artifacts (except for telemetry logs) upon exiting the script. This helps maintain a
    clean environment while ensuring that important logs are preserved for analysis.
.EXAMPLE
    # To run the C2 Hunter lifecycle manager in dry-run mode with a confidence threshold of 80:
    .\Invoke-C2HunterLifecycle.ps1 -ConfidenceThreshold 80
    This command will start the C2 Hunter daemons in dry-run mode, where the defender will log potential threats with a confidence score
    of 80 or higher without taking any mitigation actions.
.EXAMPLE
    # To run the C2 Hunter lifecycle manager in armed mode with the default confidence threshold:
    .\Invoke-C2HunterLifecycle.ps1 -ArmedMode
    This command will start the C2 Hunter daemons in armed mode, where the defender will actively mitigate threats that meet or exceed the
    default confidence threshold of 75.
.NOTES
    Author: Robert Weber
#>
#Requires -RunAsAdministrator

param ([switch]$ArmedMode, [int]$ConfidenceThreshold = 75, [switch]$PurgeLogsOnExit = $true)

$ScriptDir = Split-Path $PSCommandPath -Parent
Set-Location $ScriptDir
$Host.UI.RawUI.WindowTitle = "C2 Hunter - Full Lifecycle Manager (V4)"

Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "  C2 Hunter End-to-End Lifecycle Manager (V4)" -ForegroundColor Cyan
Write-Host "===================================================`n" -ForegroundColor Cyan

$MonitorProcess = $null
$DefendProcess = $null

try {
    Write-Host "[1/3] Preparing Environment..." -ForegroundColor Yellow
    Get-ChildItem -Path $ScriptDir -Filter "*.ps1" -Recurse | Unblock-File -ErrorAction SilentlyContinue
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

    Write-Host "      [*] Bootstrapping Python and ML Dependencies..." -ForegroundColor Gray
    $SetupScript = Join-Path $ScriptDir "Setup-C2HunterEnvironment.ps1"
    if (Test-Path $SetupScript) {
        & $SetupScript
    } else {
        Write-Host "      [!] Setup-C2HunterEnvironment.ps1 missing. Daemons will likely fail." -ForegroundColor Red
    }

    Write-Host "`n[2/3] Spawning V4 Hybrid Daemons..." -ForegroundColor Yellow
    $MonitorScript = Join-Path $ScriptDir "MonitorKernelC2BeaconHunter_v4.ps1"
    $MonitorProcess = Start-Process powershell.exe -ArgumentList "-NoExit -Command `"& '$MonitorScript'`"" -PassThru -WindowStyle Normal

    $DefendScript = Join-Path $ScriptDir "c2_defend.ps1"
    $DefendArgsStr = "& '$DefendScript' -LogPath 'C:\Temp\C2KernelMonitoring_v4.jsonl' -ConfidenceThreshold $ConfidenceThreshold"
    if (-not $ArmedMode) { $DefendArgsStr += " -DryRun" }
    $DefendProcess = Start-Process powershell.exe -ArgumentList "-NoExit -Command `"$DefendArgsStr`"" -PassThru -WindowStyle Normal

    Write-Host "      [+] Daemons Running.`n" -ForegroundColor Green

    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host " [!] COLLECTION IS LIVE (REAL-TIME RAM SESSION) [!]" -ForegroundColor Green
    if (-not $ArmedMode) { Write-Host " [*] DEFENDER IS IN DRY-RUN MODE." -ForegroundColor Yellow }
    else { Write-Host " [!] DEFENDER IS ARMED." -ForegroundColor Red }
    Write-Host "===================================================`n" -ForegroundColor Cyan

    Write-Host "Press [ENTER] to safely STOP capture..." -ForegroundColor White
    Read-Host

} finally {
    Write-Host "`n[*] Commencing Teardown Sequence..." -ForegroundColor Yellow
    if ($MonitorProcess) { Stop-Process -Id $MonitorProcess.Id -Force -ErrorAction SilentlyContinue }
    if ($DefendProcess) { Stop-Process -Id $DefendProcess.Id -Force -ErrorAction SilentlyContinue }
    logman stop "C2RealTimeSession" -ets 2>&1 | Out-Null

    if ($PurgeLogsOnExit) {
        Write-Host "      [*] Cleaning project artifacts (Preserving Telemetry for SIEM)..." -ForegroundColor DarkGray

        # Architectural Revision: The .jsonl and .log files have been permanently removed
        # from the teardown array to ensure SIEM forwarders maintain persistent file handles.
        $ProjectArtifacts = @(
            "C:\Temp\TraceEventPackage",
            "C:\Temp\TraceEvent.zip",
            "C:\Temp\TraceEventSupport.zip",
            "C:\Temp\C2Kernel.etl"
        )
        foreach ($item in $ProjectArtifacts) {
            Remove-Item -Path $item -Recurse -Force -ErrorAction SilentlyContinue
        }
        Write-Host "      [+] Engine Artifacts Purged. Telemetry Logs preserved in C:\Temp." -ForegroundColor Green
    }

    Write-Host "      [+] Teardown Complete." -ForegroundColor Green
}