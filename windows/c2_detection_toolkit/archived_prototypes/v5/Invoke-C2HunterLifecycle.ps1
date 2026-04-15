<#
.SYNOPSIS
    C2 Hunter End-to-End Lifecycle Manager (V5) - A PowerShell script to orchestrate the full lifecycle of the C2 Hunter project,
    including environment setup, daemon management, and graceful teardown.
.DESCRIPTION
    This script manages the entire lifecycle of the C2 Hunter project, from initial setup to final teardown.
    It performs the following key functions:
    1. Environment Preparation: Unblocks script files, sets execution policy, and bootstraps Python and ML dependencies.
    2. Daemon Management: Spawns the MonitorKernelC2BeaconHunter_v5.ps1 in a separate PowerShell window, allowing for real-time monitoring and defense.
    3. User Interaction: Provides clear console output to guide the user through the process and indicates the status of the collection
       and defense mechanisms.
    4. Graceful Teardown: On user command, it safely stops the monitoring and defense processes, stops the ETW session, and optionally
       purges project artifacts while preserving telemetry logs for SIEM analysis.
.PARAMETER PurgeLogsOnExit
    A switch parameter that, when set, purges project artifacts (except for telemetry logs) upon exiting the script. This helps maintain a
    clean environment while ensuring that important logs are preserved for analysis.
.NOTES
    Author: Robert Weber

    To enable a diagnostic log in C:\Temp:
    .\Invoke-C2HunterLifecycle.ps1 -EnableDiagnostics

    To run the C2 validation test, launch the orchestrator with the following switch:
    .\Invoke-C2HunterLifecycle.ps1 -TestMode

    This will disable the CDN prefixes so the test script can run and actually trigger ML Alerts.
    After testing, stop the lifecycle and relaunch without the "-TestMode" switch.
#>
#Requires -RunAsAdministrator

param (
    [switch]$ArmedMode,
    [int]$ConfidenceThreshold = 85,
    [switch]$PurgeLogsOnExit = $true,
    [switch]$EnableDiagnostics,
    [switch]$TestMode
)

$ScriptDir = Split-Path $PSCommandPath -Parent
Set-Location $ScriptDir
$Host.UI.RawUI.WindowTitle = "C2 Hunter - Full Lifecycle Manager (V5)"

Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "  C2 Hunter End-to-End Lifecycle Manager (V5)" -ForegroundColor Cyan
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

    # =========================================================================
    # DYNAMIC THREAT INTEL FETCH (JA3 Hashes)
    # =========================================================================
    Write-Host "      [*] Updating JA3 Threat Intel Cache from Abuse.ch..." -ForegroundColor Gray
    try {
        $Ja3Url = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"
        $CsvData = Invoke-RestMethod -Uri $Ja3Url -TimeoutSec 10 -ErrorAction Stop
        $Ja3Hashes = @()

        # Parse the CSV, ignoring comments, and extract the 32-char MD5 hashes
        foreach ($line in $CsvData -split "`n") {
            if ($line -match "^([a-fA-F0-9]{32}),") {
                $Ja3Hashes += $matches[1]
            }
        }

        if ($Ja3Hashes.Count -gt 0) {
            $Ja3Hashes | ConvertTo-Json -Compress | Set-Content "C:\Temp\C2Hunter_JA3_Cache.json" -Encoding UTF8
            Write-Host "      [+] Successfully loaded $($Ja3Hashes.Count) malicious JA3 profiles." -ForegroundColor Green
        }
    } catch {
        Write-Host "      [-] Threat Intel update failed/timed out. Sensor will use offline fallback." -ForegroundColor DarkYellow
    }

    Write-Host "`n[2/3] Spawning V5 Monitoring Dashboard..." -ForegroundColor Yellow
    $MonitorScript = Join-Path $ScriptDir "MonitorKernelC2BeaconHunter_v5.ps1"

    # Dynamically build the launch arguments for the V5 Monitor
    $MonitorCmd = "& '$MonitorScript'"
    if ($EnableDiagnostics) { $MonitorCmd += " -EnableDiagnostics" }
    if ($ArmedMode) { $MonitorCmd += " -ArmedMode -ConfidenceThreshold $ConfidenceThreshold" }
    if ($TestMode) { $MonitorCmd += " -TestMode" }

    $MonitorProcess = Start-Process powershell.exe -ArgumentList "-NoExit -Command `"$MonitorCmd`"" -PassThru -WindowStyle Normal

    Write-Host "      [*] Booting Anti-Tamper Process Watchdog..." -ForegroundColor Gray
    $WatchdogAction = {
        param($TargetId)
        while ($true) {
            $Proc = Get-Process -Id $TargetId -ErrorAction SilentlyContinue
            if (-not $Proc) {
                # Monitor was killed forcefully. Sound the alarm and stop the session.
                logman stop "C2RealTimeSession" -ets 2>&1 | Out-Null
                break
            }

            # Check for thread suspension (Freeze attacks)
            $SuspendedThreads = $Proc.Threads | Where-Object { $_.ThreadState -eq 'Wait' -and $_.WaitReason -eq 'Suspended' }
            if ($SuspendedThreads) {
                # Write to the Tamper Guard Log directly
                $logLine = "[$(Get-Date -Format 'o')] [CRITICAL] C2 Hunter Thread Suspension Detected! Evasion Attempt in Progress."
                Add-Content -Path "C:\Temp\C2Hunter_TamperGuard.log" -Value $logLine
            }
            Start-Sleep -Seconds 5
        }
    }
    $WatchdogJob = Start-Job -ScriptBlock $WatchdogAction -ArgumentList $MonitorProcess.Id

    # [DEVELOPER NOTE: c2_defend.ps1 is deprecated in V5. Active defense is now handled natively in RAM by the Monitor.]

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