<#
.SYNOPSIS
    Automated V4 Post-Containment Triage and Root Cause Analysis
.DESCRIPTION
    Executes Phase 2 and Phase 3 hunting based on a contained PID.
    Rips through Windows Event Logs, Sysmon, Script Blocks, and advanced
    persistence mechanisms (LOLBins, WMI, IFEO, Services) to locate the initial dropper.
.NOTES
    Author: Robert Weber
    Version: 1.0 (V4 Companion)
#>
#Requires -RunAsAdministrator

param (
    [int]$TargetPID,
    [datetime]$AlertTime = (Get-Date),
    [int]$LookbackHours = 96, # Lookback window for persistence enumeration (default 4 days)
    [string]$ReportOutput = "C:\Temp\C2_Triage_Report_PID_$TargetPID.txt"
)

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " [*] C2 FORENSIC TRIAGE ENGINE (V4.1 - LOLBIN ENHANCED)" -ForegroundColor Cyan
Write-Host "============================================================`n" -ForegroundColor Cyan

$ReportContent = @(
    "============================================================"
    " FORENSIC TRIAGE REPORT (ENHANCED)"
    " Target PID: $TargetPID | Alert Time: $($AlertTime.ToString('yyyy-MM-dd HH:mm:ss'))"
    "============================================================`n"
)

$StartTime = $AlertTime.AddHours(-$LookbackHours)
$PreFetchWindow = $AlertTime.AddMinutes(-60) # 1-hour window before beaconing for stage-0 droppers

# =================================================================
# PHASE 2: ROOT CAUSE ANALYSIS (Process Lineage & LOLBins)
# =================================================================
Write-Host "[1/4] Reconstructing Process Lineage & Hunting LOLBins..." -ForegroundColor Yellow
$ReportContent += "[*] PHASE 2A: PROCESS LINEAGE & LOLBIN EXECUTION`n"

$ProcessEvents = @()
try {
    # Attempt to pull Sysmon EID 1 first, fallback to Security EID 4688
    $SysmonEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1; StartTime=$StartTime; EndTime=$AlertTime} -ErrorAction SilentlyContinue
    if ($SysmonEvents) { $ProcessEvents += $SysmonEvents }
    else { $ProcessEvents += Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688; StartTime=$StartTime; EndTime=$AlertTime} -ErrorAction SilentlyContinue }
} catch {}

if ($ProcessEvents.Count -gt 0) {
    $ReportContent += "  [+] Direct Lineage for PID $TargetPID:`n"
    foreach ($evt in $ProcessEvents) {
        $xml = [xml]$evt.ToXml()
        $eventData = $xml.Event.EventData.Data

        $newPidHex = ($eventData | Where-Object { $_.Name -match 'NewProcessId|ProcessId' }).'#text'
        if (-not $newPidHex) { continue }
        $parsedPid = if ($newPidHex.StartsWith('0x')) { [Convert]::ToInt32($newPidHex, 16) } else { $newPidHex }

        if ($parsedPid -eq $TargetPID) {
            $processName = ($eventData | Where-Object { $_.Name -match 'NewProcessName|Image' }).'#text'
            $creatorPidHex = ($eventData | Where-Object { $_.Name -match 'ProcessId|ParentProcessId' } | Select-Object -Last 1).'#text'
            $cmdLine = ($eventData | Where-Object { $_.Name -eq 'CommandLine' }).'#text'

            $ReportContent += "      Time           : $($evt.TimeCreated)"
            $ReportContent += "      Process Name   : $processName"
            $ReportContent += "      Command Line   : $cmdLine`n"
        }
    }

    $ReportContent += "  [+] Pre-Fetch LOLBin Activity (60 mins prior to alert):`n"
    $LOLBinRegex = "certutil|mshta|rundll32|regsvr32|wmic|bitsadmin|cscript|wscript|msbuild|installutil|forfiles"
    $foundLolbin = $false

    foreach ($evt in $ProcessEvents | Where-Object { $_.TimeCreated -ge $PreFetchWindow }) {
        $xml = [xml]$evt.ToXml()
        $eventData = $xml.Event.EventData.Data
        $processName = ($eventData | Where-Object { $_.Name -match 'NewProcessName|Image' }).'#text'
        $cmdLine = ($eventData | Where-Object { $_.Name -eq 'CommandLine' }).'#text'

        if ($processName -match $LOLBinRegex -or $cmdLine -match $LOLBinRegex) {
            $foundLolbin = $true
            $ReportContent += "      Suspicious Exec: $($evt.TimeCreated)"
            $ReportContent += "      Command Line   : $cmdLine`n"
        }
    }
    if (-not $foundLolbin) { $ReportContent += "      None detected in 60-minute window.`n" }

} else {
    $ReportContent += "  [-] No Process Creation events found (Sysmon or 4688).`n"
}

# =================================================================
# PHASE 2B: POWERSHELL SCRIPT BLOCKS
# =================================================================
Write-Host "[2/4] Extracting PowerShell Script Blocks..." -ForegroundColor Yellow
$ReportContent += "`n[*] PHASE 2B: POWERSHELL SCRIPT BLOCK LOGGING (Event ID 4104)`n"

try {
    $PshEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104; StartTime=$StartTime; EndTime=$AlertTime} -ErrorAction Stop
    $foundBlocks = $false
    foreach ($evt in $PshEvents) {
        if ($evt.Message -match "Context:\s*.*Process ID:\s*$TargetPID") {
            $foundBlocks = $true
            $ReportContent += "  [+] Script Block Executed at $($evt.TimeCreated):"
            $ReportContent += "--------------------------------------------------"
            $ReportContent += $evt.Properties[2].Value
            $ReportContent += "`n--------------------------------------------------`n"
        }
    }
    if (-not $foundBlocks) { $ReportContent += "  [-] No associated Script Blocks found for PID $TargetPID.`n" }
} catch {
    $ReportContent += "  [-] PowerShell Operational logs unavailable or empty.`n"
}

# =================================================================
# PHASE 3: PERSISTENCE ENUMERATION
# =================================================================
Write-Host "[3/4] Scanning Standard Persistence Mechanisms..." -ForegroundColor Yellow
$ReportContent += "`n[*] PHASE 3: STANDARD PERSISTENCE`n"

# 3A. Scheduled Tasks
$ReportContent += "  [+] Scheduled Tasks Modified in last $LookbackHours Hours:`n"
$RecentTasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' -and $_.Date -ge $StartTime }
if ($RecentTasks) {
    foreach ($task in $RecentTasks) {
        $action = $task.Actions[0]
        $ReportContent += "      Name: $($task.TaskName)"
        $ReportContent += "      Exec: $($action.Execute) $($action.Arguments)`n"
    }
} else { $ReportContent += "      None detected.`n" }

# 3B. Services (Event ID 7045)
$ReportContent += "  [+] New Services Installed (Event ID 7045):`n"
try {
    $SvcEvents = Get-WinEvent -FilterHashtable @{LogName='System'; ID=7045; StartTime=$StartTime} -ErrorAction Stop
    foreach ($evt in $SvcEvents) {
        $xml = [xml]$evt.ToXml()
        $eventData = $xml.Event.EventData.Data
        $svcName = ($eventData | Where-Object { $_.Name -eq 'ServiceName' }).'#text'
        $imgPath = ($eventData | Where-Object { $_.Name -eq 'ImagePath' }).'#text'
        $ReportContent += "      Time : $($evt.TimeCreated)"
        $ReportContent += "      Name : $svcName"
        $ReportContent += "      Path : $imgPath`n"
    }
} catch { $ReportContent += "      None detected.`n" }

# 3C. Startup Folders
$ReportContent += "  [+] Startup Folder Artifacts:`n"
$StartupPaths = @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Startup")
$foundStartup = $false
foreach ($path in $StartupPaths) {
    if (Test-Path $path) {
        $files = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue
        foreach ($file in $files) {
            $foundStartup = $true
            $ReportContent += "      File: $($file.FullName) (Created: $($file.CreationTime))`n"
        }
    }
}
if (-not $foundStartup) { $ReportContent += "      Directories empty.`n" }

# =================================================================
# PHASE 4: ADVANCED PERSISTENCE (WMI & IFEO)
# =================================================================
Write-Host "[4/4] Scanning Advanced Persistence Mechanisms..." -ForegroundColor Yellow
$ReportContent += "`n[*] PHASE 4: ADVANCED PERSISTENCE`n"

# 4A. WMI Event Subscriptions
$ReportContent += "  [+] WMI CommandLineEventConsumers:`n"
try {
    $WmiConsumers = Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -ErrorAction Stop
    if ($WmiConsumers) {
        foreach ($consumer in $WmiConsumers) {
            $ReportContent += "      Name : $($consumer.Name)"
            $ReportContent += "      Line : $($consumer.CommandLineTemplate)`n"
        }
    } else { $ReportContent += "      None detected.`n" }
} catch { $ReportContent += "      Failed to query WMI Event Consumers.`n" }

# 4B. Image File Execution Options (IFEO Debugger Injection)
$ReportContent += "  [+] IFEO Debugger Injections:`n"
$IfeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
$foundIfeo = $false
if (Test-Path $IfeoPath) {
    $subkeys = Get-ChildItem -Path $IfeoPath -ErrorAction SilentlyContinue
    foreach ($key in $subkeys) {
        $debugger = Get-ItemProperty -Path $key.PSPath -Name "Debugger" -ErrorAction SilentlyContinue
        if ($debugger) {
            $foundIfeo = $true
            $ReportContent += "      Target   : $($key.PSChildName)"
            $ReportContent += "      Debugger : $($debugger.Debugger)`n"
        }
    }
}
if (-not $foundIfeo) { $ReportContent += "      None detected.`n" }

# 4C. BITS Jobs
$ReportContent += "  [+] Active/Suspended BITS Jobs:`n"
try {
    $BitsJobs = Get-BitsTransfer -AllUsers -ErrorAction Stop
    if ($BitsJobs) {
        foreach ($job in $BitsJobs) {
            $ReportContent += "      State : $($job.JobState)"
            $ReportContent += "      File  : $($job.FileList.RemoteName) -> $($job.FileList.LocalName)`n"
        }
    } else { $ReportContent += "      No suspicious BITS jobs detected.`n" }
} catch { $ReportContent += "      Failed to query BITS or module not imported.`n" }

$ReportContent | Out-File -FilePath $ReportOutput -Encoding UTF8
Write-Host "      [+] Triage complete. Report saved to: $ReportOutput" -ForegroundColor Green
Write-Host "============================================================`n" -ForegroundColor Cyan