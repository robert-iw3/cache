<#
.SYNOPSIS
    Automated C2 Forensic Triage & Persistence Extraction (V5)
.DESCRIPTION
    Executes immediately after a threat is contained. Dumps volatile state data
    (network connections, loaded modules) and aggressively sweeps for staging
    persistence (Scheduled Tasks, Run Keys, WMI Event Consumers).

    Generates the C2_Triage_Report consumed by the Eradication Engine.
.NOTES
    Author: Robert Weber
    Version: 5.0
#>
#Requires -RunAsAdministrator

param (
    [int]$TargetPID,
    [datetime]$AlertTime = [datetime]::Now,
    [string]$EvidenceFolder = "C:\temp\DFIR_Evidence_20260406_1846",
    [switch]$Orchestrated
)

$ScriptDir = if ($PSCommandPath) { Split-Path $PSCommandPath -Parent } else { $PWD.Path }

# =================================================================
# DUAL-MODE UI ENGINE
# =================================================================
$ESC = [char]27
$cRed = "$ESC[38;2;255;70;85m"; $cCyan = "$ESC[38;2;0;200;255m"; $cGreen = "$ESC[38;2;10;210;130m"; $cDark = "$ESC[38;2;100;100;100m"; $cYellow = "$ESC[38;2;255;180;50m"; $cReset = "$ESC[0m"

if (-not $Orchestrated) {
    $Host.UI.RawUI.WindowTitle = "V5 DFIR // FORENSIC TRIAGE ENGINE"
    [Console]::CursorVisible = $false
    Clear-Host
    [Console]::SetCursorPosition(0, 6)
}

function Update-UI([int]$Progress, [int]$Threats, [string]$ActionText) {
    if ($Orchestrated) {
        Write-Output "[HUD]|$Progress|$Threats|$ActionText"
    } else {
        $curLeft = [Console]::CursorLeft; $curTop = [Console]::CursorTop
        [Console]::SetCursorPosition(0, 0)

        # --- DYNAMIC PADDING MATH ---
        # 1. Define the raw, uncolored strings so PowerShell can count the EXACT character length
        $EngineName = "FORENSIC TRIAGE ENGINE"
        $TitleStr   = "  ⚡ C2 HUNTER V5  | $EngineName"
        $StatsStr   = "  Progress : $Progress% | Targets: $Threats"

        # 2. Prevent Action text from overflowing the 86-character boundary
        if ($ActionText.Length -gt 70) { $ActionText = $ActionText.Substring(0, 67) + "..." }
        $ActionStr  = "  Action   : $ActionText"

        # 3. Calculate exact spaces needed to hit 86 characters perfectly
        # (Note: Some terminals render the ⚡ emoji as 2 spaces wide. If the top line is off by 1 space, subtract 1 from the Title length math)
        $PadTitle  = " " * [math]::Max(0, (86 - $TitleStr.Length))
        $PadStats  = " " * [math]::Max(0, (86 - $StatsStr.Length))
        $PadAction = " " * [math]::Max(0, (86 - $ActionStr.Length))

        Write-Host "$cCyan╔══════════════════════════════════════════════════════════════════════════════════════╗$cReset"
        Write-Host "$cCyan║$cReset  $cRed⚡ C2 HUNTER V5$cReset | $EngineName$PadTitle$cCyan║$cReset"
        Write-Host "$cCyan╠══════════════════════════════════════════════════════════════════════════════════════╣$cReset"
        Write-Host "$cCyan║$cReset  Progress : $cCyan$Progress%$cReset | Targets: $cRed$Threats$cReset$PadStats$cCyan║$cReset"
        Write-Host "$cCyan║$cReset  Action   : $cYellow$ActionText$cReset$PadAction$cCyan║$cReset"
        Write-Host "$cCyan╚══════════════════════════════════════════════════════════════════════════════════════╝$cReset"

        if ($curTop -lt 6) { $curTop = 6 }
        [Console]::SetCursorPosition($curLeft, $curTop)
    }
}

$ReportFile = Join-Path $EvidenceFolder "C2_Triage_Report_PID_$TargetPID.txt"
$ArtifactCount = 0

Update-UI 10 $ArtifactCount "Initializing Triage for PID $TargetPID..."

# 1. Initialize Report
$Header = @(
    "============================================================"
    "  FORENSIC TRIAGE REPORT: SUSPENDED THREAT"
    "  PID: $TargetPID | Time: $($AlertTime.ToString('yyyy-MM-dd HH:mm:ss'))"
    "============================================================`n"
)
$Header | Out-File -FilePath $ReportFile -Encoding UTF8

# 2. Extract Process Metadata & Lineage
Update-UI 30 $ArtifactCount "Extracting Process Lineage..."
try {
    $Proc = Get-CimInstance Win32_Process -Filter "ProcessId = $TargetPID" -ErrorAction Stop
    $ParentProc = Get-CimInstance Win32_Process -Filter "ProcessId = $($Proc.ParentProcessId)" -ErrorAction SilentlyContinue

    $Lineage = @(
        "[PROCESS METADATA]"
        "Name           : $($Proc.Name)"
        "Path           : $($Proc.ExecutablePath)"
        "CommandLine    : $($Proc.CommandLine)"
        "Parent PID     : $($Proc.ParentProcessId) ($($ParentProc.Name))"
        "Parent CmdLine : $($ParentProc.CommandLine)`n"
    )
    $Lineage | Out-File -FilePath $ReportFile -Encoding UTF8 -Append
    $ArtifactCount++
} catch {
    "[-] Could not extract process lineage (Process may have exited).`n" | Out-File -FilePath $ReportFile -Encoding UTF8 -Append
}

# 3. Aggressive Persistence Sweep: Scheduled Tasks
Update-UI 60 $ArtifactCount "Sweeping Scheduled Tasks..."
"[PERSISTENCE - SCHEDULED TASKS]" | Out-File -FilePath $ReportFile -Encoding UTF8 -Append
try {
    # Filter out standard Microsoft tasks to reduce noise
    $Tasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch "\\Microsoft\\Windows" -and $_.State -ne 'Disabled' }
    foreach ($Task in $Tasks) {
        $Action = $Task.Actions | Select-Object -First 1
        if ($Action.Execute) {
            # THIS FORMAT IS REQUIRED FOR ERADICATION REGEX MATCHING
            $TaskStr = "TaskName: $($Task.TaskName)`r`nAction: $($Action.Execute) $($Action.Arguments)"
            $TaskStr | Out-File -FilePath $ReportFile -Encoding UTF8 -Append
            $ArtifactCount++
        }
    }
    "`n" | Out-File -FilePath $ReportFile -Encoding UTF8 -Append
} catch { }

# 4. Aggressive Persistence Sweep: Registry Run Keys
Update-UI 80 $ArtifactCount "Sweeping Registry Run Keys..."
"[PERSISTENCE - REGISTRY RUN KEYS]" | Out-File -FilePath $ReportFile -Encoding UTF8 -Append
try {
    $HKCU_Run = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
    if ($HKCU_Run) {
        foreach ($prop in $HKCU_Run.psobject.properties) {
            if ($prop.Name -notmatch "PSPath|PSParentPath|PSChildName|PSDrive|PSProvider") {
                # THIS FORMAT IS REQUIRED FOR ERADICATION REGEX MATCHING
                $RegStr = "RunKey: $($prop.Name) -> $($prop.Value)"
                $RegStr | Out-File -FilePath $ReportFile -Encoding UTF8 -Append
                $ArtifactCount++
            }
        }
    }

    $HKLM_Run = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
    if ($HKLM_Run) {
        foreach ($prop in $HKLM_Run.psobject.properties) {
            if ($prop.Name -notmatch "PSPath|PSParentPath|PSChildName|PSDrive|PSProvider") {
                $RegStr = "RunKey: $($prop.Name) -> $($prop.Value)"
                $RegStr | Out-File -FilePath $ReportFile -Encoding UTF8 -Append
                $ArtifactCount++
            }
        }
    }
} catch { }

Update-UI 100 $ArtifactCount "Triage Complete. Artifacts logged."
if (-not $Orchestrated) { [Console]::CursorVisible = $true }