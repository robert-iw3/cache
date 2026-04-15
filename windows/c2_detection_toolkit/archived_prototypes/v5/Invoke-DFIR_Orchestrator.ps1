<#
.SYNOPSIS
    DFIR Automated Response Orchestrator (V5)
.DESCRIPTION
    This script chains the four V5 Post-Detection DFIR phases:
    0. Configuration & API Key Validation
    1. Threat Intelligence Enrichment (CTI)
    2. Tri-Lateral Vector Correlation (Target Identification)
    3. Advanced Memory Hunting (YARA/Signature scanning)
    4. Surgical Containment (Thread suspension & Firewall isolation)

    It dynamically creates a timestamped evidence directory and routes all
    forensic artifacts and logs to that centralized location.
.NOTES
    Author: Robert Weber
    Version: 5.0
#>
#Requires -RunAsAdministrator

param(
    [switch]$ArmedMode,
    [string]$EvidenceFolder = "C:\Temp\DFIR_Evidence_$(Get-Date -Format 'yyyyMMdd_HHmm')",
    [switch]$Orchestrated
)

$ScriptDir = Split-Path $PSCommandPath -Parent
if (-not (Test-Path $EvidenceFolder)) { New-Item -ItemType Directory -Path $EvidenceFolder -Force | Out-Null }

$Host.UI.RawUI.WindowTitle = "V5 DFIR // MASTER ORCHESTRATOR"
$ESC = [char]27
$cRed = "$ESC[38;2;255;70;85m"; $cCyan = "$ESC[38;2;0;200;255m"; $cGreen = "$ESC[38;2;10;210;130m"; $cDark = "$ESC[38;2;100;100;100m"; $cYellow = "$ESC[38;2;255;180;50m"; $cReset = "$ESC[0m"

[Console]::CursorVisible = $false
Clear-Host
[Console]::SetCursorPosition(0, 8) # Reserve 8 lines for Master HUD

function Draw-MasterDashboard {
    param([int]$Phase, [int]$TotalPhases, [int]$Threats, [int]$SubProgress, [string]$CurrentTarget)

    $curLeft = [Console]::CursorLeft; $curTop = [Console]::CursorTop
    [Console]::SetCursorPosition(0, 0)

    # --- DYNAMIC PADDING MATH ---
    # 1. Define uncolored strings to measure exact lengths
    $TitleStr  = "  ⚡ C2 HUNTER V5  | MASTER DFIR ORCHESTRATOR ENGINE"
    $StatusStr = "  [ PIPELINE STATUS ]"
    $StatsStr  = "  Phase  : $Phase / $TotalPhases | Targets: $Threats | Progress: $SubProgress%"

    # 2. Manage Action text length to prevent line-wrapping
    if ($CurrentTarget.Length -gt 70) { $CurrentTarget = $CurrentTarget.Substring(0, 67) + "..." }
    $ActionStr = "  Action : $CurrentTarget"

    # 3. Calculate exact padding for an 86-character interior width
    $PadTitle  = " " * [math]::Max(0, (86 - $TitleStr.Length))
    $PadStatus = " " * [math]::Max(0, (86 - $StatusStr.Length))
    $PadStats  = " " * [math]::Max(0, (86 - $StatsStr.Length))
    $PadAction = " " * [math]::Max(0, (86 - $ActionStr.Length))

    # --- RENDER DASHBOARD ---
    Write-Host "$cCyan╔══════════════════════════════════════════════════════════════════════════════════════╗$cReset"
    Write-Host "$cCyan║$cReset  $cRed⚡ C2 HUNTER V5$cReset | MASTER DFIR ORCHESTRATOR ENGINE$PadTitle$cCyan║$cReset"
    Write-Host "$cCyan╠══════════════════════════════════════════════════════════════════════════════════════╣$cReset"
    Write-Host "$cCyan║$cReset  $cDark[ PIPELINE STATUS ]$cReset$PadStatus$cCyan║$cReset"

    # Stats Line (Phase / Targets / Progress)
    Write-Host "$cCyan║$cReset  Phase  : $cGreen$Phase / $TotalPhases$cReset | Targets: $cRed$Threats$cReset | Progress: $cCyan$SubProgress%$cReset$PadStats$cCyan║$cReset"

    # Action Line
    Write-Host "$cCyan║$cReset  Action : $cYellow$CurrentTarget$cReset$PadAction$cCyan║$cReset"
    Write-Host "$cCyan╚══════════════════════════════════════════════════════════════════════════════════════╝$cReset"

    # Reset cursor below the 8-line reserved UI area
    if ($curTop -lt 8) { $curTop = 8 }
    [Console]::SetCursorPosition($curLeft, $curTop)
}

$global:TotalThreats = 0

function Invoke-DFIRMinion {
    param($ScriptPath, $ArgsHash, $PhaseNum, $PhaseName)
    if (-not (Test-Path $ScriptPath)) { Write-Host "  $cRed[-] Missing Minion: $ScriptPath$cReset"; return }

    $global:ActivePhaseThreats = 0
    Draw-MasterDashboard $PhaseNum 5 $global:TotalThreats 0 "Initializing $PhaseName..."

    $ArgsHash['Orchestrated'] = $true

    & $ScriptPath @ArgsHash 2>&1 | ForEach-Object {
        $msg = $_.ToString()
        if ($msg.StartsWith("[HUD]|")) {
            $parts = $msg.Split('|')
            $subProg = [int]$parts[1]; $phaseThreats = [int]$parts[2]; $action = $parts[3]
            $global:ActivePhaseThreats = $phaseThreats
            Draw-MasterDashboard $PhaseNum 5 ($global:TotalThreats + $phaseThreats) $subProg $action
        } else {
            $curLeft = [Console]::CursorLeft; $curTop = [Console]::CursorTop
            if ($curTop -lt 8) { $curTop = 8 }
            [Console]::SetCursorPosition(0, $curTop)
            Write-Host $msg
        }
    }
    $global:TotalThreats += $global:ActivePhaseThreats
}

Draw-MasterDashboard 0 5 0 0 "Initializing Pre-Flight Checks..."
Write-Host "`n$cDark[*] Evidence Repository allocated: $EvidenceFolder$cReset"

# =================================================================
# EXECUTE PHASES (DFIR PIPELINE)
# =================================================================

# -----------------------------------------------------------------
# PHASE 1: CYBER THREAT INTELLIGENCE (CTI) ENRICHMENT
# -----------------------------------------------------------------
# Calls the Threat Intel minion to gather fresh indicators of compromise (IoCs).
Invoke-DFIRMinion (Join-Path $ScriptDir "cti_check\Invoke-ThreatIntelCheck.ps1") @{} 1 "CTI Enrichment"

# Locate the most recently generated CTI report in the minion's directory.
$LatestCti = Get-ChildItem -Path (Join-Path $ScriptDir "cti_check") -Filter "threat_intel_report_*.txt" | Sort-Object LastWriteTime -Descending | Select-Object -First 1

# If a report was found, define its new path in the centralized Evidence Folder.
$FinalCtiReport = if ($LatestCti) { Join-Path $EvidenceFolder $LatestCti.Name } else { $null }

# Copy the report to the Evidence Folder so all artifacts are stored together.
if ($LatestCti) { Copy-Item $LatestCti.FullName $FinalCtiReport -Force }

# -----------------------------------------------------------------
# PHASE 2: TRI-LATERAL VECTOR CORRELATION
# -----------------------------------------------------------------
# Defines the paths for the correlation script and its output report.
$CorrScript = Join-Path $ScriptDir "C2VectorCorrelation.ps1"
$CorrelationReport = Join-Path $EvidenceFolder "Correlated_C2_Vectors.txt"

# Prepare the arguments. If a CTI report was generated in Phase 1, pass it down
# the chain so the correlation engine can use it for cross-referencing.
$corrArgs = @{ OutputReport = $CorrelationReport }
if ($FinalCtiReport) { $corrArgs['CtiReportPath'] = $FinalCtiReport }

# Execute the Correlation engine to identify active threats.
Invoke-DFIRMinion $CorrScript $corrArgs 2 "Tri-Lateral Correlation"

# --- TARGET EXTRACTION ---
# Parse the newly generated Correlation Report to extract the Process IDs (PIDs)
# of any identified threats. This creates an array of specific targets for the next phases.
$TargetPIDs = @()
if (Test-Path $CorrelationReport) {
    [regex]::Matches((Get-Content $CorrelationReport -Raw), "\(PID:\s*(\d+)") | ForEach-Object { $TargetPIDs += [int]$_.Groups[1].Value }
    $TargetPIDs = $TargetPIDs | Select-Object -Unique
}

# -----------------------------------------------------------------
# PHASE 3: ADVANCED MEMORY FORENSICS (YARA/SIGNATURE HUNT)
# -----------------------------------------------------------------
$memArgs = @{ ArtifactDirectory = $EvidenceFolder }

# If Phase 2 found specific malicious PIDs, only scan those specific processes.
# If Phase 2 found nothing, do a sweeping scan of ALL running processes.
if ($TargetPIDs.Count -gt 0) {
    $memArgs['ProcessIds'] = $TargetPIDs
} else {
    $memArgs['ScanAll'] = $true
}

# Execute the Memory Hunter to find injected payloads or hollowed processes.
Invoke-DFIRMinion (Join-Path $ScriptDir "Invoke-AdvancedMemoryHunter.ps1") $memArgs 3 "Memory Forensics"

# -----------------------------------------------------------------
# PHASE 4: THREAT CONTAINMENT & HOOK PERSISTANCE ENUMERATION TRIAGE
# -----------------------------------------------------------------
# Pass the Correlation Report into the Containment Engine so it knows exactly
# which threads to suspend and which IPs to block at the firewall level.
$contArgs = @{
    CorrelationReport = $CorrelationReport;
    ContainmentLog = Join-Path $EvidenceFolder "C2_Containment_Actions.log";
    ArmedMode = $ArmedMode;
    EvidenceFolder = $EvidenceFolder
}

# Execute the Containment Engine to freeze the threats in place.
# The Containment script will hook the forensic triage script to enumerate persistant artifacts.
Invoke-DFIRMinion (Join-Path $ScriptDir "Invoke-C2Containment.ps1") $contArgs 4 "Thread Containment"

# -----------------------------------------------------------------
# PHASE 5: DATA-DRIVEN ERADICATION & MEMORY ACQUISITION
# -----------------------------------------------------------------
# Look for the CSV report generated by the Memory Forensics engine (Phase 3).
# Check the evidence folder first, then fall back to the root Temp directory.
$MemReportPath = Join-Path $EvidenceFolder "advanced_memory_injections.csv"
if (-not (Test-Path $MemReportPath)) {
    $MemReportPath = "C:\Temp\advanced_memory_injections.csv"
}

# If the memory report exists, feed it directly into the Sweeper.
if (Test-Path $MemReportPath) {
    $eradArgs = @{
        ReportCSV = $MemReportPath
        EvidenceFolder = $EvidenceFolder
    }

    # If the Orchestrator was launched with -ArmedMode, grant the Eradication
    # Engine the authority to force-reboot the host to flush protected payloads,
    # and safely arm the Registry/Task scubber.
    if ($ArmedMode) {
        $eradArgs['AutoReboot'] = $true
        $eradArgs['ArmedMode'] = $true
    }

    # Execute the final kill-chain to dump memory, destroy drivers, and reboot.
    Invoke-DFIRMinion (Join-Path $ScriptDir "Invoke-AutomatedEradication.ps1") $eradArgs 5 "Automated Eradication & ProcDump"
} else {
    # If no memory report was found, gracefully skip the eradication phase.
    Draw-MasterDashboard 5 5 $global:TotalThreats 100 "No Memory Injection Report Found. Skipping Eradication."
}

# -----------------------------------------------------------------
# PHASE 6: AUTOMATED WINDBG FORENSIC TRIAGE
# -----------------------------------------------------------------
# Scan the Evidence Folder for any memory dumps acquired in Phase 5
$DumpFiles = Get-ChildItem -Path $EvidenceFolder -Filter "*.dmp"
if ($DumpFiles.Count -gt 0) {
    foreach ($dump in $DumpFiles) {
        $triageArgs = @{ DumpPath = $dump.FullName; ReportDir = $EvidenceFolder }
        Invoke-DFIRMinion (Join-Path $ScriptDir "Invoke-DumpAnalysis.ps1") $triageArgs 6 "WinDbg Memory Analysis"
    }
} else {
    Draw-MasterDashboard 6 6 $global:TotalThreats 100 "No Memory Dumps Acquired. Skipping WinDbg Analysis."
}

# --- SUMMARY ---
Draw-MasterDashboard 5 5 $global:TotalThreats 100 "PIPELINE SECURE - AWAITING ANALYST REVIEW"
Write-Host "`n$cGreen============================================================$cReset"
Write-Host " $cGreen[+] DFIR AUTOMATION COMPLETE$cReset"
Write-Host "$cGreen============================================================$cReset"
Write-Host " Evidence Repository : $cCyan$EvidenceFolder$cReset"
[Console]::CursorVisible = $true