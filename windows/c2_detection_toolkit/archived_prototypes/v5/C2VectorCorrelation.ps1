<#
.SYNOPSIS
    Automated Tri-Lateral C2 Vector Correlation Engine
.DESCRIPTION
    Ingests the JSONL ML alerts, plaintext connection logs, and CTI enrichment reports.
    Correlates mathematical anomalies with process names and external threat intel to
    generate a prioritized list of high-risk vectors requiring immediate SOC investigation.
.NOTES
    Author: Robert Weber
    Version: 1.0 (V5 Companion)
#>
#Requires -RunAsAdministrator

param (
    [string]$MonitorLogPath = "C:\Temp\OutboundNetwork_Monitor.log",
    [string]$JsonlLogPath   = "C:\Temp\C2KernelMonitoring_v5.jsonl",
    [string]$CtiReportPath  = "C:\Temp\threat_intel_report_20260404_164702.txt",
    [string]$OutputReport   = "C:\Temp\Correlated_C2_Vectors.txt",
    [switch]$Orchestrated
)

$ScriptDir = Split-Path $PSCommandPath -Parent
if (-not [System.IO.Path]::IsPathRooted($CtiReportPath)) { $CtiReportPath = Join-Path $ScriptDir $CtiReportPath }

# =================================================================
# DUAL-MODE UI ENGINE
# =================================================================
$ESC = [char]27
$cRed = "$ESC[38;2;255;70;85m"; $cCyan = "$ESC[38;2;0;200;255m"; $cGreen = "$ESC[38;2;10;210;130m"; $cDark = "$ESC[38;2;100;100;100m"; $cYellow = "$ESC[38;2;255;180;50m"; $cReset = "$ESC[0m"

if (-not $Orchestrated) {
    $Host.UI.RawUI.WindowTitle = "V5 DFIR // C2 VECTOR CORRELATION"
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
        $EngineName = "C2 VECTOR CORRELATION"
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

foreach ($file in @($MonitorLogPath, $JsonlLogPath, $CtiReportPath)) {
    if (-not (Test-Path $file)) { Write-Output "  $cRed[!] CRITICAL:$cReset Required file not found -> $file"; exit }
}

$CorrelatedThreats = 0

# --- PHASE 1 ---
Update-UI 25 $CorrelatedThreats "Parsing CTI Intelligence Report..."
$CtiData = @{}; $currentIP = $null
Get-Content $CtiReportPath | ForEach-Object {
    $line = $_.Trim()
    if ($line -match "^TARGET IP:\s*([0-9\.]+)") {
        $currentIP = $matches[1]; $CtiData[$currentIP] = @{ Malicious = 0; Framework = "None"; Abuse = 0 }
    } elseif ($currentIP) {
        if ($line -match "VT Malicious Hits:\s*([1-9][0-9]*)") { $CtiData[$currentIP].Malicious = [int]$matches[1] }
        if ($line -match "C2 Framework Match:\s*(?!No specific)(.*)") { $CtiData[$currentIP].Framework = $matches[1] }
        if ($line -match "Abuse Confidence Score:\s*([1-9][0-9]*)%") { $CtiData[$currentIP].Abuse = [int]$matches[1] }
    }
}
$DirtyIPs = @{}
foreach ($key in $CtiData.Keys) {
    if ($CtiData[$key].Malicious -gt 0 -or $CtiData[$key].Framework -ne "None" -or $CtiData[$key].Abuse -ge 20) { $DirtyIPs[$key] = $CtiData[$key] }
}
Write-Output "  $cGreen[+]$cReset Loaded $($DirtyIPs.Count) IPs meeting CTI thresholds."

# --- PHASE 2 ---
Update-UI 50 $CorrelatedThreats "Rebuilding Process-to-Network Ledger..."
$NetworkLedger = @{}
Get-Content $MonitorLogPath | ForEach-Object {
    if ($_ -match "Destination IP: (.*?), Destination Domain: (.*?), Port: (.*?), PID: (.*?), Process Name: (.*?),") {
        $ip = $matches[1]; $domain = $matches[2]; $port = $matches[3]; $flowPid = $matches[4]; $proc = $matches[5]
        $key = "${ip}_${flowPid}"
        if (-not $NetworkLedger.ContainsKey($key)) {
            $NetworkLedger[$key] = @{ IP = $ip; Domain = $domain; Port = $port; PID = $flowPid; ProcessName = $proc; ML_Alerts = @(); Static_Alerts = @() }
        }
    }
}

# --- PHASE 3 ---
Update-UI 75 $CorrelatedThreats "Correlating Mathematical & Cryptographic Alerts..."
Get-Content $JsonlLogPath | ConvertFrom-Json | ForEach-Object {
    $evt = $_
    if ($evt.EventType -eq "ML_Beacon" -and $evt.Destination) {
        $flowPid = "Unknown"; $ip = "Unknown"
        $parts = $evt.Destination -split "_Port_"
        if ($parts.Count -gt 0) {
            $prefix = $parts[0]
            if ($prefix -match "PID_(\d+)_IP_([0-9\.]+)") { $flowPid = $matches[1]; $ip = $matches[2] }
            elseif ($prefix -match "PID_(\d+)") {
                $flowPid = $matches[1]
                foreach ($k in $NetworkLedger.Keys) { if ($NetworkLedger[$k].PID -eq $flowPid) { $ip = $NetworkLedger[$k].IP; break } }
            }
        }
        $key = "${ip}_${flowPid}"
        if ($NetworkLedger.ContainsKey($key)) { $NetworkLedger[$key].ML_Alerts += $evt.SuspiciousFlags }
    }
    # Integrate JA3 Cryptographic Fingerprints
    elseif ($evt.EventType -eq "JA3_C2_FINGERPRINT" -and $evt.Destination) {
        $ip = $evt.Destination; $proc = $evt.Image
        $MatchedKey = $null
        # Match Layer 2 IP to Layer 4 Process Ledger
        foreach ($k in $NetworkLedger.Keys) {
            if ($NetworkLedger[$k].IP -eq $ip -and $NetworkLedger[$k].ProcessName -eq $proc) { $MatchedKey = $k; break }
        }
        if (-not $MatchedKey) {
            $MatchedKey = "${ip}_Unknown"
            if (-not $NetworkLedger.ContainsKey($MatchedKey)) {
                $NetworkLedger[$MatchedKey] = @{ IP = $ip; Domain = "Unknown"; Port = "443"; PID = "Unknown"; ProcessName = $proc; ML_Alerts = @(); Static_Alerts = @() }
            }
        }
        $NetworkLedger[$MatchedKey].ML_Alerts += $evt.SuspiciousFlags
    }
    elseif ($evt.EventType -match "EventID" -and $evt.DestinationHostname) {
        foreach ($k in $NetworkLedger.Keys) { if ($NetworkLedger[$k].Domain -match $evt.DestinationHostname) { $NetworkLedger[$k].Static_Alerts += $evt.SuspiciousFlags } }
    }
}

# --- PHASE 4 ---
Update-UI 90 $CorrelatedThreats "Generating Prioritized Vector Report..."
$Vectors = @()
foreach ($key in $NetworkLedger.Keys) {
    $flow = $NetworkLedger[$key]
    $hasCti = $DirtyIPs.ContainsKey($flow.IP); $hasMl = $flow.ML_Alerts.Count -gt 0; $hasStatic = $flow.Static_Alerts.Count -gt 0

    if ($hasCti -or $hasMl -or $hasStatic) {
        $score = 0
        if ($hasCti) { $score += 50 }
        if ($hasMl) {
            $score += 30
            # Instant Critical Score for verified Cryptographic C2 Matches
            if ($flow.ML_Alerts -match "Matched Abuse.ch JA3 Profile") { $score += 100 }
        }
        if ($hasStatic) { $score += 20 }
        if ($flow.ProcessName -match "pwsh|powershell|cmd|mshta|rundll32|regsvr32") { $score += 40 }

        $Vectors += [PSCustomObject]@{
            Score = $score
            Process = "$($flow.ProcessName) (PID: $($flow.PID))"
            Destination = "$($flow.IP):$($flow.Port) ($($flow.Domain))"
            ML_Alerts = if ($hasMl) { ($flow.ML_Alerts | Select-Object -Unique) -join " | " } else { "None" }
            Static_Alerts = if ($hasStatic) { ($flow.Static_Alerts | Select-Object -Unique) -join " | " } else { "None" }
            CTI_Intel = if ($hasCti) { "VT: $($DirtyIPs[$flow.IP].Malicious), Framework: $($DirtyIPs[$flow.IP].Framework), AbuseIPDB: $($DirtyIPs[$flow.IP].Abuse)%" } else { "Clean/Unknown" }
        }
    }
}

$Vectors = $Vectors | Sort-Object Score -Descending
$CorrelatedThreats = $Vectors.Count

$ReportContent = @(
    "============================================================"
    "  TARGETED INVESTIGATION REPORT (Correlated C2 Vectors)     "
    "  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')      "
    "============================================================`n"
)

foreach ($v in $Vectors) {
    $riskLevel = if ($v.Score -ge 90) { "CRITICAL" } elseif ($v.Score -ge 50) { "HIGH" } else { "MEDIUM" }
    $ReportContent += "------------------------------------------------------------"
    $ReportContent += "RISK LEVEL  : $riskLevel (Score: $($v.Score))"
    $ReportContent += "  PROCESS     : $($v.Process)`n"
    $ReportContent += "DESTINATION : $($v.Destination)"
    $ReportContent += "CTI INTEL   : $($v.CTI_Intel)"
    $ReportContent += "ML ALERTS   : $($v.ML_Alerts)"
    $ReportContent += "STATIC FLAGS: $($v.Static_Alerts)"
    $ReportContent += "------------------------------------------------------------`n"
}

$ReportContent | Out-File -FilePath $OutputReport -Encoding UTF8
Update-UI 100 $CorrelatedThreats "Vector Correlation Complete."
if (-not $Orchestrated) { [Console]::CursorVisible = $true }