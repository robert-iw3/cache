<#
.SYNOPSIS
    Automated Tri-Lateral C2 Vector Correlation Engine
.DESCRIPTION
    Ingests the JSONL ML alerts, plaintext connection logs, and CTI enrichment reports.
    Correlates mathematical anomalies with process names and external threat intel to
    generate a prioritized list of high-risk vectors requiring immediate SOC investigation.
.NOTES
    Author: Robert Weber
    Version: 1.0 (V4 Companion)
#>
#Requires -RunAsAdministrator

param (
    [string]$MonitorLogPath = "C:\Temp\OutboundNetwork_Monitor.log",
    [string]$JsonlLogPath   = "C:\Temp\C2KernelMonitoring_v4.jsonl",
    [string]$CtiReportPath  = "C:\Temp\threat_intel_report_20260404_164702.txt", # Update with your specific directory and filename
    [string]$OutputReport   = "C:\Temp\Correlated_C2_Vectors.txt"
)

$ScriptDir = Split-Path $PSCommandPath -Parent
if (-not [System.IO.Path]::IsPathRooted($CtiReportPath)) { $CtiReportPath = Join-Path $ScriptDir $CtiReportPath }

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " [*] C2 VECTOR CORRELATION ENGINE" -ForegroundColor Cyan
Write-Host "============================================================`n" -ForegroundColor Cyan

# Ensure all files exist
foreach ($file in @($MonitorLogPath, $JsonlLogPath, $CtiReportPath)) {
    if (-not (Test-Path $file)) {
        Write-Host "[!] CRITICAL: Required file not found -> $file" -ForegroundColor Red
        exit
    }
}

# =================================================================
# PHASE 1: Parse CTI Report for Dirty IPs
# =================================================================
Write-Host "[1/4] Parsing CTI Intelligence Report..." -ForegroundColor Yellow
$CtiData = @{}
$currentIP = $null

Get-Content $CtiReportPath | ForEach-Object {
    $line = $_.Trim()
    if ($line -match "^TARGET IP:\s*([0-9\.]+)") {
        $currentIP = $matches[1]
        $CtiData[$currentIP] = @{ Malicious = 0; Framework = "None"; Abuse = 0 }
    } elseif ($currentIP) {
        if ($line -match "VT Malicious Hits:\s*([1-9][0-9]*)") { $CtiData[$currentIP].Malicious = [int]$matches[1] }
        if ($line -match "C2 Framework Match:\s*(?!No specific)(.*)") { $CtiData[$currentIP].Framework = $matches[1] }
        if ($line -match "Abuse Confidence Score:\s*([1-9][0-9]*)%") { $CtiData[$currentIP].Abuse = [int]$matches[1] }
    }
}

# Filter out clean IPs
$DirtyIPs = @{}
foreach ($key in $CtiData.Keys) {
    # Tuning: Raised AbuseIPDB threshold from > 0 to >= 20 to eliminate shared-infrastructure false positives.
    if ($CtiData[$key].Malicious -gt 0 -or $CtiData[$key].Framework -ne "None" -or $CtiData[$key].Abuse -ge 20) {
        $DirtyIPs[$key] = $CtiData[$key]
    }
}
Write-Host "      [+] Found $($DirtyIPs.Count) IPs meeting the high-confidence CTI threshold." -ForegroundColor Green


# =================================================================
# PHASE 2: Parse Network Ledger to map PIDs to Processes
# =================================================================
Write-Host "[2/4] Rebuilding Process-to-Network Ledger..." -ForegroundColor Yellow
$NetworkLedger = @{} # Key: IP_PID, Value: FlowData

Get-Content $MonitorLogPath | ForEach-Object {
    # Regex matching the V4 deduplication log format
    if ($_ -match "Destination IP: (.*?), Destination Domain: (.*?), Port: (.*?), PID: (.*?), Process Name: (.*?),") {
        # Using $flowPid to completely avoid the reserved $PID variable
        $ip = $matches[1]; $domain = $matches[2]; $port = $matches[3]; $flowPid = $matches[4]; $proc = $matches[5]
        $key = "${ip}_${flowPid}"

        if (-not $NetworkLedger.ContainsKey($key)) {
            $NetworkLedger[$key] = @{
                IP = $ip; Domain = $domain; Port = $port; PID = $flowPid; ProcessName = $proc; ML_Alerts = @(); Static_Alerts = @()
            }
        }
    }
}
Write-Host "      [+] Mapped $($NetworkLedger.Count) unique Process-to-IP flows." -ForegroundColor Green


# =================================================================
# PHASE 3: Map JSONL Alerts to Ledger
# =================================================================
Write-Host "[3/4] Correlating Mathematical Anomaly Alerts..." -ForegroundColor Yellow
Get-Content $JsonlLogPath | ConvertFrom-Json | ForEach-Object {
    $evt = $_
    if ($evt.EventType -eq "ML_Beacon" -and $evt.Destination) {

        # Using $flowPid instead of $pid
        $flowPid = "Unknown"; $ip = "Unknown"

        $parts = $evt.Destination -split "_Port_"
        if ($parts.Count -gt 0) {
            $prefix = $parts[0]
            if ($prefix -match "PID_(\d+)_IP_([0-9\.]+)") {
                $flowPid = $matches[1]; $ip = $matches[2]
            } elseif ($prefix -match "PID_(\d+)") {
                $flowPid = $matches[1]
                # If IP isn't in the ML key, we must find it via the PID in the ledger
                foreach ($k in $NetworkLedger.Keys) {
                    if ($NetworkLedger[$k].PID -eq $flowPid) { $ip = $NetworkLedger[$k].IP; break }
                }
            }
        }

        $key = "${ip}_${flowPid}"
        if ($NetworkLedger.ContainsKey($key)) {
            $NetworkLedger[$key].ML_Alerts += $evt.SuspiciousFlags
        }
    }
    elseif ($evt.EventType -match "EventID" -and $evt.DestinationHostname) {
        # Map Static DGA alerts to any IP that resolved to that domain
        foreach ($k in $NetworkLedger.Keys) {
            if ($NetworkLedger[$k].Domain -match $evt.DestinationHostname) {
                $NetworkLedger[$k].Static_Alerts += $evt.SuspiciousFlags
            }
        }
    }
}
Write-Host "      [+] Anomalies mapped." -ForegroundColor Green


# =================================================================
# PHASE 4: Build Investigation Report
# =================================================================
Write-Host "[4/4] Generating Prioritized Vector Report..." -ForegroundColor Yellow

$Vectors = @()
foreach ($key in $NetworkLedger.Keys) {
    $flow = $NetworkLedger[$key]
    $hasCti = $DirtyIPs.ContainsKey($flow.IP)
    $hasMl = $flow.ML_Alerts.Count -gt 0
    $hasStatic = $flow.Static_Alerts.Count -gt 0

    # Only report vectors that have at least one anomaly or CTI hit
    if ($hasCti -or $hasMl -or $hasStatic) {
        $score = 0
        if ($hasCti) { $score += 50 }
        if ($hasMl) { $score += 30 }
        if ($hasStatic) { $score += 20 }
        if ($flow.ProcessName -match "pwsh|powershell|cmd|mshta|rundll32|regsvr32") { $score += 40 } # LOLBin penalty

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

# Sort by Risk Score
$Vectors = $Vectors | Sort-Object Score -Descending

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
    $ReportContent += "PROCESS     : $($v.Process)"
    $ReportContent += "DESTINATION : $($v.Destination)"
    $ReportContent += "CTI INTEL   : $($v.CTI_Intel)"
    $ReportContent += "ML ALERTS   : $($v.ML_Alerts)"
    $ReportContent += "STATIC FLAGS: $($v.Static_Alerts)"
    $ReportContent += "------------------------------------------------------------`n"
}

$ReportContent | Out-File -FilePath $OutputReport -Encoding UTF8
Write-Host "      [+] Correlation complete. See report at: $OutputReport" -ForegroundColor Green
