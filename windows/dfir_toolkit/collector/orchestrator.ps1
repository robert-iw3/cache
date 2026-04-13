<#
.SYNOPSIS
    DFIR Orchestrator

.DESCRIPTION
    A master script to orchestrate the entire DFIR pipeline: collection, analysis, anomaly hunting, memory scanning, and report generation.
    It sequentially executes each phase and compiles an executive report with triage results, statistical anomalies, and memory findings.

.NOTES
    Usage:
    .\orchestrator.ps1 -KeepLocalCopy -DetailedReport -ScanAllMemory

    Author: RW
#>

param (
    [switch]$KeepLocalCopy,
    [switch]$DetailedReport,
    [switch]$ScanAllMemory
)

$ErrorActionPreference = "SilentlyContinue"
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " DFIR ORCHESTRATOR v3.0 " -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

# 1. Collection Phase
Write-Host "`n[*] INITIATING COLLECTION PHASE..." -ForegroundColor Yellow
.\collect_forensics.ps1 -KeepLocalCopy:$KeepLocalCopy

$LatestDir = Get-ChildItem "C:\Windows\Temp\DFIR_Collect" -Directory | Sort-Object CreationTime -Descending | Select-Object -First 1
$Path = $LatestDir.FullName

if (-not $Path) {
    Write-Host "[!] FATAL: Collection failed or directory not found." -ForegroundColor Red
    exit
}

# 2. Analysis & Hunt Phase
Write-Host "`n[*] INITIATING ANALYSIS & HUNTING PHASE..." -ForegroundColor Yellow
.\triage_response.ps1 -ArtifactDirectory $Path -DetailedReport:$DetailedReport
.\anomaly_hunt.ps1 -ArtifactDirectory $Path

# 3. Memory Hunt Phase
Write-Host "`n[*] INITIATING MEMORY SCAN..." -ForegroundColor Yellow
if ($ScanAllMemory) {
    .\memory_hunter.ps1 -ArtifactDirectory $Path -ScanAll
} else {
    .\memory_hunter.ps1 -ArtifactDirectory $Path
}

# 4. Reporting Phase
Write-Host "`n[*] GENERATING INTELLIGENCE REPORT..." -ForegroundColor Yellow
$Manifest = Get-Content "$Path\manifest.json" | ConvertFrom-Json

# Parse Memory Findings for the Report
$MemoryFindingsText = "<span style='color:green'>No memory injections detected in targeted processes.</span>"
$MemoryCsvPath = Join-Path $Path "memory_injections.csv"
if (Test-Path $MemoryCsvPath) {
    $MemData = Import-Csv $MemoryCsvPath
    $MemCount = @($MemData).Count # Force array to get accurate count
    $MemoryFindingsText = "<span style='color:red; font-weight:bold'>CRITICAL: $MemCount memory injection(s) detected! Review memory_injections.csv.</span>"
}

# Generate HTML
$Report = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f4f9; color: #333; padding: 20px; }
        h1 { border-bottom: 2px solid #0056b3; padding-bottom: 10px; color: #0056b3; }
        h2 { margin-top: 30px; color: #444; }
        pre { background: #2b2b2b; color: #f8f8f2; padding: 15px; border-radius: 5px; overflow-x: auto; }
        .alert { background-color: #fff3cd; border-left: 5px solid #ffecb5; padding: 10px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <h1>DFIR Executive Report – $($env:COMPUTERNAME)</h1>
    <div class="alert">
        <strong>Chain-of-Custody ZIP SHA256:</strong> $($Manifest.ZipSHA256)<br>
        <strong>Collection Time:</strong> $($Manifest.Timestamp)
    </div>

    <h2>1. Triage Verdict</h2>
    <pre>$(Get-Content "$Path\triage_summary.txt" -Raw)</pre>

    <h2>2. Advanced Threats (Memory & C2)</h2>
    <p>$MemoryFindingsText</p>

    <h2>3. Statistical Anomalies</h2>
    <pre>$(Get-Content "$Path\anomaly_summary.txt" -Raw)</pre>
</body>
</html>
"@

$Report | Out-File "$Path\DFIR_Report_$($env:COMPUTERNAME).html" -Encoding UTF8

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " FULL PIPELINE COMPLETE! " -ForegroundColor Green
Write-Host " Report: $Path\DFIR_Report_$($env:COMPUTERNAME).html" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Cyan