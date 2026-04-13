<#
.SYNOPSIS
    EDR Toolkit - Fleet Analysis & Tuning Engine
.DESCRIPTION
    Ingests JSON reports from the EDR Toolkit. Applies a universal Windows baseline
    to filter out OS-level noise, leaving only actionable anomalies.
    Designed to be deployed centrally to parse logs from multiple endpoints.
.PARAMETER ReportPath
    Path to the EDR_Report_*.json file (or a directory of JSON files).
.PARAMETER ExportCSV
    Exports the filtered findings to a clean CSV for SIEM ingestion.
.PARAMETER ShowGrid
    Opens the actionable alerts in an interactive Out-GridView.
.EXAMPLE
    .\Analyze-EDRReport.ps1 -ReportPath .\EDR_Report_20260402_011825.json -ShowGrid
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [String]$ReportPath,
    [Switch]$ExportCSV,
    [Switch]$ShowGrid
)

# =============================================================================
# 1. THE TUNING BLOCK (Universal Windows Baselines)
# =============================================================================

# Universal NT Kernel & Core OS Processes
$Global_FP_Processes = @(
    "^\s*System Idle Process\s*$",
    "^\s*System\s*$",
    "^\s*Secure System\s*$",
    "^\s*Registry\s*$",
    "^\s*Memory Compression\s*$",
    "smss\.exe", "csrss\.exe", "wininit\.exe", "services\.exe", "lsass\.exe", "winlogon\.exe"
)

# Standard Microsoft/Windows Component Paths
$Global_FP_Paths = @(
    "\\Windows\\System32\\",
    "\\Windows\\SysWOW64\\",
    "\\Windows\\WinSxS\\",
    "\\Windows\\Microsoft\.NET\\",
    "\\Program Files\\Common Files\\System\\",
    "\\Program Files\\Microsoft Office\\",
    "\\Program Files \(x86\)\\Microsoft Office\\",
    "\\ProgramData\\Microsoft\\Office\\"
)

# Known benign boot-time operations (OS Updates, Temp cleanup)
$Global_FP_Renames = @(
    "\\Windows\\Temp\\",
    "\\Windows\\Prefetch\\",
    "\\Windows\\SoftwareDistribution\\Download\\",
    "\\Windows\\servicing\\Packages\\"
)

# =============================================================================
# 2. INGESTION ENGINE
# =============================================================================

$filesToProcess = @()
if (Test-Path $ReportPath -PathType Container) {
    $filesToProcess = Get-ChildItem -Path $ReportPath -Filter "*.json" -File
} else {
    $filesToProcess = Get-Item -Path $ReportPath
}

if ($filesToProcess.Count -eq 0) {
    Write-Host "[-] No JSON reports found at specified path." -ForegroundColor Red
    exit
}

$allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($file in $filesToProcess) {
    $content = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
    if ($content) {
        foreach ($item in $content) {
            $allFindings.Add($item)
        }
    }
}

Write-Host "[*] Ingested $($allFindings.Count) total raw events across $($filesToProcess.Count) report(s)." -ForegroundColor Gray
Write-Host "[*] Applying Universal Windows Baseline filters..." -ForegroundColor Cyan

# =============================================================================
# 3. FILTERING LOGIC
# =============================================================================

$actionableFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($finding in $allFindings) {
    $isFP = $false

    switch ($finding.Type) {

        "Hidden Process" {
            foreach ($proc in $Global_FP_Processes) {
                if ($finding.Details -match $proc) { $isFP = $true; break }
            }
        }

        "PendingFileRenameOperations" {
            foreach ($path in $Global_FP_Renames) {
                if ($finding.Details -match [regex]::Escape($path)) { $isFP = $true; break }
            }
        }

        # Check COM Hijacking, Cloaked Files, and High Entropy against trusted paths
        { $_ -in "COM Hijacking", "Cloaked File", "High Entropy File" } {
            $targetPath = if ($finding.Target) { $finding.Target } else { $finding.Details }
            foreach ($path in $Global_FP_Paths) {
                if ($targetPath -match [regex]::Escape($path)) { $isFP = $true; break }
            }
        }

        "Alternate Data Stream" {
            if ($finding.Details -match "Zone\.Identifier") { $isFP = $true }
        }
    }

    if (-not $isFP) {
        $actionableFindings.Add($finding)
    }
}

# =============================================================================
# 4. TRIAGE & OUTPUT
# =============================================================================

$fpCount = $allFindings.Count - $actionableFindings.Count
Write-Host "[+] Baseline Tuning Complete. Filtered out $fpCount normal OS/App events." -ForegroundColor Green
Write-Host "==================================================================="

if ($actionableFindings.Count -eq 0) {
    Write-Host "[+] ZERO ACTIONABLE FINDINGS. Fleet baseline is clean." -ForegroundColor Green
    exit
}

Write-Host "[!] ACTIONABLE FINDINGS: $($actionableFindings.Count)" -ForegroundColor Red

# Quick Console Summary
$actionableFindings | Group-Object Severity | Sort-Object Count -Descending | Select-Object Count, Name | Format-Table -AutoSize
$actionableFindings | Group-Object Type | Sort-Object Count -Descending | Select-Object Count, Name | Format-Table -AutoSize

if ($ShowGrid) {
    Write-Host "[*] Launching interactive triage grid..." -ForegroundColor Gray
    $actionableFindings | Out-GridView -Title "Actionable EDR Alerts (Tuned)"
}

if ($ExportCSV) {
    $timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $outPath = ".\Fleet_Actionable_Alerts_$timestamp.csv"
    $actionableFindings | Export-Csv -Path $outPath -NoTypeInformation
    Write-Host "[+] Actionable alerts exported to: $outPath" -ForegroundColor Green
}