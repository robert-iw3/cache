<#
.SYNOPSIS
    DFIR Statistical Anomaly Hunter
.DESCRIPTION
    Parses DFIR JSON artifacts using mathematical anomaly detection.
    Identifies high-entropy command lines, anomalous parent-child lineages,
    and calculates Coefficient of Variation (CV) for C2 beaconing rhythms.

.NOTES
    Usage:
    .\anomaly_hunt.ps1 -ArtifactDirectory "C:\Windows\Temp\DFIR_Collect\hostname-20240601_120000"

    Author: RW
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$ArtifactDirectory
)

$ErrorActionPreference = "SilentlyContinue"
$Anomalies = @()

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " STATISTICAL & HEURISTIC ANOMALY HUNTER " -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

# ---------------------------------------------------------
# UTILITY: Calculate Shannon Entropy
# ---------------------------------------------------------
function Get-ShannonEntropy ([string]$String) {
    if ([string]::IsNullOrEmpty($String)) { return 0 }
    $Chars = $String.ToCharArray()
    $TotalCount = $Chars.Count
    $Frequencies = @{}
    foreach ($Char in $Chars) { $Frequencies[$Char]++ }

    $Entropy = 0
    foreach ($Key in $Frequencies.Keys) {
        $Probability = $Frequencies[$Key] / $TotalCount
        $Entropy -= $Probability * [Math]::Log($Probability, 2)
    }
    return [Math]::Round($Entropy, 3)
}

# ---------------------------------------------------------
# 1. ENTROPY & LINEAGE ANALYSIS (ProcessTree.json)
# ---------------------------------------------------------
$ProcessFile = Join-Path $ArtifactDirectory "ProcessTree.json"
if (Test-Path $ProcessFile) {
    Write-Host "[*] Calculating Entropy and Process Lineage..."
    $Processes = Get-Content -Path $ProcessFile -Raw | ConvertFrom-Json

    # Build a quick lookup hash table for Parent-Child mapping
    $ProcessMap = @{}
    foreach ($P in $Processes) { $ProcessMap[$P.ProcessId] = $P.Name }

    # Define high-risk parent processes that should rarely spawn shells
    $VulnerableParents = "(?i)^(w3wp\.exe|sqlservr\.exe|winword\.exe|excel\.exe|spoolsv\.exe|httpd\.exe)$"
    $SuspiciousChildren = "(?i)^(cmd\.exe|powershell\.exe|pwsh\.exe|rundll32\.exe|sh\.exe|bash\.exe)$"

    foreach ($Proc in $Processes) {

        # --- A. Shannon Entropy Check ---
        $Entropy = Get-ShannonEntropy $Proc.CommandLine
        if ($Entropy -gt 4.8 -and $Proc.CommandLine -notmatch "(?i)ssh-rsa|Pktmon") {
            $Anomalies += [PSCustomObject]@{
                Category = "High Entropy Execution"
                Score = "Score: $Entropy"
                Details = "PID: $($Proc.ProcessId) | Exec: $($Proc.Name)"
                Raw = $Proc.CommandLine
            }
        }

        # --- B. Process Lineage Check ---
        $ParentName = $ProcessMap[$Proc.ParentProcessId]
        if ($ParentName -match $VulnerableParents -and $Proc.Name -match $SuspiciousChildren) {
             $Anomalies += [PSCustomObject]@{
                Category = "Anomalous Process Lineage"
                Score = "High Risk"
                Details = "Child PID: $($Proc.ProcessId) | Shell: $($Proc.Name)"
                Raw = "Spawned by Vulnerable Parent: $ParentName"
            }
        }

        # --- C. Volatile Path Check ---
        if ($Proc.ExecutablePath -match "(?i)\\ProgramData\\|\\Temp\\|\\AppData\\Local\\Temp\\") {
            if ([string]::IsNullOrWhiteSpace($Proc.CommandLine) -or $Proc.CommandLine -eq $Proc.ExecutablePath) {
                $Anomalies += [PSCustomObject]@{
                    Category = "Volatile Path Execution (No Args)"
                    Score = "Medium Risk"
                    Details = "PID: $($Proc.ProcessId) | Exec: $($Proc.Name)"
                    Raw = $Proc.ExecutablePath
                }
            }
        }
    }
}

# ---------------------------------------------------------
# 2. BEACONING RHYTHM ANALYSIS (ActiveNetworkConnections.json)
# ---------------------------------------------------------
$NetFile = Join-Path $ArtifactDirectory "ActiveNetworkConnections.json"
if (Test-Path $NetFile) {
    Write-Host "[*] Analyzing Network Rhythm (Coefficient of Variation)..."
    $NetData = Get-Content -Path $NetFile -Raw | ConvertFrom-Json

    $TargetGroups = $NetData.TCP | Where-Object {$_.RemoteAddress -notmatch "^127\.|^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\."} | Group-Object RemoteAddress

    foreach ($Group in $TargetGroups) {
        # Need at least 4 concurrent/recent connections to establish a pattern
        if ($Group.Count -ge 4) {
            $Times = $Group.Group | Sort-Object CreationTime | ForEach-Object { [datetime]$_.CreationTime }

            $Deltas = @()
            for ($i = 1; $i -lt $Times.Count; $i++) {
                $Deltas += ($Times[$i] - $Times[$i-1]).TotalSeconds
            }

            # Math: Mean & Standard Deviation
            $Mean = ($Deltas | Measure-Object -Average).Average
            $SumOfSquares = 0
            foreach ($Delta in $Deltas) { $SumOfSquares += [Math]::Pow(($Delta - $Mean), 2) }
            $StdDev = [Math]::Sqrt($SumOfSquares / $Deltas.Count)

            # Math: Coefficient of Variation (CV = StdDev / Mean)
            $CV = 0
            if ($Mean -gt 0) { $CV = $StdDev / $Mean }

            # C2 beacons with programmed jitter (e.g. 10-20%) typically result in a CV between 0.05 and 0.35.
            # Human organic web traffic usually results in a CV > 1.0.
            if ($CV -lt 0.35 -and $Mean -gt 1.0) {
                $Anomalies += [PSCustomObject]@{
                    Category = "Programmatic C2 Beaconing"
                    Score = "CV: $([Math]::Round($CV, 3))"
                    Details = "Target IP: $($Group.Name) | Connections: $($Group.Count)"
                    Raw = "Mean Interval: $([Math]::Round($Mean, 2))s | StdDev: $([Math]::Round($StdDev, 2))s"
                }
            }
        }
    }
}

# ---------------------------------------------------------
# OUTPUT ANOMALIES
# ---------------------------------------------------------
Write-Host "`n============================================="
Write-Host " DETECTED MATHEMATICAL ANOMALIES "
Write-Host "============================================="

if ($Anomalies.Count -gt 0) {
    $Anomalies | Sort-Object Category, Score -Descending | Format-Table -AutoSize
} else {
    Write-Host "No statistical anomalies detected. Execution and network rhythm appear organic." -ForegroundColor Green
}

$Anomalies | Export-Csv (Join-Path $ArtifactDirectory "anomaly_findings.csv") -NoTypeInformation
"Anomalies detected: $($Anomalies.Count)" | Out-File (Join-Path $ArtifactDirectory "anomaly_summary.txt")