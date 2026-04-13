<#
.SYNOPSIS
    Automated C2 Containment and Remediation Engine (DFIR Integrated)
.DESCRIPTION
    Parses the Correlated C2 Vectors report for HIGH and CRITICAL risk findings.
    Automatically terminates malicious process IDs, injects outbound firewall block rules,
    and triggers automated forensic triage to enumerate persistence mechanisms.
.NOTES
    Author: Robert Weber
    Version: 1.0 (V4 Companion)
#>
#Requires -RunAsAdministrator

param (
    [string]$CorrelationReport = "C:\Temp\Correlated_C2_Vectors.txt",
    [string]$ContainmentLog    = "C:\Temp\C2_Containment_Actions.log",
    [string]$TriageScriptPath  = "C:\Temp\C2_Toolkit\Invoke-C2ForensicTriage.ps1", # V1.1 Triage Hook
    [int]$RiskThreshold        = 85,  # Minimum score required to trigger automated containment
    [switch]$ArmedMode                # Script runs in Dry-Run (Safe) mode unless this is passed
)

$ScriptDir = Split-Path $PSCommandPath -Parent
if (-not [System.IO.Path]::IsPathRooted($CorrelationReport)) { $CorrelationReport = Join-Path $ScriptDir $CorrelationReport }
if (-not [System.IO.Path]::IsPathRooted($TriageScriptPath)) { $TriageScriptPath = Join-Path $ScriptDir $TriageScriptPath }

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " [*] C2 CONTAINMENT & REMEDIATION ENGINE" -ForegroundColor Cyan
Write-Host "============================================================`n" -ForegroundColor Cyan

if (-not (Test-Path $CorrelationReport)) {
    Write-Host "[!] CRITICAL: Correlation report not found at $CorrelationReport" -ForegroundColor Red
    exit
}

if (-not $ArmedMode) {
    Write-Host " [!] ENGINE IS IN DRY-RUN MODE. NO LETHAL ACTIONS WILL BE TAKEN. [!]`n" -ForegroundColor Yellow
} else {
    Write-Host " [!] ENGINE ARMED. LETHAL CONTAINMENT AUTHORIZED. [!]`n" -ForegroundColor Red
}

function Write-ContainmentLog {
    param([string]$Message)
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    "[$ts] $Message" | Out-File -FilePath $ContainmentLog -Encoding UTF8 -Append
}

# Protected System PID Whitelist (Prevents BSOD during automated remediation)
$ProtectedPIDs = @(0, 4)

$ActiveRisk = $false
$CurrentScore = 0
$TargetPID = $null
$TargetProcess = $null
$TargetIP = $null

$ActionCount = 0

Write-Host "[*] Scanning Correlation Report for Actionable Threats (Score >= $RiskThreshold)..." -ForegroundColor Yellow

Get-Content $CorrelationReport | ForEach-Object {
    $line = $_.Trim()

    # 1. Detect a new Risk Block
    if ($line -match "RISK LEVEL\s*:\s*(CRITICAL|HIGH)\s*\(Score:\s*(\d+)\)") {
        $CurrentScore = [int]$matches[2]
        if ($CurrentScore -ge $RiskThreshold) {
            $ActiveRisk = $true
        } else {
            $ActiveRisk = $false
        }
    }

    # 2. Extract Process Data if inside an actionable block
    if ($ActiveRisk -and $line -match "PROCESS\s*:\s*(.*)\s*\(PID:\s*(\d+)\)") {
        $TargetProcess = $matches[1].Trim()
        $TargetPID = [int]$matches[2]
    }

    # 3. Extract Destination Data if inside an actionable block
    if ($ActiveRisk -and $line -match "DESTINATION\s*:\s*([0-9\.]+):\d+") {
        $TargetIP = $matches[1]
    }

    # 4. Trigger Remediation at the end of the block
    if ($ActiveRisk -and $line -match "^STATIC FLAGS:") {
        if ($TargetPID -and $TargetIP) {
            Write-Host "`n[!] Actionable Threat Identified: $TargetProcess (PID: $TargetPID) -> $TargetIP (Score: $CurrentScore)" -ForegroundColor Red

            # --- REMEDIATION 1: PROCESS TERMINATION ---
            if ($ProtectedPIDs -contains $TargetPID) {
                Write-Host "    [-] ABORTED PROCESS KILL: PID $TargetPID is a protected System process." -ForegroundColor DarkYellow
                Write-ContainmentLog "ABORTED KILL: PID $TargetPID ($TargetProcess) is protected."
            } else {
                try {
                    $proc = Get-Process -Id $TargetPID -ErrorAction Stop
                    if ($ArmedMode) {
                        Stop-Process -Id $TargetPID -Force -ErrorAction Stop
                        Write-Host "    [+] SUCCESS: Terminated $TargetProcess (PID: $TargetPID)" -ForegroundColor Green
                        Write-ContainmentLog "TERMINATED: $TargetProcess (PID: $TargetPID)"
                    } else {
                        Write-Host "    [?] DRY-RUN: Would have terminated $TargetProcess (PID: $TargetPID)" -ForegroundColor DarkGray
                    }
                    $ActionCount++

                    # --- DFIR ENUMERATION HOOK ---
                    # Executed universally. Read-only operation provides vital eradication data.
                    if (Test-Path $TriageScriptPath) {
                        Write-Host "    [*] Initiating Automated Forensic Triage for PID $TargetPID..." -ForegroundColor Yellow
                        & $TriageScriptPath -TargetPID $TargetPID -AlertTime (Get-Date)
                    } else {
                        Write-Host "    [-] Triage script not found at $TriageScriptPath. Skipping enumeration." -ForegroundColor DarkGray
                    }

                } catch {
                    Write-Host "    [-] Process PID $TargetPID already exited or access denied." -ForegroundColor DarkGray
                }
            }

            # --- REMEDIATION 2: FIREWALL BLACKLISTING ---
            $RuleName = "C2_Hunter_Block_$TargetIP"
            $ExistingRule = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue

            if ($ExistingRule) {
                Write-Host "    [-] Network block rule for $TargetIP already exists." -ForegroundColor DarkGray
            } else {
                if ($ArmedMode) {
                    New-NetFirewallRule -DisplayName $RuleName `
                                        -Direction Outbound `
                                        -Action Block `
                                        -RemoteAddress $TargetIP `
                                        -Description "Automated C2 Hunter Containment (Score: $CurrentScore)" | Out-Null
                    Write-Host "    [+] SUCCESS: Outbound traffic to $TargetIP blocked at Windows Firewall." -ForegroundColor Green
                    Write-ContainmentLog "FIREWALL BLOCK: Dropped outbound traffic to C2 IP $TargetIP"
                } else {
                    Write-Host "    [?] DRY-RUN: Would have created outbound firewall block for $TargetIP" -ForegroundColor DarkGray
                }
                $ActionCount++
            }
        }

        # Reset state for next block
        $ActiveRisk = $false
        $TargetPID = $null
        $TargetIP = $null
    }
}

Write-Host "`n============================================================" -ForegroundColor Cyan
if ($ArmedMode) {
    Write-Host " [+] Containment Complete. Executed $ActionCount remediation actions." -ForegroundColor Green
    Write-Host " [*] Audit log saved to: $ContainmentLog" -ForegroundColor Gray
} else {
    Write-Host " [+] Dry-Run Complete. Simulated $ActionCount remediation actions." -ForegroundColor Yellow
    Write-Host " [*] Pass -ArmedMode to execute lethal containment." -ForegroundColor Gray
}
Write-Host "============================================================`n" -ForegroundColor Cyan