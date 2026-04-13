<#
.SYNOPSIS
    DFIR Triage Analyzer - Post-Collection Automated Triage
.DESCRIPTION
    Parses the JSON artifacts collected from the DFIR Endpoint Collector.
    Applies heuristic rules to identify suspicious processes, C2 network connections,
    persistence mechanisms, and critical event logs to determine if a host requires deep analysis.

.NOTES
    Usage:
    .\triage_response.ps1 -ArtifactDirectory "C:\Windows\Temp\DFIR_Collect\hostname-20240601_120000" -DetailedReport

    The detailed report switch will include the raw data for each finding, which can be useful for analysts who want
    to quickly pivot into deeper analysis without having to manually open each JSON artifact.

    author: @RW
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$ArtifactDirectory,
    [switch]$DetailedReport
)

$ErrorActionPreference = "SilentlyContinue"
$TotalScore = 0
$Findings = @()

function Add-Finding ($Severity, $Category, $Description, $RawData) {
    $script:TotalScore += $Severity
    $script:Findings += [PSCustomObject]@{ Severity = $Severity; Category = $Category; Description = $Description; RawData = $RawData }
}

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " DFIR AUTOMATED TRIAGE ANALYZER " -ForegroundColor Cyan
Write-Host " Analyzing Artifacts in: $ArtifactDirectory"
Write-Host "=============================================" -ForegroundColor Cyan

# ---------------------------------------------------------
# 1. PROCESS TREE ANALYSIS (Hunting LOLBins & Obfuscation)
# ---------------------------------------------------------
$ProcessFile = Join-Path $ArtifactDirectory "ProcessTree.json"
if (Test-Path $ProcessFile) {
    Write-Host "[*] Analyzing Process Execution..."
    $Processes = Get-Content -Path $ProcessFile -Raw | ConvertFrom-Json

    foreach ($Proc in $Processes) {
        # Rule 1: Encoded or Hidden PowerShell
        if ($Proc.CommandLine -match "(?i)-enc|-encodedcommand|-nop|-bypass|-windowstyle hidden") {
            Add-Finding 50 "Execution" "Suspicious PowerShell command line arguments detected" $Proc.CommandLine
        }

        # Rule 2: Execution from Suspicious Directories (Temp, Public, AppData)
        if ($Proc.ExecutablePath -match "(?i)\\Temp\\|\\Users\\Public\\|\\AppData\\Local\\Temp\\") {
            if ($Proc.Name -match "(?i).exe$") {
                Add-Finding 40 "Execution" "Executable running from Temp/Public directory" $Proc.ExecutablePath
            }
        }

        # Rule 3: LOLBin Abuse (Rundll32, Regsvr32, MSHTA)
        if ($Proc.Name -match "(?i)^(rundll32\.exe|regsvr32\.exe|mshta\.exe|certutil\.exe)$") {
             if ($Proc.CommandLine -match "(?i)http|ftp|.ps1|javascript|vbscript") {
                 Add-Finding 60 "Execution" "LOLBin executing remote or script payload" $Proc.CommandLine
             }
        }
    }
}

# ---------------------------------------------------------
# 2. NETWORK CONNECTION ANALYSIS (Hunting C2 Beacons)
# ---------------------------------------------------------
$NetFile = Join-Path $ArtifactDirectory "ActiveNetworkConnections.json"
if (Test-Path $NetFile) {
    Write-Host "[*] Analyzing Network Connections..."
    $NetData = Get-Content -Path $NetFile -Raw | ConvertFrom-Json

    foreach ($Conn in $NetData.TCP) {
        # Rule 4: System processes making outbound connections to non-standard ports
        $SuspiciousPorts = @("4444", "1337", "8080", "8443", "9001")
        if ($Conn.State -eq "Established" -and $Conn.RemotePort -in $SuspiciousPorts) {
            Add-Finding 70 "C2 Network" "Outbound connection to known suspicious port" "Port: $($Conn.RemotePort) | Process ID: $($Conn.OwningProcess)"
        }
    }
}

# ---------------------------------------------------------
# 3. PERSISTENCE ANALYSIS (Hunting Scheduled Tasks & WMI)
# ---------------------------------------------------------
$TasksFile = Join-Path $ArtifactDirectory "ScheduledTasks.json"
if (Test-Path $TasksFile) {
    Write-Host "[*] Analyzing Scheduled Tasks..."
    $Tasks = Get-Content -Path $TasksFile -Raw | ConvertFrom-Json

    foreach ($Task in $Tasks) {
        # Rule 5: Tasks executing shells or web requests
        if ($Task.Action -match "(?i)powershell|cmd\.exe|wscript|cscript|certutil|bitsadmin") {
            Add-Finding 50 "Persistence" "Scheduled Task executing command shell or LOLBin" "Task: $($Task.TaskName) | Action: $($Task.Action)"
        }
    }
}

$WMIFile = Join-Path $ArtifactDirectory "WMIPersistence.json"
if (Test-Path $WMIFile) {
    Write-Host "[*] Analyzing WMI Event Consumers..."
    $WMI = Get-Content -Path $WMIFile -Raw | ConvertFrom-Json

    if ($WMI.Consumers.Count -gt 0) {
        foreach ($Consumer in $WMI.Consumers) {
            # Rule 6: ANY CommandLineEventConsumer is highly suspicious in standard environments
            Add-Finding 80 "Persistence" "WMI CommandLineEventConsumer detected (Fileless Malware Risk)" $Consumer.CommandLineTemplate
        }
    }
}

# ---------------------------------------------------------
# 4. EVENT LOG ANALYSIS (Hunting Advanced TTPs)
# ---------------------------------------------------------
$EventsFile = Join-Path $ArtifactDirectory "CriticalEventLogs.json"
if (Test-Path $EventsFile) {
    Write-Host "[*] Analyzing Critical Event Logs for Legacy & Modern TTPs..."
    $Events = Get-Content -Path $EventsFile -Raw | ConvertFrom-Json

    # Pre-compile regex patterns for performance across thousands of events
    $SuspiciousServices = "(?i)PSEXESVC|Metasploit|Cobalt|Bypass|WCE|winexesvc|gsecdump|wmic|Rundll32|ngrok|AnyDesk|Atera"
    $LotLCommands = "(?i)(-enc|-encodedcommand|bypass|hidden|noninteractive|downloadstring|invoke-webrequest|certutil.*-urlcache|bitsadmin|vssadmin.*delete|wmic.*shadowcopy.*delete|procdump|lsass)"
    $MaliciousPS = "(?i)(VirtualAlloc|MiniDumpWriteDump|System.Reflection.AssemblyName|AmsiScanBuffer|Out-Minidump|Invoke-Mimikatz|Invoke-BloodHound)"

    foreach ($Event in $Events) {
        switch ($Event.Id) {

            # --- DEFENSE EVASION ---
            { $_ -in 1102, 104 } {
                # Event logs cleared
                Add-Finding 100 "Defense Evasion" "Audit or System Event Log explicitly cleared." $Event.TimeCreated
                break
            }

            # --- PERSISTENCE & PRIV ESC ---
            7045 {
                # New Service Installation
                if ($Event.Message -match $SuspiciousServices) {
                    Add-Finding 90 "Execution/PrivEsc" "Suspicious new service installed matching known threat tools/RMMs." $Event.Message
                }
                break
            }

            # --- EXECUTION (LotL & PowerShell) ---
            4688 {
                # Process Creation
                if ($Event.Message -match $LotLCommands) {
                    Add-Finding 85 "Execution" "Suspicious process command line execution (LotL/Ransomware Precursor)." $Event.Message
                }
                break
            }
            4104 {
                # PowerShell Script Block Logging
                if ($Event.Message -match $MaliciousPS) {
                    Add-Finding 95 "Execution/Defense Evasion" "Malicious API calls, dumping, or AMSI bypass in PowerShell script block." $Event.TimeCreated
                }
                break
            }

            # --- LATERAL MOVEMENT & CREDENTIAL ACCESS ---
            4624 {
                # Successful Logon
                if ($Event.Message -match "Logon Type:\s*9") {
                    # Logon Type 9 = NewCredentials (associated with Pass-the-Hash / RunAs /netonly)
                    Add-Finding 80 "Lateral Movement" "Logon Type 9 detected (Potential Pass-the-Hash or Credential Injection)." $Event.TimeCreated
                }
                break
            }
            4625 {
                # Failed Logon
                if ($Event.Message -match "(?i)Account Name:\s*(Administrator|krbtgt|Guest)") {
                    # Flagging targeted brute force against critical built-in accounts
                    Add-Finding 40 "Credential Access" "Failed logon attempt targeting critical default account." $Event.TimeCreated
                }
                break
            }

            # --- RDP / TERMINAL SERVICES LATERAL MOVEMENT ---
            { $_ -in 21, 24, 25 } {
                # 21: Logon succeeded, 24: Session disconnected, 25: Session reconnected
                if ($Event.Id -eq 25) {
                    Add-Finding 60 "Lateral Movement" "RDP Session Reconnected. Review for potential RDP session hijacking." $Event.Message
                }
                break
            }
        }
    }
}

# ---------------------------------------------------------
# TRIAGE VERDICT & SUMMARY
# ---------------------------------------------------------
Write-Host "`n============================================="
Write-Host " TRIAGE VERDICT "
Write-Host "============================================="

$Verdict = "GREEN (CLEAN)"
$VerdictColor = "Green"

if ($TotalScore -ge 100) {
    $Verdict = "RED (COMPROMISE LIKELY - IMMEDIATE ISOLATION REQUIRED)"
    $VerdictColor = "Red"
} elseif ($TotalScore -ge 40) {
    $Verdict = "YELLOW (SUSPICIOUS - DEEP ANALYSIS REQUIRED)"
    $VerdictColor = "Yellow"
}

Write-Host "Host Status: $Verdict" -ForegroundColor $VerdictColor
Write-Host "Total Anomaly Score: $TotalScore`n"

if ($Findings.Count -gt 0) {
    Write-Host "--- CRITICAL FINDINGS ---" -ForegroundColor Red
    $Findings | Sort-Object Severity -Descending | Select-Object Severity, Category, Description | Format-Table -AutoSize

    if ($DetailedReport) {
        Write-Host "--- RAW DATA FOR FINDINGS ---" -ForegroundColor Yellow
        $Findings | Sort-Object Severity -Descending | Select-Object Category, RawData | Format-List
    }
} else {
    Write-Host "No anomalous indicators matched the triage rules. Host can be deprioritized." -ForegroundColor Green
}

$Findings | Export-Csv (Join-Path $ArtifactDirectory "triage_findings.csv") -NoTypeInformation
"VERDICT: $Verdict`nScore: $TotalScore" | Out-File (Join-Path $ArtifactDirectory "triage_summary.txt")