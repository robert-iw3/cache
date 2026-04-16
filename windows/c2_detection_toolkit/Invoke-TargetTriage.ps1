<#
.SYNOPSIS
    Targeted Forensic Triage Script - In-Memory C2 & Fast-Flux Detection
.DESCRIPTION
    Audits live system state for behavioral indicators of advanced C2 frameworks,
    specifically focusing on process injection (svchost masquerading) and
    Fast-Flux network infrastructure evasion.
#>
#Requires -RunAsAdministrator

function Invoke-TargetTriage {
    [CmdletBinding()]
    param (
        [int]$FastFluxThreshold = 8,
        [switch]$SuspendAnomalies
    )

    $Report = [System.Collections.Generic.List[PSCustomObject]]::new()
    Write-Host "[*] Initiating Live Memory & Network Triage..." -ForegroundColor Cyan

    # =====================================================================
    # PHASE 1: SVCHOST & PROCESS INJECTION HUNTING
    # =====================================================================
    Write-Host "    -> Auditing core system processes for injection indicators..." -ForegroundColor Gray

    # Get all processes with their command lines (requires WMI/CIM for reliable extraction)
    $Processes = Get-CimInstance Win32_Process

    foreach ($Proc in $Processes) {
        $Flags = @()

        # Indicator 1: svchost.exe running without the standard service (-k) arguments
        if ($Proc.Name -eq "svchost.exe") {
            if ([string]::IsNullOrWhiteSpace($Proc.CommandLine) -or $Proc.CommandLine -notmatch "-k ") {
                $Flags += "Anomalous Execution: svchost.exe missing standard service arguments"
            }
        }

        # Indicator 2: Processes running from suspicious directories
        if ($Proc.ExecutablePath -match "\\Temp\\|\\AppData\\Local\\Temp\\|\\ProgramData\\") {
            $Flags += "Suspicious Path: Executing from temporary or public directory"
        }

        if ($Flags.Count -gt 0) {
            $Report.Add([PSCustomObject]@{
                Category    = "Process Anomaly"
                PID         = $Proc.ProcessId
                Name        = $Proc.Name
                Path        = $Proc.ExecutablePath
                CommandLine = $Proc.CommandLine
                Details     = $Flags -join "; "
            })
        }
    }

    # =====================================================================
    # PHASE 2: FAST-FLUX & NETWORK CHURN ANALYSIS
    # =====================================================================
    Write-Host "    -> Correlating active TCP connections for Fast-Flux churn..." -ForegroundColor Gray

    $ActiveConnections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
                         Where-Object { $_.RemoteAddress -notmatch "^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^127\." }

    $NetworkMap = @{}
    foreach ($Conn in $ActiveConnections) {
        if (-not $NetworkMap.ContainsKey($Conn.OwningProcess)) {
            $NetworkMap[$Conn.OwningProcess] = [System.Collections.Generic.HashSet[string]]::new()
        }
        [void]$NetworkMap[$Conn.OwningProcess].Add($Conn.RemoteAddress)
    }

    foreach ($TargetId in $NetworkMap.Keys) {
        $UniqueIPs = $NetworkMap[$TargetId].Count
        if ($UniqueIPs -ge $FastFluxThreshold) {
            $ProcName = "Unknown/Terminated"
            try { $ProcName = (Get-Process -Id $TargetId -ErrorAction Stop).Name } catch {}

            $Report.Add([PSCustomObject]@{
                Category    = "Network Anomaly (Fast-Flux)"
                PID         = $TargetId
                Name        = $ProcName
                Path        = "N/A"
                CommandLine = "N/A"
                Details     = "High IP Churn Detected: Process connected to $UniqueIPs unique external IPs."
            })
        }
    }

    # =====================================================================
    # PHASE 3: MITIGATION & REPORTING
    # =====================================================================
    Write-Host "[+] Triage complete. Compiling findings..." -ForegroundColor Green

    if ($Report.Count -eq 0) {
        Write-Host "No active anomalies detected during this sweep." -ForegroundColor Yellow
        return
    }

    $Report | Format-Table -AutoSize -Wrap

    if ($SuspendAnomalies) {
        Write-Host "[!] Initiating containment protocol for identified processes..." -ForegroundColor Red
        foreach ($Entry in $Report) {
            if ($Entry.PID -and $Entry.PID -ne 0 -and $Entry.PID -ne 4) {
                try {
                    # Isolate the process rather than relying on system termination calls
                    Suspend-Process -Id $Entry.PID -ErrorAction Stop
                    Write-Host "    -> Successfully suspended PID: $($Entry.PID) ($($Entry.Name))" -ForegroundColor Yellow
                } catch {
                    Write-Host "    -> Failed to suspend PID: $($Entry.PID). Process may have escalated privileges." -ForegroundColor DarkRed
                }
            }
        }
    }
}

# Execute the triage sweep
Invoke-TargetTriage -SuspendAnomalies