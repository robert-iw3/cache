<#
.SYNOPSIS
    Targeted Network Containment Script (Safe-Mode)
.DESCRIPTION
    Dynamically isolates identified malicious infrastructure based on sensor telemetry.
    Implements strict whitelisting to ensure core network functionality (DNS, local routing)
    remains unaffected during the containment phase.
#>
#Requires -RunAsAdministrator

function Invoke-NetworkContainment {
    [CmdletBinding()]
    param (
        [string]$MonitorLog = "C:\ProgramData\C2Sensor\Logs\OutboundNetwork_Monitor.log",
        [string[]]$TargetProcesses = @("chrome", "Code", "svchost", "pwsh"),
        [switch]$ApplyRules
    )

    Write-Host "[*] Initializing Network Containment Protocol..." -ForegroundColor Cyan

    # =====================================================================
    # 1. DEFINE STRICT SAFETY WHITELIST 
    # =====================================================================
    # Ensure core routing and trusted DNS resolution is never suspended
    $SafeList = @(
        "1.1.1.1", "1.0.0.1",       # Cloudflare DNS
        "8.8.8.8", "8.8.4.4",       # Google DNS
        "127.0.0.1", "::1",         # Local Loopback
        "255.255.255.255"           # Broadcast
    )
    # Regex to protect internal LAN routing (10.x, 172.16.x, 192.168.x)
    $SafeRegex = "^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\." 

    # =====================================================================
    # 2. PARSE TELEMETRY FOR FAST-FLUX NODES
    # =====================================================================
    $IsolateList = [System.Collections.Generic.HashSet[string]]::new()

    if (Test-Path $MonitorLog) {
        $LogData = Get-Content -Path $MonitorLog
        
        foreach ($Line in $LogData) {
            foreach ($Proc in $TargetProcesses) {
                # Match the compromised processes and extract the exact Destination IP
                if ($Line -match "Process Name: $Proc," -and $Line -match "Destination IP: ([0-9\.]+)") {
                    $ExtractedIp = $matches[1]
                    [void]$IsolateList.Add($ExtractedIp)
                }
            }
        }
    } else {
        Write-Host "[-] Telemetry log not found at $MonitorLog." -ForegroundColor Red
        return
    }

    # =====================================================================
    # 3. APPLY SANITIZATION AND CONTAINMENT
    # =====================================================================
    $BlockedCount = 0

    foreach ($TargetIp in $IsolateList) {
        # Critical Check: Bypass isolation if the IP is trusted or internal
        if ($SafeList -contains $TargetIp -or $TargetIp -match $SafeRegex) {
            continue
        }

        $RuleName = "C2Sensor_Containment_$TargetIp"
        
        if (-not $ApplyRules) {
            Write-Host "[SIMULATION] Would isolate outbound traffic to node: $TargetIp" -ForegroundColor DarkGray
        } else {
            if (-not (Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule -DisplayName $RuleName -Direction Outbound -Action Block -RemoteAddress $TargetIp | Out-Null
                Write-Host "[+] Active Containment: Outbound traffic isolated for node $TargetIp" -ForegroundColor Yellow
                $BlockedCount++
            }
        }
    }

    # =====================================================================
    # 4. COMPLETION STATUS
    # =====================================================================
    if (-not $ApplyRules) {
        Write-Host "`n[*] Simulation complete. To commit changes, execute with the -ApplyRules switch." -ForegroundColor Cyan
    } else {
        Write-Host "`n[*] Containment protocol complete. $BlockedCount infrastructure nodes successfully isolated." -ForegroundColor Green
    }
}

# Execute in Simulation Mode first to verify safety
Invoke-NetworkContainment