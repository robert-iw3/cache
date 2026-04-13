<#
.SYNOPSIS
    AV-Safe Network Validation Suite for Kernel C2 Beacon Hunter v5
#>
#Requires -RunAsAdministrator

Write-Host "=============================================================" -ForegroundColor Cyan
Write-Host "   C2 HUNTER V5: FULL PIPELINE VALIDATION SUITE" -ForegroundColor Cyan
Write-Host "=============================================================" -ForegroundColor Cyan

function Send-RawBeacon {
    param([string]$TargetHost, [int]$Port)
    try {
        $tcp = [System.Net.Sockets.TcpClient]::new()
        # Synchronous Connect keeps the network event on a single, trackable TID!
        $tcp.Connect($TargetHost, $Port)

        if ($tcp.Connected) {
            $stream = $tcp.GetStream()
            $payload = "GET / HTTP/1.1`r`nHost: $TargetHost`r`nConnection: close`r`nUser-Agent: C2-Validation-Agent`r`n`r`n"
            $bytes = [System.Text.Encoding]::ASCII.GetBytes($payload)
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Close()
        }
        $tcp.Close()
    } catch {}
}

# -------------------------------------------------------------------------
# TEST 1: SENSOR BLINDING & RECOVERY (The Deadman's Switch)
# -------------------------------------------------------------------------
Write-Host "`n[TEST 1] Initiating ETW Sensor Blinding Simulation..." -ForegroundColor Yellow
Write-Host "[*] Disconnecting the DNS-Client Provider from the active session to starve the Canary..." -ForegroundColor DarkGray

# Use native logman to rip the provider out of the running C# session
logman update trace C2RealTimeSession --p Microsoft-Windows-DNS-Client -ets | Out-Null

Write-Host "[*] Sensor Blinded. The Master Daemon will realize it has been compromised in 180 seconds." -ForegroundColor Red
Write-Host "[*] Waiting for the Deadman's Switch to trigger..." -ForegroundColor DarkGray

# Progress bar for 185 seconds to allow the Watchdog math to trigger
for ($i = 185; $i -gt 0; $i--) {
    Write-Progress -Activity "Simulating BYOVD Sensor Blinding" -Status "Waiting for Watchdog Alarm... ${i}s remaining" -PercentComplete (100 - ($i / 185 * 100))
    Start-Sleep -Seconds 1
}
Write-Progress -Activity "Simulating BYOVD Sensor Blinding" -Completed

Write-Host "[*] Look at the Daemon HUD! It should now show [ ANTI-TAMPER : BAD ] and a CRITICAL ALARM." -ForegroundColor Yellow
Start-Sleep -Seconds 3

Write-Host "`n[*] Restoring the ETW Sensor connection..." -ForegroundColor Green
logman update trace C2RealTimeSession -p Microsoft-Windows-DNS-Client 0xffffffffffffffff 0xff -ets | Out-Null

Write-Host "[*] Sensor Restored. Waiting 60 seconds for the next Canary ping to trigger Recovery..." -ForegroundColor DarkGray
for ($i = 65; $i -gt 0; $i--) {
    Write-Progress -Activity "Sensor Recovery" -Status "Waiting for Canary Ping... ${i}s remaining" -PercentComplete (100 - ($i / 65 * 100))
    Start-Sleep -Seconds 1
}
Write-Progress -Activity "Sensor Recovery" -Completed
Write-Host "[+] Recovery Complete. The Daemon should now show [ ANTI-TAMPER : Good ] with a Recovery log." -ForegroundColor Green

# -------------------------------------------------------------------------
# TEST 2: JITTERED APT BEACON (Post-Recovery ML Validation)
# -------------------------------------------------------------------------
Write-Host "`n[TEST 2] Validating ML Pipeline Post-Recovery (Jittered APT Beacon)..." -ForegroundColor Yellow
Write-Host "[*] Sending 20 synchronous connections to httpbin.org:80 (30% Jitter)..." -ForegroundColor DarkGray

for ($i = 1; $i -le 20; $i++) {
    Send-RawBeacon -TargetHost "httpbin.org" -Port 80
    # 800ms base sleep with a -200 to +250ms jitter
    Start-Sleep -Milliseconds (800 + (Get-Random -Minimum -200 -Maximum 250))
    Write-Host "." -NoNewline -ForegroundColor Cyan
}
Write-Host " Done." -ForegroundColor Green
Write-Host "[*] Wait 15-30 seconds. The Python Daemon will evaluate the Thread IDs and fire the ML Alert." -ForegroundColor DarkGray

# -------------------------------------------------------------------------
# TEST 3: FAST-FLUX BEACONING
# -------------------------------------------------------------------------
Write-Host "`n[TEST 3] Validating Fast-Flux / Multi-IP Infrastructure Routing..." -ForegroundColor Yellow
$fluxHosts = @("example.com", "httpbin.org", "neverssl.com", "ident.me", "ifconfig.me")
for ($i = 1; $i -le 20; $i++) {
    $target = $fluxHosts | Get-Random
    Send-RawBeacon -TargetHost $target -Port 80
    Start-Sleep -Milliseconds (800 + (Get-Random -Minimum -200 -Maximum 250))
    Write-Host "." -NoNewline -ForegroundColor Cyan
}
Write-Host " Done." -ForegroundColor Green

Write-Host "`n[SUCCESS] V5 Validation Suite Completed. Monitor your Daemon HUD for the final ML detections!" -ForegroundColor Green