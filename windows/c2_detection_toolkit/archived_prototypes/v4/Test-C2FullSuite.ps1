<#
.SYNOPSIS
    AV-Safe Network Validation Suite for Kernel C2 Beacon Hunter
.DESCRIPTION
    This script simulates various C2 beaconing patterns to validate the detection capabilities of the Kernel
    C2 Beacon Hunter v4. It includes tests for high-entropy DNS queries, rigid beaconing, jittered beaconing,
    and fast-flux/multi-IP scenarios. The script is designed to be safe for use in environments with perimeter
    defenses, as it sends legitimate HTTP requests to well-known domains.
.NOTES
    @RW
#>
#Requires -RunAsAdministrator

Write-Host "[v4.0] Starting AV-Safe Feature Validation Suite..." -ForegroundColor Cyan

function Send-RawBeacon {
    param([string]$TargetHost, [int]$Port)
    try {
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $connectTask = $tcp.ConnectAsync($TargetHost, $Port)

        if ($connectTask.Wait(2000)) {
            if ($tcp.Connected) {
                $stream = $tcp.GetStream()
                # Sending a legitimate HTTP payload prevents perimeter firewalls
                # from rate-limiting the test loop as a TCP SYN Flood.
                $payload = "GET / HTTP/1.1`r`nHost: $TargetHost`r`nConnection: close`r`nUser-Agent: C2-Validation-Agent`r`n`r`n"
                $bytes = [System.Text.Encoding]::ASCII.GetBytes($payload)
                $stream.Write($bytes, 0, $bytes.Length)
                $stream.Close()
            }
        }
        $tcp.Close()
    } catch {}
}

# 1. DNS: DGA + high-entropy domain
Write-Host "`n[1] DNSQuery: Simulating APT DGA Domain (x92mz84p7q.com)..." -NoNewline
try { [System.Net.Dns]::GetHostEntry("x92mz84p7q.com") | Out-Null } catch {}
Write-Host " Done." -ForegroundColor Green

# 2. Rigid Beacon (Simulating Script Kiddie)
Write-Host "[2] Rigid Beacon: 20 connections to example.com:80 (0% Jitter)..."
for ($i = 1; $i -le 20; $i++) {
    Send-RawBeacon -TargetHost "example.com" -Port 80
    Start-Sleep -Milliseconds 600
    Write-Host "." -NoNewline -ForegroundColor DarkGray
}
Write-Host " Done." -ForegroundColor Green

# 3. Jittered Beacon (Simulating APT)
Write-Host "`n[3] Jittered Beacon: 20 connections to httpbin.org:80 (30% Jitter)..."
for ($i = 1; $i -le 20; $i++) {
    Send-RawBeacon -TargetHost "httpbin.org" -Port 80
    Start-Sleep -Milliseconds (600 + (Get-Random -Minimum -200 -Maximum 250))
    Write-Host "." -NoNewline -ForegroundColor DarkGray
}
Write-Host " Done." -ForegroundColor Green

# 4. Fast-Flux / Multi-IP (Simulating Botnet/APT Infrastructure)
Write-Host "`n[4] Fast-Flux: 20 rotating IP connections over HTTP (Port 80)..."
$fluxHosts = @("example.com", "httpbin.org", "neverssl.com", "ident.me", "ifconfig.me")
for ($i = 0; $i -lt 20; $i++) {
    $targetHost = $fluxHosts[$i % $fluxHosts.Count]
    Send-RawBeacon -TargetHost $targetHost -Port 80
    Start-Sleep -Milliseconds 600
    Write-Host "." -NoNewline -ForegroundColor DarkGray
}
Write-Host " Done." -ForegroundColor Green

Write-Host "`n[v4.0] Validation Complete!" -ForegroundColor Cyan
Write-Host "    Monitor your Hunter console in ~30 seconds for the simultaneous ML detections." -ForegroundColor Yellow