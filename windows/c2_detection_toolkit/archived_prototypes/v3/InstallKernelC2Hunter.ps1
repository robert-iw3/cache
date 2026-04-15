<#
.SYNOPSIS
    v3.0 Kernel installer — ETW + pktmon
#>
#Requires -RunAsAdministrator

Write-Host "[v3.0] Setting up kernel telemetry..." -ForegroundColor Cyan

# Purge any zombie traces
logman stop "C2KernelTrace" -ets 2>&1 | Out-Null
logman delete "C2KernelTrace" -ets 2>&1 | Out-Null
pktmon stop 2>&1 | Out-Null
pktmon filter remove 2>&1 | Out-Null

# Ensure directory exists
if (-not (Test-Path "C:\Temp")) {
    New-Item -Path "C:\Temp" -ItemType Directory -Force | Out-Null
    Write-Host "      [+] Created C:\Temp" -ForegroundColor Green
}

$EtwPath = "C:\Temp\C2Kernel.etl"

# 1. Create logman trace
logman create trace "C2KernelTrace" -o "$EtwPath" -max 200 -f bincirc -ft 1 -ets 2>&1 | Out-Null

# 2. Add providers
logman update trace "C2KernelTrace" -p Microsoft-Windows-TCPIP -ets 2>&1 | Out-Null
logman update trace "C2KernelTrace" -p Microsoft-Windows-DNS-Client -ets 2>&1 | Out-Null
logman update trace "C2KernelTrace" -p Microsoft-Windows-Kernel-Network -ets 2>&1 | Out-Null
logman update trace "C2KernelTrace" -p Microsoft-Windows-Kernel-Process -ets 2>&1 | Out-Null
logman update trace "C2KernelTrace" -p Microsoft-Windows-Kernel-File -ets 2>&1 | Out-Null
logman update trace "C2KernelTrace" -p Microsoft-Windows-Kernel-Registry -ets 2>&1 | Out-Null

# 3. Start logman
logman start "C2KernelTrace" -ets 2>&1 | Out-Null
Write-Host "      [+] Logman ETW session started" -ForegroundColor Green

# 4. PktMon
pktmon filter add -d Outbound 2>&1 | Out-Null
pktmon start --etw 2>&1 | Out-Null
Write-Host "      [+] PktMon counters active in background" -ForegroundColor Green

Write-Host "`n[v3.0] Kernel monitoring is now LIVE!" -ForegroundColor Green
Write-Host "      ETL file: $EtwPath" -ForegroundColor Cyan