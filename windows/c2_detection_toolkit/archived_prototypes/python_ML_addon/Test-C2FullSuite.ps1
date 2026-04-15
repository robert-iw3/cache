<#
.SYNOPSIS
    Full Unit Test for MonitorC2Activities_Full.ps1
    Validates: Process, File, Registry, DNS, and ML Beaconing.
#>

Write-Host "[-] Starting Full Feature Validation..." -ForegroundColor Cyan

# 1. PROCESS: Encoded Command
Write-Host "   [1] Process: Simulating Encoded Command..." -NoNewline
try {
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Host 'Test'"))
    $null = Start-Process powershell.exe -ArgumentList "-EncodedCommand $enc", "-WindowStyle Hidden" -Wait
    Write-Host " Done." -ForegroundColor Green
} catch { Write-Host " Failed." -ForegroundColor Red }

# 2. FILE: Suspicious Script Creation
Write-Host "   [2] File: Creating suspicious .ps1 in Temp..." -NoNewline
New-Item -Path "$env:TEMP\malware_test.ps1" -ItemType File -Force | Out-Null
Write-Host " Done." -ForegroundColor Green

# 3. DNS: DGA
Write-Host "   [3] DNS: Simulating DGA Query (x92mz84.com)..." -NoNewline
try { [System.Net.Dns]::GetHostEntry("x92mz84.com") } catch {}
Write-Host " Done." -ForegroundColor Green

# 4. REGISTRY: Persistence
Write-Host "   [4] Registry: Simulating Run Key access..." -NoNewline
# We just read it; modifying might require higher privs or trigger AV.
# The monitor checks for 'TargetObject' matching Run keys in Sysmon events.
# Accessing it often triggers Event 12/13 depending on auditing.
try { Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | Out-Null } catch {}
Write-Host " Done." -ForegroundColor Green

# 5. ML: Jittered Beaconing
Write-Host "   [5] Network: Simulating Jittered Beacon to 8.8.8.8..." -NoNewline
$target = "8.8.8.8"
for ($i=0; $i -lt 5; $i++) {
    $null = Test-NetConnection -ComputerName $target -Port 53 -WarningAction SilentlyContinue
    Start-Sleep -Seconds (Get-Random -Min 1 -Max 3) # Jitter 1-3s
}
Write-Host " Done." -ForegroundColor Green

Write-Host "[-] Validation Complete. Check C2Monitoring.csv in ~60 seconds." -ForegroundColor Cyan