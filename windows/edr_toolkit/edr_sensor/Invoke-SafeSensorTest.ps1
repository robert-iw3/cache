<#
.SYNOPSIS
    Deep Sensor v2.1 - AV-Safe Telemetry Generator
.DESCRIPTION
    Generates benign system behaviors designed to trigger the native Rust ML engine
    and Sigma Gatekeeper without triggering static AV/EDR blocklists (Defender/Trend Micro).
#>

Write-Host "`n[*] Initiating Deep Sensor v2.1 AV-Safe Telemetry Generation...`n" -ForegroundColor Cyan

# -------------------------------------------------------------------------
# TEST 1: Sigma String Matching (Built-in TI)
# The ETW ProcessStart provider will catch the command line argument, triggering
# the Aho-Corasick string matcher, but AV will ignore the benign 'echo' execution.
# -------------------------------------------------------------------------
Write-Host "    [1] Triggering Built-In Threat Intel (procdump -ma lsass)..." -ForegroundColor Gray
Start-Process cmd.exe -ArgumentList '/c echo "procdump -ma lsass"' -WindowStyle Hidden
Start-Sleep -Milliseconds 500

# -------------------------------------------------------------------------
# TEST 2: High-Entropy I/O Burst (Ransomware Simulator)
# Creates 60 files in < 1 second using Base64/Guid names to spike the
# Shannon Entropy calculator in lib.rs above the 5.2 threshold.
# -------------------------------------------------------------------------
Write-Host "    [2] Triggering High-Entropy File I/O Burst (60 ops/sec)..." -ForegroundColor Gray
$testDir = Join-Path $env:TEMP "DeepSensor_BurstTest"
if (-not (Test-Path $testDir)) { New-Item -ItemType Directory -Path $testDir | Out-Null }

for ($i = 0; $i -lt 65; $i++) {
    # Generate high entropy file names
    $b64Name = [Convert]::ToBase64String([Guid]::NewGuid().ToByteArray()).Substring(0, 15) -replace '[/\+=]', ''
    $path = Join-Path $testDir "$b64Name.txt"
    [System.IO.File]::WriteAllText($path, "AV-Safe Deep Sensor Test Data")
}
Start-Sleep -Seconds 2
Remove-Item -Path $testDir -Recurse -Force -ErrorAction SilentlyContinue

# -------------------------------------------------------------------------
# TEST 3: Suspicious Named Pipe Creation
# Opens a named pipe containing the 'mojo.' substring which is hardcoded
# in the C# gateway as a suspicious IPC pattern.
# -------------------------------------------------------------------------
Write-Host "    [3] Triggering Suspicious Named Pipe Creation (mojo.1337.test)..." -ForegroundColor Gray
try {
    $pipe = New-Object System.IO.Pipes.NamedPipeServerStream("mojo.1337.test", [System.IO.Pipes.PipeDirection]::InOut, 1)
    Start-Sleep -Milliseconds 500
    $pipe.Dispose()
} catch {}

# -------------------------------------------------------------------------
# TEST 4: Anomalous Execution Lineage
# Spawns a nested execution chain to validate the newly enriched
# ParentProcess tracking across the FFI boundary.
# -------------------------------------------------------------------------
Write-Host "    [4] Triggering Anomalous Lineage (powershell -> cmd -> certutil)..." -ForegroundColor Gray
$nestedCmd = 'Start-Process cmd.exe -ArgumentList ''/c certutil.exe -?'' -WindowStyle Hidden'
Start-Process powershell.exe -ArgumentList "-NoProfile -NonInteractive -Command `"$nestedCmd`"" -WindowStyle Hidden

Write-Host "`n[+] Telemetry dispatched successfully." -ForegroundColor Green
Write-Host "[*] Monitor the Deep Sensor HUD or review DeepSensor_Events.jsonl for results." -ForegroundColor DarkGray