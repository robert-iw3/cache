<#
.SYNOPSIS
    DFIR Attack Simulator - End-to-End Pipeline Validation

.DESCRIPTION
    Safely generates high-fidelity telemetry to validate the DFIR collector,
    anomaly hunter, memory scanner, and SIEM queries.

.NOTES
    ⚠️ IMPORTANT DISCLAIMER:

    Run this on a dedicated Test VM only.
    While the script is non-destructive (it does not download real malware),
    it will clear your Application Event Log to simulate defense evasion,
    and it will light up any local AV/EDR you have running.

    The script simulates the following TTPs:
    1. C2 Beaconing with low variance (CV Trigger)
    2. Privilege Escalation / RMM Abuse (Event ID 7045)
    3. AMSI Bypass / Malicious Script Block (Event ID 4104)
    4. Living off the Land / Process Tree Anomalies (LotL)
    5. Memory Injection with Cobalt Strike signature
    6. Log Tampering / Footprint Erasure (Event ID 104)

    Author: RW
#>

$ErrorActionPreference = "SilentlyContinue"

Write-Host "=============================================" -ForegroundColor Red
Write-Host " INITIATING THREAT SIMULATION " -ForegroundColor Red
Write-Host "=============================================" -ForegroundColor Red

# Require Admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Warning "Administrator privileges required to simulate advanced TTPs."; exit }

# ---------------------------------------------------------
# 1. C2 BEACONING SIMULATION (Low Variance / CV Trigger)
# ---------------------------------------------------------
Write-Host "[*] Simulating Programmatic C2 Beaconing (Target: 8.8.8.8:443)..." -ForegroundColor Yellow
# Loop 12 times with an exact 2-second sleep.
# Standard Deviation = 0, meaning the CV = 0.0 (Flags < 0.35 in SIEM/Anomaly Hunt)
for ($i = 1; $i -le 12; $i++) {
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $tcp.Connect("8.8.8.8", 443)
        $tcp.Close()
    } catch {}
    Start-Sleep -Seconds 2
}

# ---------------------------------------------------------
# 2. PRIVILEGE ESCALATION / RMM ABUSE (Event ID 7045)
# ---------------------------------------------------------
Write-Host "[*] Simulating Malicious Service Installation (PSEXESVC)..." -ForegroundColor Yellow
# Creates a benign service with a highly suspicious name to trigger the SIEM 7045 query
$ServiceName = "PSEXESVC"
$BinPath = "C:\Windows\System32\ping.exe -n 1 127.0.0.1"
New-Service -Name $ServiceName -BinaryPathName $BinPath -DisplayName "Sysinternals PsExec" -StartupType Manual | Out-Null
Start-Sleep -Seconds 2
sc.exe delete $ServiceName | Out-Null

# ---------------------------------------------------------
# 3. DEFENSE EVASION / AMSI BYPASS (Event ID 4104)
# ---------------------------------------------------------
Write-Host "[*] Simulating Malicious PowerShell Script Block..." -ForegroundColor Yellow
# Evaluating these strings forces ETW to log them into Microsoft-Windows-PowerShell/Operational
$SuspiciousCode = @"
    `$Patch = 'AmsiScanBuffer'
    `$Alloc = 'VirtualAlloc'
    `$Dump  = 'MiniDumpWriteDump'
    Write-Output 'Simulated AMSI Patching'
"@
[scriptblock]::Create($SuspiciousCode).Invoke() | Out-Null

# ---------------------------------------------------------
# 4. LIVING OFF THE LAND / PROCESS TREE ANOMALIES (LotL)
# ---------------------------------------------------------
Write-Host "[*] Simulating Suspicious Execution (Encoded Command)..." -ForegroundColor Yellow
# Leaves a running process with a high-entropy/suspicious command line for ProcessTree.json
$LotlArgs = "-NoProfile -WindowStyle Hidden -EncodedCommand IAAgAFcAcgBpAHQAZQAtAEgAbwBzAHQAIAAnAFMAaQBtAHUAbABhAHQAaQBvAG4AJwA7ACAAUwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBTAGUAYwBvAG4AZABzACAAMwAwADAA"
Start-Process -FilePath "powershell.exe" -ArgumentList $LotlArgs -WindowStyle Hidden

# ---------------------------------------------------------
# 5. MEMORY INJECTION (C2 Artifact in Notepad)
# ---------------------------------------------------------
Write-Host "[*] Simulating C2 Memory Injection (Cobalt Strike Named Pipe)..." -ForegroundColor Yellow
$Notepad = Start-Process -FilePath "notepad.exe" -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2

# Using P/Invoke to allocate RW memory in Notepad and write a Cobalt Strike signature
$Win32API = @"
using System;
using System.Runtime.InteropServices;
public class Injector {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
}
"@
Add-Type -TypeDefinition $Win32API -Language CSharp

$PROCESS_ALL_ACCESS = 0x001F0FFF
$MEM_COMMIT = 0x1000
$PAGE_READWRITE = 0x04

$hProcess = [Injector]::OpenProcess($PROCESS_ALL_ACCESS, $false, $Notepad.Id)
$AllocAddr = [Injector]::VirtualAllocEx($hProcess, [IntPtr]::Zero, 1024, $MEM_COMMIT, $PAGE_READWRITE)

# Cobalt Strike standard SMB named pipe signature
$SigString = "\pipe\msagent_12"
$SigBytes = [System.Text.Encoding]::ASCII.GetBytes($SigString)
$BytesWritten = [UIntPtr]::Zero

[Injector]::WriteProcessMemory($hProcess, $AllocAddr, $SigBytes, $SigBytes.Length, [ref]$BytesWritten) | Out-Null
Write-Host "    -> Injected '\pipe\msagent_12' into notepad.exe (PID: $($Notepad.Id))"

# ---------------------------------------------------------
# 6. LOG TAMPERING (Event ID 104)
# ---------------------------------------------------------
Write-Host "[*] Simulating Footprint Erasure (Clearing Application Log)..." -ForegroundColor Yellow
# Clearing the Application log safely generates Event ID 104 in the System Log
wevtutil cl Application

Write-Host "`n=============================================" -ForegroundColor Green
Write-Host " SIMULATION COMPLETE " -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green
Write-Host "The test VM is now primed. Run the DFIR Orchestrator to collect and validate."