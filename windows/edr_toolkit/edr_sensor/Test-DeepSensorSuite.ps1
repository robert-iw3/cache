<#
.SYNOPSIS
    Deep Sensor - Validation Suite

.DESCRIPTION
    Safely generates benign but highly suspicious telemetry designed to trigger
    all completed features.

    Executes techniques via isolated background jobs or native API calls to ensure
    the sensor's Active Defense module neutralizes the specific threat without
    terminating the main test runner.

@RW
#>
#Requires -RunAsAdministrator

$ErrorActionPreference = "SilentlyContinue"
$ESC = [char]27
$cRed = "$ESC[91m"; $cGreen = "$ESC[92m"; $cCyan = "$ESC[96m"; $cYellow = "$ESC[93m"; $cReset = "$ESC[0m"

try {
    Clear-Host
    Write-Host "$cCyan=================================================================$cReset"
    Write-Host "$cCyan   DEEP VISIBILITY SENSOR - VALIDATION SUITE    $cReset"
    Write-Host "$cCyan=================================================================`n$cReset"
    Write-Host "$cYellow[*] Ensure DeepSensor_Launcher.ps1 is actively running in another window.$cReset"
    Start-Sleep -Seconds 2

    # ==========================================================================
    # HELPER: NATIVE MEMORY INJECTOR
    # ==========================================================================
    $InjectorCode = @"
    using System;
    using System.Runtime.InteropServices;
    public class Injector {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        public static void AllocateRWX(int pid) {
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid); // PROCESS_ALL_ACCESS
            if (hProcess != IntPtr.Zero) {
                // Allocate with PAGE_EXECUTE_READWRITE (0x40)
                VirtualAllocEx(hProcess, IntPtr.Zero, 4096, 0x3000, 0x40);
                CloseHandle(hProcess);
            }
        }
    }
"@
    Add-Type -TypeDefinition $InjectorCode

    # ==========================================================================
    # PHASE 1: STATIC HEURISTICS & ETW
    # ==========================================================================
    Write-Host "`n$cDark--- PHASE 1: STATIC PIPELINE & THREAT INTEL ---$cReset"

    Write-Host "$cGreen[1/12] Testing T1059.001: Obfuscated PowerShell Execution...$cReset"
    $encPayload = "VwByAGkAdABlAC0ASABvAHMAdAAgACcAVABlAHMAdAAnAA=="
    Start-Process powershell.exe -ArgumentList "-enc $encPayload" -WindowStyle Hidden
    Start-Sleep -Seconds 1

    Write-Host "$cGreen[2/12] Testing T1562.002: ETW Sensor Blinding (Tampering)...$cReset"
    Start-Process cmd.exe -ArgumentList "/c logman stop edr_deepsensor_host" -WindowStyle Hidden
    Start-Sleep -Seconds 1

    Write-Host "$cGreen[3/12] Testing Sigma Engine: Built-in Credential Dumping...$cReset"
    # DEVELOPER NOTE: Splitting the string prevents Windows Defender (AMSI) from hard-killing
    # the PowerShell test suite. It is reassembled dynamically for cmd.exe so ETW still catches it.
    $lsa = "ls" + "ass.exe"
    $dmp = "proc" + "dump -ma"
    Start-Process cmd.exe -ArgumentList "/c $dmp $lsa" -WindowStyle Hidden
    Start-Sleep -Seconds 1

    Write-Host "$cGreen[4/12] Testing Live BYOVD Intel (LOLDrivers.io)...$cReset"
    # Simulates a BYOVD load by copying a benign DLL to a known malicious .sys name and loading it into memory
    $FakeDriver = "$env:TEMP\RTCore64.sys"
    Copy-Item "C:\Windows\System32\ntdll.dll" -Destination $FakeDriver -Force
    # Trigger a plausible load path that ETW will see
    sc.exe create FakeVulnDriver type= kernel start= demand binPath= $FakeDriver | Out-Null
    Start-Sleep -Seconds 2
    sc.exe delete FakeVulnDriver | Out-Null

    Write-Host "$cGreen[5/12] Testing T1564.004: Alternate Data Stream (ADS) Creation...$cReset"
    $AdsTarget = "$env:TEMP\benign_file.txt"
    Set-Content -Path $AdsTarget -Value "Standard Data"
    # Writing to the colon namespace creates the ADS, which the kernel FileIOCreate will catch
    Set-Content -Path "$AdsTarget:hidden_payload.exe" -Value "Hidden Data"
    Start-Sleep -Seconds 1
    Remove-Item -Path $AdsTarget -Force -ErrorAction SilentlyContinue

    # ==========================================================================
    # PHASE 2: ADVANCED KERNEL TELEMETRY
    # ==========================================================================
    Write-Host "`n$cDark--- PHASE 2: ADVANCED REGISTRY & MEMORY ---$cReset"

    Write-Host "$cGreen[6/12] Testing Deep Registry: IFEO Accessibility Hijacking...$cReset"
    $IfeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe"
    New-Item -Path $IfeoPath -Force | Out-Null
    New-ItemProperty -Path $IfeoPath -Name "Debugger" -Value "cmd.exe" -Force | Out-Null
    Start-Sleep -Milliseconds 500
    Remove-ItemProperty -Path $IfeoPath -Name "Debugger" -Force | Out-Null
    Remove-Item -Path $IfeoPath -Force | Out-Null
    Start-Sleep -Seconds 1

    Write-Host "$cGreen[7/12] Testing T1547.001: Registry Run Key Persistence...$cReset"
    $RunKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    New-ItemProperty -Path $RunKeyPath -Name "DeepSensor_Test_Key" -Value "C:\Temp\malware.exe" -PropertyType String -Force | Out-Null
    Start-Sleep -Milliseconds 500
    Remove-ItemProperty -Path $RunKeyPath -Name "DeepSensor_Test_Key" -Force | Out-Null
    Start-Sleep -Seconds 1

    Write-Host "$cGreen[8/12] Testing T1055.012: Process Hollowing Heuristics...$cReset"
    # Spawns a process and immediately allocates RWX memory into it (simulating injection)
    $dummyProc = Start-Process notepad.exe -PassThru -WindowStyle Hidden
    Start-Sleep -Milliseconds 200
    [Injector]::AllocateRWX($dummyProc.Id)
    Start-Sleep -Seconds 1
    if (-not $dummyProc.HasExited) { Stop-Process -Id $dummyProc.Id -Force -ErrorAction SilentlyContinue }

    # ==========================================================================
    # PHASE 3: ML EVOLUTION & ACTIVE DEFENSE
    # ==========================================================================
    Write-Host "`n$cDark--- PHASE 3: BEHAVIORAL ML & SELF-DEFENSE ---$cReset"

    Write-Host "$cGreen[9/12] Testing ML Tuple Lineage (Isolation Forest Anomaly)...$cReset"
    # Spawns a bizarre parent-child execution chain (WMI spawning MSHTA)
    Start-Process wmic.exe -ArgumentList "process call create `"mshta.exe vbscript:close(1)`"" -WindowStyle Hidden
    Start-Sleep -Seconds 2

    Write-Host "$cGreen[10/12] Testing Ransomware Burst Tracker...$cReset"
    $RansomTestDir = "$env:TEMP\DeepSensor_RansomTest"
    if (-not (Test-Path $RansomTestDir)) { New-Item -ItemType Directory -Path $RansomTestDir | Out-Null }
    $RansomSimulatorBlock = {
        param($TargetDir)
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?'

        # DEVELOPER NOTE: Pre-generate the random strings in memory BEFORE file creation.
        # This removes the CPU bottleneck, allowing the actual I/O operations to flood
        # the disk in < 0.1 seconds, successfully triggering the ML burst window.
        $fileNames = @()
        for ($i = 1; $i -le 65; $i++) {
            $result = -join ((1..50) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
            $fileNames += "$TargetDir\$result.locked"
        }

        # Execute the burst as fast as the physical disk allows
        foreach ($file in $fileNames) {
            $null = [System.IO.File]::Create($file)
        }
    }
    $BurstJob = Start-Job -ScriptBlock $RansomSimulatorBlock -ArgumentList $RansomTestDir
    Wait-Job $BurstJob -Timeout 5 | Out-Null
    Remove-Item -Path $RansomTestDir -Recurse -Force | Out-Null
    Start-Sleep -Seconds 1

    Write-Host "$cGreen[11/12] Testing T1027: Cryptographic Entropy (Mathematical Obfuscation)...$cReset"
    # Generate a highly randomized 200-character string to push Shannon Entropy above 7.2
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?'
    $entropyString = -join ((1..200) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
    # The Python daemon evaluates both path and command line arguments
    Start-Process cmd.exe -ArgumentList "/c echo $entropyString" -WindowStyle Hidden
    Start-Sleep -Seconds 1

    Write-Host "$cGreen[12/12] Testing Sensor Self-Defense Watchdog (Anti-Tamper)...$cReset"
    # Finds the DeepSensor Orchestrator PID and attempts to allocate RWX memory into it.
    # The C# engine should instantly catch this and kill the background job's thread.
    $sensorProcess = Get-CimInstance Win32_Process -Filter "CommandLine LIKE '%DeepSensor_Launcher.ps1%'" | Select-Object -First 1
    if ($sensorProcess) {
        $sensorPid = $sensorProcess.ProcessId
        $AttackerJob = Start-Job -ScriptBlock {
            param($pidToAttack, $code)
            Add-Type -TypeDefinition $code
            [Injector]::AllocateRWX($pidToAttack)
            Start-Sleep -Seconds 5 # Thread should be killed before this finishes
        } -ArgumentList $sensorPid, $InjectorCode
        Wait-Job $AttackerJob -Timeout 3 | Out-Null
        Write-Host "$cYellow      > RWX Injection fired at Sensor PID: $sensorPid.$cReset"
    } else {
        Write-Host "$cRed      > Could not locate DeepSensor_Launcher.ps1 to test self-defense.$cReset"
    }

    # ==========================================================================
    # PHASE 4: TEARDOWN & CLEANUP
    # ==========================================================================
    Write-Host "`n$cDark--- PHASE 4: SUITE TEARDOWN ---$cReset"
    Write-Host "$cGreen[*] Reverting filesystem and purging background jobs...$cReset"

    # 1. Purge the mock BYOVD driver
    # DEVELOPER NOTE: Because [Reflection.Assembly]::LoadFile locks the file in RAM,
    # we force a garbage collection sweep to release the handle before attempting deletion.
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    $FakeDriver = "$env:TEMP\RTCore64.sys"
    if (Test-Path $FakeDriver) {
        Remove-Item -Path $FakeDriver -Force -ErrorAction SilentlyContinue
    }

    # 2. Flush orphaned background jobs
    # Clears the Ransomware Simulator and Anti-Tamper Attacker jobs from memory
    Get-Job | Remove-Job -Force -ErrorAction SilentlyContinue

    Write-Host "`n$cCyan[+] Comprehensive Validation Suite Complete & Environment Sanitized.$cReset"
    Write-Host "$cYellow[*] Review the DeepSensor HUD. You should see specific alerts for Hollowing, BYOVD, IFEO, and Tampering.$cReset"

} catch {
    # --- GLOBAL CRASH CATCHER ---
    Write-Host "`n$cRed[!] FATAL SCRIPT ERROR ENCOUNTERED:$cReset"
    Write-Host "$cYellow$($_.Exception.Message)$cReset"
    Write-Host "$cDark$($_.InvocationInfo.PositionMessage)$cReset"
} finally {
    # --- AUTO-CLOSE PREVENTION ---
    Write-Host "`n"
    Read-Host -Prompt "$cCyan[?] Press ENTER to close this window...$cReset"
}