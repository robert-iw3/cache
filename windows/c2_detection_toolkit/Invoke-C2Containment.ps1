<#
.SYNOPSIS
    Automated C2 Containment and Remediation Engine
#>
#Requires -RunAsAdministrator

param (
    [string]$CorrelationReport = "C:\ProgramData\C2Sensor\Data\Correlated_C2_Vectors.txt",
    [string]$ContainmentLog = "C:\ProgramData\C2Sensor\Logs\C2_Containment_Actions.log",
    [string]$TriageScriptPath = "Invoke-C2ForensicTriage.ps1",
    [string]$EvidenceFolder = "C:\ProgramData\C2Sensor\Evidence\DFIR_Collect",
    [int]$RiskThreshold = 100,
    [switch]$ArmedMode,
    [switch]$Orchestrated
)

$ScriptDir = if ($PSCommandPath) { Split-Path $PSCommandPath -Parent } else { $PWD.Path }

if (-not [System.IO.Path]::IsPathRooted($TriageScriptPath)) {
    $TriageScriptPath = Join-Path $ScriptDir $TriageScriptPath
}

# =================================================================
# DUAL-MODE UI ENGINE
# =================================================================
$ESC = [char]27
$cRed = "$ESC[38;2;255;70;85m"; $cCyan = "$ESC[38;2;0;200;255m"; $cGreen = "$ESC[38;2;10;210;130m"; $cDark = "$ESC[38;2;100;100;100m"; $cYellow = "$ESC[38;2;255;180;50m"; $cReset = "$ESC[0m"

if (-not $Orchestrated) {
    $Host.UI.RawUI.WindowTitle = "V1 DFIR // THREAT CONTAINMENT ENGINE"
    [Console]::CursorVisible = $false
    Clear-Host
    [Console]::SetCursorPosition(0, 6)
}

function Update-UI([int]$Progress, [int]$Threats, [string]$ActionText) {
    if ($Orchestrated) {
        Write-Output "[HUD]|$Progress|$Threats|$ActionText"
    } else {
        $curLeft = [Console]::CursorLeft; $curTop = [Console]::CursorTop
        [Console]::SetCursorPosition(0, 0)

        # --- DYNAMIC PADDING MATH ---
        # 1. Define the raw, uncolored strings so PowerShell can count the EXACT character length
        $EngineName = "THREAT CONTAINMENT ENGINE"
        $TitleStr   = "  ⚡ C2 SENSOR V1  | $EngineName"
        $StatsStr   = "  Progress : $Progress% | Targets: $Threats"

        # 2. Prevent Action text from overflowing the 86-character boundary
        if ($ActionText.Length -gt 70) { $ActionText = $ActionText.Substring(0, 67) + "..." }
        $ActionStr  = "  Action   : $ActionText"

        # 3. Calculate exact spaces needed to hit 86 characters perfectly
        # (Note: Some terminals render the ⚡ emoji as 2 spaces wide. If the top line is off by 1 space, subtract 1 from the Title length math)
        $PadTitle  = " " * [math]::Max(0, (86 - $TitleStr.Length))
        $PadStats  = " " * [math]::Max(0, (86 - $StatsStr.Length))
        $PadAction = " " * [math]::Max(0, (86 - $ActionStr.Length))

        Write-Host "$cCyan╔══════════════════════════════════════════════════════════════════════════════════════╗$cReset"
        Write-Host "$cCyan║$cReset  $cRed⚡ C2 SENSOR V1$cReset | $EngineName$PadTitle$cCyan║$cReset"
        Write-Host "$cCyan╠═════════════════════════════════════════════════════════════════════════════════════╣$cReset"
        Write-Host "$cCyan║$cReset  Progress : $cCyan$Progress%$cReset | Targets: $cRed$Threats$cReset$PadStats$cCyan║$cReset"
        Write-Host "$cCyan║$cReset  Action   : $cYellow$ActionText$cReset$PadAction$cCyan║$cReset"
        Write-Host "$cCyan╚══════════════════════════════════════════════════════════════════════════════════════╝$cReset"

        if ($curTop -lt 6) { $curTop = 6 }
        [Console]::SetCursorPosition($curLeft, $curTop)
    }
}

$Win32ThreadManager = @"
using System;
using System.Runtime.InteropServices;
public class ThreadManager {
    [Flags] public enum ThreadAccess : int { SUSPEND_RESUME = 0x0002 }
    [DllImport("kernel32.dll")] public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
    [DllImport("kernel32.dll")] public static extern uint SuspendThread(IntPtr hThread);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr hHandle);
}
"@
Add-Type -TypeDefinition $Win32ThreadManager -ErrorAction SilentlyContinue

if (-not $ArmedMode) { Write-Output "  $cYellow[!] ENGINE IS IN DRY-RUN MODE. NO LETHAL ACTIONS WILL BE TAKEN.$cReset" }

function Write-ContainmentLog([string]$Message) {
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    "[$ts] $Message" | Out-File -FilePath $ContainmentLog -Encoding UTF8 -Append
}

if (-not (Test-Path $CorrelationReport)) { exit }
$Lines = Get-Content $CorrelationReport
$TotalLines = $Lines.Count; $Idx = 0

$ProtectedPIDs = @(0, 4); $ActiveRisk = $false; $ActionCount = 0

foreach ($line in $Lines) {
    $Idx++
    $pct = if ($TotalLines -gt 0) { [math]::Round(($Idx / $TotalLines) * 100) } else { 0 }
    Update-UI $pct $ActionCount "Evaluating Correlation Matrix..."

    if ($line -match "RISK LEVEL\s*:\s*(CRITICAL|HIGH)\s*\(Score:\s*(\d+)\)") {
        $ActiveRisk = ([int]$matches[2] -ge $RiskThreshold)
    }

    if ($ActiveRisk -and $line -match "PROCESS\s*:\s*(.*)\s*\(PID:\s*(\d+)(?:,\s*TID:\s*(\d+))?\)") {
        $TargetProcess = $matches[1].Trim(); $TargetPID = [int]$matches[2]
        if ($matches[3]) { $TargetTID = [uint32]$matches[3] }
    }

    if ($ActiveRisk -and $line -match "DESTINATION\s*:\s*([0-9\.]+):\d+") {
        $TargetIP = $matches[1]
    }

    if ($ActiveRisk -and $line -match "^STATIC FLAGS:") {
        if ($TargetPID -and $TargetIP) {
            Update-UI $pct $ActionCount "Isolating Threat: $TargetProcess"
            Write-Output "  $cRed[!] THREAT ISOLATED:$cReset $TargetProcess (PID: $TargetPID, TID: $($TargetTID -replace '^$','Unknown')) -> $TargetIP"

            if ($ProtectedPIDs -contains $TargetPID -and -not $TargetTID) {
                Write-Output "    $cYellow[-] ABORTED TERMINATION:$cReset PID $TargetPID is protected."
            } else {
                try {
                    if ($TargetTID) {
                        if ($ArmedMode) {
                            $hThread = [ThreadManager]::OpenThread([ThreadManager+ThreadAccess]::SUSPEND_RESUME, $false, $TargetTID)
                            if ($hThread -ne [IntPtr]::Zero) {
                                [ThreadManager]::SuspendThread($hThread) | Out-Null
                                [ThreadManager]::CloseHandle($hThread) | Out-Null
                                $ActionCount++
                                Write-Output "    $cGreen[+] THREAD SUSPENDED:$cReset TID $TargetTID inside $TargetProcess"
                                Write-Output "    $cCyan[*] FORENSICS:$cReset Execute: procdump.exe -ma $TargetPID C:\Temp\Dump_$($TargetPID).dmp"
                                Write-ContainmentLog "SUSPENDED THREAD: TID $TargetTID inside $TargetProcess (PID: $TargetPID)"
                            }
                        } else { Write-Output "    $cDark[?] DRY-RUN:$cReset Would suspend TID $TargetTID" }
                    } else {
                        if ($ArmedMode) {
                            Stop-Process -Id $TargetPID -Force -ErrorAction Stop
                            $ActionCount++
                            Write-Output "    $cGreen[+] PROCESS TERMINATED:$cReset PID $TargetPID"
                        } else { Write-Output "    $cDark[?] DRY-RUN:$cReset Would terminate $TargetProcess" }
                    }

                    # Execute Triage Hook directly from Root
                    if (Test-Path $TriageScriptPath) {
                        if ($Orchestrated) {
                            & $TriageScriptPath -TargetPID $TargetPID -AlertTime (Get-Date) -EvidenceFolder $EvidenceFolder -Orchestrated
                        } else {
                            & $TriageScriptPath -TargetPID $TargetPID -AlertTime (Get-Date) -EvidenceFolder $EvidenceFolder
                        }
                    }
                } catch { }
            }

            $RuleName = "C2_Hunter_Block_$TargetIP"
            if (-not (Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue)) {
                if ($ArmedMode) {
                    New-NetFirewallRule -DisplayName $RuleName -Direction Outbound -Action Block -RemoteAddress $TargetIP | Out-Null
                    $ActionCount++
                    Write-Output "    $cGreen[+] FIREWALL BLACKLIST:$cReset Outbound traffic to $TargetIP blocked."
                } else { Write-Output "    $cDark[?] DRY-RUN:$cReset Would block IP $TargetIP" }
            }
        }
        $ActiveRisk = $false; $TargetPID = $null; $TargetTID = $null; $TargetIP = $null
    }
}
Update-UI 100 $ActionCount "Containment Loop Complete."
if (-not $Orchestrated) { [Console]::CursorVisible = $true }