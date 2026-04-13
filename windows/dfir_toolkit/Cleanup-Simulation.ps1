<#
.SYNOPSIS
    DFIR Simulation Cleanup
.DESCRIPTION
    Reverts the state of the test VM by surgically killing simulated malicious processes,
    ensuring test services are removed, and clearing out local staging artifacts.
#>

$ErrorActionPreference = "SilentlyContinue"

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " INITIATING SIMULATION CLEANUP " -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

# Require Admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Warning "Administrator privileges required to clean up simulated artifacts."; exit }

# ---------------------------------------------------------
# 1. SURGICAL PROCESS TERMINATION
# ---------------------------------------------------------
Write-Host "[*] Hunting for simulated processes..."

# Target the specific Encoded PowerShell command from the simulator
$EncodedString = "IAAgAFcAcgBpAHQAZQAtAEgAbwBzAHQAIAAnAFMAaQBtAHUAbABhAHQAaQBvAG4AJwA7ACAAUwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBTAGUAYwBvAG4AZABzACAAMwAwADAA"
$RoguePS = Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" | Where-Object { $_.CommandLine -match $EncodedString }

if ($RoguePS) {
    Stop-Process -Id $RoguePS.ProcessId -Force
    Write-Host "    -> Terminated simulated LotL PowerShell process (PID: $($RoguePS.ProcessId))" -ForegroundColor Green
} else {
    Write-Host "    -> Simulated PowerShell process not found (It may have already exited)."
}

# Target hidden Notepad processes (Simulated C2)
# Note: Since the simulator launched Notepad completely hidden, we look for Notepad instances with no visible main window handle
$HiddenNotepads = Get-Process -Name "notepad" | Where-Object { $_.MainWindowHandle -eq 0 }

if ($HiddenNotepads) {
    foreach ($np in $HiddenNotepads) {
        Stop-Process -Id $np.Id -Force
        Write-Host "    -> Terminated hidden injected Notepad process (PID: $($np.Id))" -ForegroundColor Green
    }
} else {
    Write-Host "    -> No hidden injected Notepad processes found."
}

# ---------------------------------------------------------
# 2. SERVICE VERIFICATION
# ---------------------------------------------------------
Write-Host "[*] Verifying test service removal..."
$ServiceName = "PSEXESVC"
$ServiceCheck = Get-Service -Name $ServiceName

if ($ServiceCheck) {
    Stop-Service -Name $ServiceName -Force
    sc.exe delete $ServiceName | Out-Null
    Write-Host "    -> Residual '$ServiceName' service successfully deleted." -ForegroundColor Green
} else {
    Write-Host "    -> Test service already cleared."
}

# ---------------------------------------------------------
# 3. STAGING ARTIFACT SWEEP
# ---------------------------------------------------------
Write-Host "[*] Sweeping local DFIR staging directories..."

$StagingDir = "C:\Windows\Temp\DFIR_Collect"
if (Test-Path $StagingDir) {
    Remove-Item -Path $StagingDir -Recurse -Force
    Write-Host "    -> Deleted endpoint collection staging directory ($StagingDir)." -ForegroundColor Green
}

# ---------------------------------------------------------
# NOTE ON EVENT LOGS
# ---------------------------------------------------------
Write-Host "`n[*] Note: Event Logs (1102, 104, 7045, 4104) generated during the test remain in the Windows Event Viewer."
Write-Host "    To fully reset them, you would need to clear the Security, System, and PowerShell logs." -ForegroundColor Yellow

Write-Host "`n=============================================" -ForegroundColor Cyan
Write-Host " CLEANUP COMPLETE " -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan