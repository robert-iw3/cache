<#
.SYNOPSIS
    Deep Sensor - Full Pipeline Validation (Sigma → ML → UEBA → Alert)
    Safe for any modern AV

.DESCRIPTION
    Generates controlled telemetry that exercises the complete detection chain
    while staying under AV radar. Validates enriched UEBA events.
#>
#Requires -RunAsAdministrator

$ESC = [char]27
$cGreen = "$ESC[92m"; $cCyan = "$ESC[96m"; $cYellow = "$ESC[93m"; $cRed = "$ESC[91m"; $cReset = "$ESC[0m"

Write-Host "$cCyan=================================================================$cReset"
Write-Host "$cCyan   DEEP SENSOR FULL PIPELINE VALIDATION SUITE $cReset"
Write-Host "$cCyan=================================================================`n$cReset"

Write-Host "$cYellow[*] Make sure DeepSensor_Launcher.ps1 is running in another window.$cReset"
Start-Sleep -Seconds 2

# =====================================================================
# PHASE 1: Trigger Sigma Detections (should appear in HUD)
# =====================================================================
Write-Host "`n$cDark--- PHASE 1: Sigma Detection (Flat-Array Match) ---$cReset"

Write-Host "$cGreen[1/6] Testing Sigma: Obfuscated PowerShell (high-fidelity anchor)...$cReset"
powershell.exe -NoProfile -WindowStyle Hidden -Command "Write-Host 'Test' -EncodedCommand 'VwByAGkAdABlAC0ASABvAHMAdAAgACcAVABlAHMAdAAnAA=='" | Out-Null

Write-Host "$cGreen[2/6] Testing Sigma: Registry Persistence (Run key)...$cReset"
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "DeepTest" -Value "powershell.exe -c echo test" -Force | Out-Null
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "DeepTest" -Force -ErrorAction SilentlyContinue

Write-Host "$cGreen[3/6] Testing Sigma: Suspicious File Drop (common malware path)...$cReset"
$testFile = "$env:TEMP\update.exe"
"test payload" | Out-File $testFile -Encoding ASCII
Remove-Item $testFile -Force -ErrorAction SilentlyContinue

# =====================================================================
# PHASE 2: Generate repeatable benign patterns for UEBA learning
# =====================================================================
Write-Host "`n$cDark--- PHASE 2: UEBA Learning Phase (Baseline Building) ---$cReset"

Write-Host "$cGreen[4/6] Creating normal parent-child lineage (code.exe → pwsh.exe)...$cReset"
for ($i = 1; $i -le 8; $i++) {
    Start-Process -FilePath "code.exe" -ArgumentList "--new-window --disable-extensions" -WindowStyle Hidden -PassThru | Out-Null
    Start-Sleep -Milliseconds 400
    Start-Process powershell.exe -ArgumentList "-NoProfile -Command 'Write-Host LearningTest$i'" -WindowStyle Hidden
    Start-Sleep -Milliseconds 600
}

Write-Host "$cGreen[5/6] Creating explorer → powershell lineage (common admin activity)...$cReset"
for ($i = 1; $i -le 6; $i++) {
    Start-Process powershell.exe -ArgumentList "-NoProfile -Command 'Get-Process'" -WindowStyle Hidden
    Start-Sleep -Milliseconds 800
}

# =====================================================================
# PHASE 3: Trigger something that should be learned/suppressed
# =====================================================================
Write-Host "`n$cDark--- PHASE 3: ML → UEBA Suppression Test ---$cReset"

Write-Host "$cGreen[6/6] Triggering repeated benign pattern (should become suppressed)...$cReset"
for ($i = 1; $i -le 12; $i++) {
    Start-Process powershell.exe -ArgumentList "-NoProfile -Command 'echo SuppressedTest'" -WindowStyle Hidden
    Start-Sleep -Milliseconds 350
}

# =====================================================================
# FINAL VERIFICATION
# =====================================================================
Write-Host "`n$cCyan[+] Pipeline test complete!$cReset"
Write-Host "$cYellow[*] Check the following in your running DeepSensor HUD and logs:$cReset"
Write-Host "    • HUD should show Sigma_Match / Static_Detection alerts"
Write-Host "    • UEBA log ($env:ProgramData\DeepSensor\Data\DeepSensor_UEBA_Events.jsonl) should contain enriched events"
Write-Host "    • Look for 'Learning', 'SuppressionLearned', and full context fields (IP, OS, SensorUser, CmdLine)"
Write-Host "    • After ~30 seconds the ML should start suppressing repeated benign patterns"

Write-Host "`n$cGreen[TEST PASSED IF] You see rich JSON with ComputerName/IP/OS/SensorUser/CmdLine in the UEBA log.$cReset"

Read-Host -Prompt "Press ENTER to close this test window"