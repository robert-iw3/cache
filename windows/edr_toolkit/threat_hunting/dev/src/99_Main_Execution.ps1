Write-Console "===================================================" "Green"
Write-Console "=========== Windows EDR Hunting Toolkit ===========" "Green"
Write-Console "===================================================" "Green"

if ($TestMode) {
    Write-Host "[*] RUNNING IN TEST MODE: Injecting simulated artifacts to test pipeline routing..." -ForegroundColor Magenta
    Add-Finding -Type "AMSI Tampering" -Target "Simulated Evasion Check" -Details "Only 0 provider(s) registered" -Severity "Critical" -Mitre "T1562.001"
    Add-Finding -Type "High Entropy File" -Target "C:\Temp\TestPayload.exe" -Details "Simulated Entropy: 7.99" -Severity "High" -Mitre "T1027"
    Export-Reports -OutDir $ReportPath
    exit
}

if (-not ($ScanProcesses -or $ScanFileless -or $TargetDirectory -or $ScanTasks -or $ScanDrivers -or $ScanInjection -or $ScanADS -or $ScanRegistry -or $ScanETWAMSI -or $ScanPendingRename -or $ScanBITS -or $ScanCOM)) {
    Write-Host "Usage examples:" -ForegroundColor Yellow
    Write-Host " .\EDR_Toolkit.ps1 -ScanProcesses -ScanFileless -ScanTasks -ScanDrivers -ScanInjection -ScanRegistry -ScanETWAMSI -ScanPendingRename -ScanBITS -ScanCOM"
    Write-Host " .\EDR_Toolkit.ps1 -TargetDirectory 'C:\' -Recursive -ScanADS -QuickMode -SeverityFilter Critical,High -OutputFormat JSON -Quiet"
    Exit
}

if ($ScanProcesses)  { Invoke-ProcessHunt }
if ($ScanInjection)  { Invoke-InjectionHunt }
if ($ScanFileless)   { Invoke-FilelessHunt }
if ($ScanRegistry)   { Invoke-AdvancedRegistryHunt }
if ($ScanTasks)      { Invoke-ScheduledTaskHunt }
if ($ScanDrivers)    { Invoke-DriverHunt }
if ($ScanBITS)       { Invoke-BITSHunt }
if ($ScanCOM)        { Invoke-COMHijackHunt }
if ($ScanETWAMSI)    { Invoke-ETWAMSITamperHunt }
if ($ScanPendingRename) { Invoke-PendingRenameHunt }

if ($TargetDirectory) {
    Invoke-FileHunt -Path $TargetDirectory -Recurse:$Recursive
    if ($ScanADS) { Invoke-ADSHunt -Path $TargetDirectory -Recurse:$Recursive }
}

Export-Reports -OutDir $ReportPath