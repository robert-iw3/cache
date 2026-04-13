function Invoke-BITSHunt {
    Write-Console "[*] Hunting for Suspicious BITS Jobs..." "Cyan"
    $jobs = Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue
    foreach ($job in $jobs) {
        if ($job.DisplayName -notmatch "Microsoft|Windows Update|Background Intelligent") {
            Add-Finding -Type "Suspicious BITS Job" -Target "Job: $($job.DisplayName)" `
                -Details "URL: $($job.FileList.Source) | State: $($job.JobState)" -Severity "High" -Mitre $Global:MITRE.BITSJob
        }
    }
}

function Invoke-COMHijackHunt {
    Write-Console "[*] Hunting for COM Hijacking..." "Cyan"
    $comPaths = @("HKLM:\Software\Classes\CLSID","HKCU:\Software\Classes\CLSID")
    foreach ($base in $comPaths) {
        if (Test-Path $base) {
            $clsids = Get-ChildItem $base -ErrorAction SilentlyContinue
            foreach ($clsid in $clsids) {
                $inproc = Join-Path $clsid.PSPath "InProcServer32"
                if (Test-Path $inproc) {
                    $dll = (Get-ItemProperty $inproc -ErrorAction SilentlyContinue).'(Default)'
                    if ($dll) {
                        # Much broader whitelist + handle bare filenames
                        if ($dll -notmatch "(?i)(system32|syswow64|Program Files|WinSxS|Microsoft\.NET|Windows Defender|Windows\\servicing|ProgramData\\Microsoft|Windows\\SystemApps)") {
                            Add-Finding -Type "COM Hijacking" -Target $clsid.PSChildName `
                                -Details "InProcServer32 points to suspicious DLL: $dll" -Severity "High" -Mitre $Global:MITRE.COMHijack
                        }
                    }
                }
            }
        }
    }
}

function Invoke-ETWAMSITamperHunt {
    Write-Console "[*] Hunting for ETW / AMSI Tampering..." "Cyan"
    $amsiProv = "HKLM:\SOFTWARE\Microsoft\AMSI\Providers"
    if (Test-Path $amsiProv) {
        $count = (Get-ChildItem $amsiProv -ErrorAction SilentlyContinue).Count
        if ($count -eq 0) {
            Add-Finding -Type "AMSI Tampering" -Target "AMSI Providers" `
                -Details "0 providers registered. AMSI is completely blinded!" -Severity "Critical" -Mitre $Global:MITRE.AMSITampering
        }
    }
    $amsiKey = "HKLM:\SOFTWARE\Microsoft\Windows Script\Settings"
    if (Test-Path $amsiKey) {
        $val = Get-ItemProperty -Path $amsiKey -Name "AmsiEnable" -ErrorAction SilentlyContinue
        if ($val.AmsiEnable -eq 0) {
            Add-Finding -Type "AMSI Disabled" -Target "AmsiEnable = 0" `
                -Details "AMSI explicitly disabled in registry" -Severity "Critical" -Mitre $Global:MITRE.AMSITampering
        }
    }
    $auto = "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger"
    if (Test-Path $auto) {
        $sessions = Get-ChildItem $auto -ErrorAction SilentlyContinue
        foreach ($s in $sessions) {
            $enabled = Get-ItemProperty -Path $s.PSPath -Name "Enabled" -ErrorAction SilentlyContinue
            if ($enabled.Enabled -eq 0) {
                Add-Finding -Type "ETW Tampering" -Target $s.PSChildName `
                    -Details "Autologger session disabled" -Severity "High" -Mitre $Global:MITRE.ETWTampering
            }
        }
    }
}

function Invoke-PendingRenameHunt {
    Write-Console "[*] Checking PendingFileRenameOperations (MoveEDR)..." "Cyan"
    $key = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    $val = Get-ItemProperty -Path $key -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
    if ($val.PendingFileRenameOperations) {
        Add-Finding -Type "PendingFileRenameOperations" -Target "Session Manager" `
            -Details "Entries present - possible boot-time EDR deletion" -Severity "High" -Mitre $Global:MITRE.PendingRename
    }
}