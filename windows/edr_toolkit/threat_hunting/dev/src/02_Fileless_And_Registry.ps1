function Invoke-FilelessHunt {
    Write-Console "[*] Hunting for Classic Fileless Persistence..." "Cyan"
    $wmiConsumers = Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue
    foreach ($consumer in $wmiConsumers) {
        if ($consumer.Name -notmatch "BVTConsumer|SCM Event Log Consumer") {
            Add-Finding -Type "WMI Persistence" -Target "WMI Consumer: $($consumer.Name)" `
                -Details "Suspicious WMI Event Consumer" -Severity "High" -Mitre $Global:MITRE.WMIPersistence
        }
    }
    $runKeys = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Run","HKCU:\Software\Microsoft\Windows\CurrentVersion\Run")
    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            $entries = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            foreach ($property in $entries.PSObject.Properties) {
                if ($property.Name -notin @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")) {
                    $val = $property.Value
                    if ($val -match "powershell|cmd\.exe|wscript|cscript|mshta|regsvr32|rundll32|certutil|bitsadmin") {
                        Add-Finding -Type "Suspicious Registry Key" -Target "$key\$($property.Name)" `
                            -Details "LOLBin in Run Key: $val" -Severity "High" -Mitre $Global:MITRE.RegPersistence
                    }
                }
            }
        }
    }
}

function Invoke-AdvancedRegistryHunt {
    Write-Console "[*] Expanded Registry Persistence (IFEO, AppInit_DLLs, Services)..." "Cyan"
    $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    if (Test-Path $ifeoPath) {
        Get-ChildItem $ifeoPath | ForEach-Object {
            $dbg = Get-ItemProperty -Path $_.PSPath -Name "Debugger" -ErrorAction SilentlyContinue
            if ($dbg.Debugger -match "powershell|cmd|wscript|mshta") {
                Add-Finding -Type "IFEO Debugger Hijack" -Target $_.PSChildName `
                    -Details "Debugger: $($dbg.Debugger)" -Severity "High" -Mitre $Global:MITRE.RegIFEO
            }
        }
    }
    $appinitPaths = @("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows","HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows")
    foreach ($p in $appinitPaths) {
        if (Test-Path $p) {
            $val = Get-ItemProperty -Path $p -Name "AppInit_DLLs" -ErrorAction SilentlyContinue
            if ($val.AppInit_DLLs) {
                Add-Finding -Type "AppInit_DLLs Hijack" -Target $p `
                    -Details "AppInit_DLLs: $($val.AppInit_DLLs)" -Severity "High" -Mitre $Global:MITRE.AppInitDLL
            }
        }
    }
    $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
    foreach ($svc in $services) {
        if ($svc.PathName -match "powershell|cmd\.exe|wscript|cscript|mshta|regsvr32|rundll32|certutil|bitsadmin" -or $svc.PathName -match "\\Temp|\\AppData") {
            Add-Finding -Type "Suspicious Service" -Target "$($svc.Name) ($($svc.PathName))" `
                -Details "Path: $($svc.PathName) | StartMode: $($svc.StartMode)" -Severity "High" -Mitre $Global:MITRE.ServiceTamper
        }
    }
}