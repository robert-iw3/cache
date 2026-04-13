function Invoke-ProcessHunt {
    Write-Console "[*] Hunting for Hidden & Suspicious Processes..." "Cyan"

    $apiProcs = Get-Process -ErrorAction SilentlyContinue
    $apiDict = @{}
    foreach ($p in $apiProcs) { $apiDict[$p.Id] = $p }

    $wmiProcesses = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue

    # Expanded whitelist for modern Windows + common vendor processes
    $coreAllowed = @(
        "System Idle Process", "System", "Secure System", "Registry", "smss.exe", "csrss.exe",
        "wininit.exe", "services.exe", "lsass.exe", "winlogon.exe", "Memory Compression",
        "LsaIso.exe", "NgcIso.exe", "fontdrvhost.exe", "WUDFHost.exe", "dwm.exe", "sihost.exe",
        "taskhostw.exe", "RuntimeBroker.exe", "ShellExperienceHost.exe", "SearchIndexer.exe",
        "spoolsv.exe", "svchost.exe", "conhost.exe", "ctfmon.exe", "explorer.exe", "StartMenuExperienceHost.exe",
        # Vendor services (ASUS, NVIDIA, Intel, Samsung, Realtek, etc.)
        "NVDisplay.Container.exe", "nvcontainer.exe", "igfx*", "Asus*", "ArmouryCrate*", "coreServiceShell.exe",
        "SamsungMagician*", "RtkAudUService64.exe", "esif_uf.exe", "Intel*", "OneApp.IGCC*", "PtSvcHost.exe",
        "DtsApo4Service.exe", "jhi_service.exe", "LMS.exe", "RstMwService.exe", "TbtP2pShortcutService.exe",
        "WMIRegistrationService.exe", "wslservice.exe", "vmms.exe", "vmcompute.exe", "VSSVC.exe"
    )

    foreach ($wmi in $wmiProcesses) {
        $name = $wmi.Name
        if (-not $apiDict.ContainsKey($wmi.ProcessId) -and $name -notin $coreAllowed) {
            Add-Finding -Type "Hidden Process" -Target "PID: $($wmi.ProcessId)" `
                -Details "Hidden from standard API. Name: $name" -Severity "High" -Mitre $Global:MITRE.HiddenProcess
        }

        if ($wmi.CommandLine -match "-enc|-encodedcommand|-w hidden|-windowstyle hidden|IEX|Invoke-Expression|certutil|bitsadmin|msiexec|regsvr32|rundll32|msbuild|wmic") {
            Add-Finding -Type "Suspicious Command Line" -Target "PID: $($wmi.ProcessId) ($name)" `
                -Details "Fileless/obfuscated execution: $($wmi.CommandLine)" -Severity "High" -Mitre $Global:MITRE.EncodedCommand
        }
    }
}

function Invoke-InjectionHunt {
    Write-Console "[*] Hunting for Reflective DLL Injection / Foreign Modules..." "Cyan"
    $procs = Get-Process -ErrorAction SilentlyContinue
    $sigCache = @{}
    foreach ($p in $procs) {
        try {
            $modules = Get-Module -InputObject $p -ErrorAction SilentlyContinue
            foreach ($m in $modules) {
                if ($m.ModuleName -like "*.dll" -and $m.Path) {
                    if (-not (Test-Path $m.Path)) {
                        Add-Finding -Type "Reflective DLL Injection" -Target "$($p.ProcessName) (PID $($p.Id))" `
                            -Details "Module '$($m.ModuleName)' loaded but file does not exist on disk" -Severity "High" -Mitre $Global:MITRE.ProcessInjection
                        continue
                    }
                    if (-not $sigCache.ContainsKey($m.Path)) {
                        $sigCache[$m.Path] = (Get-AuthenticodeSignature -FilePath $m.Path -ErrorAction SilentlyContinue).Status
                    }
                    $sigStatus = $sigCache[$m.Path]
                    if ($sigStatus -ne "Valid" -and $p.ProcessName -notin @("explorer","svchost","lsass","winlogon","services")) {
                        Add-Finding -Type "Suspicious Injected DLL" -Target "$($p.ProcessName) (PID $($p.Id))" `
                            -Details "Unsigned DLL: $($m.Path)" -Severity "High" -Mitre $Global:MITRE.ProcessInjection
                    }
                }
            }
        } catch {}
    }
}