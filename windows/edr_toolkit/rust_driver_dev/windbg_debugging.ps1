<#

PowerShell Script: Robust Kernel Driver Debugging with WinDbg
Author: Robert Weber
Description: Automates downloading/installing WinDbg (via SDK), configures VM for kernel debugging,
runs a comprehensive debug session (breakpoints, symbols, logging), and outputs to log/HTML/CSV.
Enhanced with VM connectivity error handling, advanced breakpoints (e.g., conditional, data access),
and memory leak detection (via !poolused, !heap commands in WinDbg).
Run as Administrator on host. Assumes VM setup (e.g., from prepare_test_env.ps1), driver files in VM.
Prerequisites: Host IP accessible from VM; change paths/IP as needed.

#>

param (
    [string]$VMName = "RustDriverTestVM",          # VM name
    [string]$HostIP = "192.168.1.100",             # Host IP
    [int]$DebugPort = 50000,                       # KDNET port
    [string]$DebugKey = "1.2.3.4",                 # Debug key (generate with bcdedit /dbgsettings)
    [string]$SdkInstallerUrl = "https://go.microsoft.com/fwlink/?linkid=2262345",  # Latest SDK installer
    [string]$WinDbgPath = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe",  # Post-install path
    [string]$SymbolPath = "srv*C:\Symbols*https://msdl.microsoft.com/download/symbols",  # Symbols
    [string]$DriverName = "endpoint_monitor_driver",  # For breakpoints
    [string]$LogFile = "debug_log.txt",            # Raw log
    [string]$HtmlFile = "debug_report.html",       # HTML output
    [string]$CsvFile = "debug_events.csv",         # CSV for events
    [string]$VMAdminUser = "Administrator",        # VM user
    [securestring]$VMAdminPass = (Read-Host -AsSecureString "Enter VM password")  # VM pass
)

# Function for logging
function Log-Message {
    param ([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry
    Add-Content -Path $LogFile -Value $logEntry -ErrorAction SilentlyContinue
}

try {
    # Step 1: Download and Install WinDbg (via SDK if not present)
    if (-not (Test-Path $WinDbgPath)) {
        Log-Message "Downloading Windows SDK installer..."
        $installerPath = "$env:TEMP\winsdksetup.exe"
        Invoke-WebRequest -Uri $SdkInstallerUrl -OutFile $installerPath -ErrorAction Stop
        Log-Message "Installing SDK (selecting Debugging Tools)..."
        Start-Process -FilePath $installerPath -ArgumentList "/features OptionId.WindowsDesktopDebuggers /q /norestart" -Wait -ErrorAction Stop
        if (-not (Test-Path $WinDbgPath)) { throw "WinDbg not found after install. Check path." }
        Log-Message "WinDbg installed."
    } else {
        Log-Message "WinDbg already installed."
    }

    # Step 2: Configure VM for KDNET debugging
    Log-Message "Configuring bcdedit in VM for KDNET..."
    $Cred = New-Object System.Management.Automation.PSCredential ($VMAdminUser, $VMAdminPass)
    try {
        $Session = New-PSSession -VMName $VMName -Credential $Cred -ErrorAction Stop
    } catch {
        throw "VM connectivity failed: $_. Check VM running, credentials, or network."
    }
    Invoke-Command -Session $Session -ScriptBlock {
        bcdedit /debug on
        bcdedit /dbgsettings net hostip:$using:HostIP port:$using:DebugPort key:$using:DebugKey
        if ($LASTEXITCODE -ne 0) { throw "bcdedit failed." }
        Restart-Computer -Force
    } -ErrorAction Stop
    Remove-PSSession $Session
    Log-Message "VM rebooting. Wait ~1 min."

    # Wait for VM readiness (heartbeat check + ping for connectivity)
    $maxWait = 300  # 5 min
    $waited = 0
    while ((Get-VM -Name $VMName).Heartbeat -ne "OkApplicationsHealthy" -and $waited -lt $maxWait) {
        Start-Sleep -Seconds 10
        $waited += 10
    }
    if ($waited -ge $maxWait) { throw "VM not ready after $maxWait seconds." }

    # Additional connectivity check: Ping VM IP (assume known or resolve)
    $vmIp = "192.168.1.101"  # Replace with actual VM IP
    if (-not (Test-Connection -ComputerName $vmIp -Count 1 -Quiet)) {
        throw "VM ping failed. Check network connectivity."
    }
    Log-Message "VM connectivity verified."

    # Step 3: Run comprehensive WinDbg session with advanced breakpoints/leak detection
    Log-Message "Attaching WinDbg..."
    # Advanced commands: Conditional BP on DriverEntry (if anomaly_score_fixed > 800), data BP on queue, leak detection (!poolused, !heap)
    $dbgCommands = ".symfix; .reload; bp /p @$proc $DriverName!DriverEntry `".if (poi(anomaly_score_fixed) > 800) { .echo High Anomaly; gc } .else { gc }`"; ba w4 $DriverName!QUEUE_LOCK `".echo Queue Access`"; !poolused; !heap -s; g; .logopen $LogFile; gu; .logclose"
    $dbgArgs = "-k net:port=$DebugPort,key=$DebugKey -y `"$SymbolPath`" -c `"$dbgCommands`""
    Start-Process -FilePath $WinDbgPath -ArgumentList $dbgArgs -Wait -ErrorAction Stop
    Log-Message "Debug session complete. Log saved to $LogFile."

    # Step 4: Post-process log to HTML/CSV
    Log-Message "Generating HTML/CSV outputs..."
    $logContent = Get-Content $LogFile -ErrorAction Stop

    # HTML (simple table)
    $html = "<html><body><h1>Debug Report</h1><table border='1'><tr><th>Line</th><th>Content</th></tr>"
    $logContent | ForEach-Object { $html += "<tr><td>$([System.Web.HttpUtility]::HtmlEncode($_))</td></tr>" }
    $html += "</table></body></html>"
    $html | Out-File $HtmlFile -Encoding utf8 -ErrorAction Stop

    # CSV (parse lines; assume [timestamp] [level] message format)
    $csvContent = @()
    foreach ($line in $logContent) {
        if ($line -match '\[(.*?)\] \[(.*?)\] (.*)') {
            $csvContent += [PSCustomObject]@{
                Timestamp = $matches[1]
                Level = $matches[2]
                Message = $matches[3]
            }
        }
    }
    $csvContent | Export-Csv $CsvFile -NoTypeInformation -ErrorAction Stop
    Log-Message "Outputs generated: $HtmlFile, $CsvFile."
} catch {
    Log-Message "Error: $_" "ERROR"
    exit 1
}

Log-Message "Debugging complete."