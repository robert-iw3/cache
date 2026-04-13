<#
.SYNOPSIS
    PowerShell script to enable comprehensive Windows event logging.
    Installs Sysmon, enables PowerShell logging, sets audit policies,
    configures log sizes, sets up WMI auditing, and optionally configures
    secure HTTPS event forwarding (client) or subscriptions (server).

.PARAMETER LogServer
    The FQDN of the log collection server for event forwarding (client mode). Required for HTTPS forwarding.

.PARAMETER CaCertPath
    Path to the CA certificate file (.cer) exported from the server. Required for self-signed; optional if enterprise CA is already trusted.

.PARAMETER IsServer
    Switch to indicate this is the log collection server (sets up subscriptions).

.EXAMPLE
    .\Enable-WindowsEventLogging.ps1 -LogServer "wecserver.domain.local" -CaCertPath "C:\WEC_CA.cer"

.EXAMPLE
    .\Enable-WindowsEventLogging.ps1 -LogServer "wecserver.domain.local"  # If CA already trusted

.EXAMPLE
    .\Enable-WindowsEventLogging.ps1 -IsServer

.NOTES
    Must be run as Administrator.
    Requires Sysmon download from internet.
    Expects an "events" folder in the same directory containing necessary configs.
    For HTTPS: If -CaCertPath provided, imports and trusts it (for self-signed). Validates CA if imported.
    If no -CaCertPath, assumes enterprise CA is already trusted (no import/validation).
    Hardening: Disables unencrypted, weak auth; uses Kerberos priority.

    Author: Robert Weber
#>

param (
    [string]$LogServer = "",
    [string]$CaCertPath = "",
    [switch]$IsServer
)

# Check for admin privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

# ────────────────────────────────────────────────────────────────────────────────
#  Paths & Validation
# ────────────────────────────────────────────────────────────────────────────────
$eventsPath = Join-Path -Path $PSScriptRoot -ChildPath "events"

$requiredPaths = @(
    @{ Path = $eventsPath;                       Name = "events folder" },
    @{ Path = Join-Path $eventsPath "sysmon\sysmon_config.xml";          Name = "Sysmon configuration" },
    @{ Path = Join-Path $eventsPath "wmi_auditing\wmi_auditing.ps1";     Name = "WMI auditing script" }
)

if ($IsServer) {
    $requiredPaths += @(
        @{ Path = Join-Path $eventsPath "add_subscriptions.ps1";          Name = "add_subscriptions.ps1" },
        @{ Path = Join-Path $eventsPath "set_subscriptions_sources.ps1"; Name = "set_subscriptions_sources.ps1" }
    )
} elseif ($LogServer -ne "") {
    if ($CaCertPath -ne "" -and -not (Test-Path $CaCertPath)) {
        Write-Error "Provided -CaCertPath does not exist."
        exit 1
    }
}

$missingFiles = @()
foreach ($item in $requiredPaths) {
    if (-not (Test-Path $item.Path)) {
        $missingFiles += $item.Name
    }
}

if ($missingFiles.Count -gt 0) {
    Write-Error "Missing required files/folders:`n  - $($missingFiles -join "`n  - ")"
    Write-Warning "Please ensure the 'events' folder is in the same directory as this script and contains all necessary files."
    exit 1
}

Write-Host "All required configuration files found." -ForegroundColor Green

# ────────────────────────────────────────────────────────────────────────────────
#  Sysmon Installation
# ────────────────────────────────────────────────────────────────────────────────
try {
    $sysmonZip = "$env:TEMP\Sysmon.zip"
    $sysmonExtractPath = "$env:TEMP\Sysmon"

    Write-Host "Downloading Sysmon..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" `
                      -OutFile $sysmonZip `
                      -UseBasicParsing `
                      -ErrorAction Stop

    Write-Host "Extracting Sysmon..." -ForegroundColor Cyan
    Expand-Archive -Path $sysmonZip -DestinationPath $sysmonExtractPath -Force -ErrorAction Stop

    $sysmonExe = Join-Path $sysmonExtractPath "Sysmon64.exe"
    $sysmonConfig = Join-Path $eventsPath "sysmon\sysmon_config.xml"

    if (-not (Test-Path $sysmonExe)) {
        throw "Sysmon64.exe not found after extraction"
    }

    Write-Host "Installing Sysmon..." -ForegroundColor Cyan
    & $sysmonExe -accepteula -i $sysmonConfig 2>&1 | Out-String | Write-Verbose
    Write-Host "Sysmon installed successfully" -ForegroundColor Green
}
catch {
    Write-Error "Failed to install Sysmon: $($_.Exception.Message)"
    exit 1
}

# ────────────────────────────────────────────────────────────────────────────────
#  Event Log Sizes
# ────────────────────────────────────────────────────────────────────────────────
try {
    Write-Host "Setting event log sizes..." -ForegroundColor Cyan
    wevtutil sl Security      /ms:2147483648 | Out-Null
    wevtutil sl Application   /ms:67108864  | Out-Null
    wevtutil sl System        /ms:67108864  | Out-Null
    Write-Host "Log sizes configured" -ForegroundColor Green
}
catch {
    Write-Warning "Some log sizes could not be set: $($_.Exception.Message)"
}

# ────────────────────────────────────────────────────────────────────────────────
#  PowerShell & Process Creation Logging
# ────────────────────────────────────────────────────────────────────────────────
try {
    Write-Host "Enabling PowerShell logging and command-line auditing..." -ForegroundColor Cyan

    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -ErrorAction Stop

    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1 -Type DWord -ErrorAction Stop

    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Name "*" -Value "*" -ErrorAction Stop

    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -ErrorAction Stop

    Write-Host "PowerShell and command-line logging enabled" -ForegroundColor Green
}
catch {
    Write-Warning "Failed to configure PowerShell/command-line logging: $($_.Exception.Message)"
}

# ────────────────────────────────────────────────────────────────────────────────
#  Audit Policies
# ────────────────────────────────────────────────────────────────────────────────
try {
    Write-Host "Applying audit policies..." -ForegroundColor Cyan
    $auditCommands = @(
        '/set /category:"Account Logon" /success:enable /failure:enable',
        '/set /category:"Account Management" /success:enable /failure:enable',
        '/set /category:"Detailed Tracking" /success:enable /failure:enable',
        '/set /category:"Logon/Logoff" /success:enable /failure:enable',
        '/set /category:"Object Access" /subcategory:"File Share" /success:enable /failure:enable',
        '/set /category:"Object Access" /subcategory:"Other Object Access Events" /success:enable /failure:enable',
        '/set /category:"Policy Change" /success:enable /failure:enable',
        '/set /category:"System" /success:enable /failure:enable'
    )

    foreach ($cmd in $auditCommands) {
        auditpol $cmd.split(' ') | Out-Null
    }
    Write-Host "Audit policies applied" -ForegroundColor Green
}
catch {
    Write-Warning "Some audit policies could not be applied: $($_.Exception.Message)"
}

# ────────────────────────────────────────────────────────────────────────────────
#  WMI Auditing
# ────────────────────────────────────────────────────────────────────────────────
try {
    $wmiPs1 = Join-Path $eventsPath "wmi_auditing\wmi_auditing.ps1"
    Write-Host "Configuring WMI auditing..." -ForegroundColor Cyan
    & $wmiPs1
    if ($LASTEXITCODE -ne 0) { throw "WMI auditing script returned non-zero exit code" }
    Write-Host "WMI auditing configured" -ForegroundColor Green
}
catch {
    Write-Warning "Failed to configure WMI auditing: $($_.Exception.Message)"
}

# ────────────────────────────────────────────────────────────────────────────────
#  Server / Client specific configuration
# ────────────────────────────────────────────────────────────────────────────────
if ($IsServer) {
    try {
        Write-Host "Configuring event collection server..." -ForegroundColor Cyan

        Set-Service -Name WinRM -StartupType Automatic -ErrorAction Stop
        Start-Service WinRM -ErrorAction Stop

        Set-Service -Name Wecsvc -StartupType Automatic -ErrorAction Stop
        Start-Service Wecsvc -ErrorAction Stop

        Enable-NetFirewallRule -DisplayGroup "Windows Remote Management" -ErrorAction Stop

        wevtutil sl ForwardedEvents /ms:2147483648 | Out-Null

        Push-Location $eventsPath
        try {
            & .\add_subscriptions.ps1
            & .\set_subscriptions_sources.ps1
        }
        finally {
            Pop-Location
        }

        Write-Host "Server configuration complete" -ForegroundColor Green
        Write-Host "Remember to add domain computers to the subscriptions manually if needed." -ForegroundColor Yellow
    }
    catch {
        Write-Error "Server setup failed: $($_.Exception.Message)"
    }
}
elseif ($LogServer -ne "") {
    try {
        Write-Host "Configuring secure HTTPS client forwarding to $LogServer..." -ForegroundColor Cyan

        $caThumbprint = ""
        if ($CaCertPath -ne "") {
            # Import and trust CA cert (for self-signed)
            Write-Host "Importing CA cert from $CaCertPath..." -ForegroundColor Yellow
            $caCert = Import-Certificate -FilePath $CaCertPath -CertStoreLocation Cert:\LocalMachine\Root -ErrorAction Stop
            $caThumbprint = ($caCert.Thumbprint -replace '[^a-zA-Z0-9]', '').Trim()
            Write-Host "CA imported (Thumbprint: $caThumbprint)" -ForegroundColor Green

            # Validate CA cert
            Write-Host "Validating CA certificate..." -ForegroundColor Yellow
            $basicConstraints = $caCert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.19" }
            if (-not $basicConstraints -or -not $basicConstraints.Format($true).Contains("CA:TRUE")) {
                throw "Certificate does not have Basic Constraints extension with CA:TRUE."
            }
            if ($caCert.NotBefore -gt (Get-Date) -or $caCert.NotAfter -lt (Get-Date)) {
                throw "CA certificate is not valid (expired or not yet valid)."
            }
            if (-not $caCert.Verify()) { throw "CA certificate verification failed." }
            Write-Host "CA certificate validated successfully." -ForegroundColor Green
        } else {
            Write-Warning "No -CaCertPath provided; assuming enterprise CA is already trusted. No import/validation performed."
            # For enterprise CA, we can't easily get thumbprint here; user must provide it if needed for IssuerCA
            # Prompt or assume user knows to set it manually if required
            Write-Host "If IssuerCA thumbprint is needed, set it manually in registry after setup." -ForegroundColor Yellow
            $caThumbprint = ""  # Leave blank; user can edit later
        }

        # Quick config WinRM (quiet)
        winrm quickconfig -quiet -transport:https -ErrorAction Stop

        # Harden WinRM client: Enforce encryption, disable weak auth
        winrm set winrm/config/client '@{AllowUnencrypted="false"; TrustedHosts="' + $LogServer + '"}' -ErrorAction Stop
        winrm set winrm/config/client/auth '@{Basic="false"; Kerberos="true"; Negotiate="true"; Certificate="true"; CredSSP="false"}' -ErrorAction Stop

        # Configure wecutil
        wecutil qc /q -ErrorAction Stop

        # Set subscription manager with HTTPS and IssuerCA (if available)
        $subManagerPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\EventForwarding\SubscriptionManager"
        New-Item -Path $subManagerPath -Force | Out-Null
        $subValue = "Server=https://$LogServer:5986/wsman/SubscriptionManager/WEC,Refresh=60"
        if ($caThumbprint -ne "") { $subValue += ",IssuerCA=$caThumbprint" }
        Set-ItemProperty -Path $subManagerPath -Name "1" -Value $subValue -ErrorAction Stop

        # Add NETWORK SERVICE to Event Log Readers
        Add-LocalGroupMember -Group "Event Log Readers" -Member "NT AUTHORITY\NETWORK SERVICE" -ErrorAction SilentlyContinue

        # Configure and restart wecsvc
        sc.exe config wecsvc type= own | Out-Null
        Stop-Service wecsvc -Force -ErrorAction SilentlyContinue
        Start-Service wecsvc -ErrorAction Stop

        # Restart WinRM to apply changes
        Restart-Service WinRM -ErrorAction Stop

        Write-Host "Secure HTTPS client forwarding configured successfully" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to configure secure event forwarding: $($_.Exception.Message)"
    }
}
else {
    Write-Host "Basic logging enabled (no forwarding configured)" -ForegroundColor Yellow
    Write-Host "Use -LogServer <fqdn> [-CaCertPath <path>] or -IsServer for secure forwarding/subscription setup" -ForegroundColor Yellow
}

Write-Host "`nConfiguration complete." -ForegroundColor Green