<#
.SYNOPSIS
    Complete Windows Event Collector (WEC) Server Setup Script
    Configures a machine as a central Windows Event Forwarding (WEF) collection server with secure HTTPS WinRM.

.DESCRIPTION
    This script performs everything required for a push-based WEF server:
    - Optionally generates a self-signed CA and server certificate (for testing) or uses an existing server certificate (for production with trusted CA)
    - Validates the server certificate for proper usage (Server Auth EKU, validity, DNS match)
    - Configures HTTPS WinRM listener with hardening (disables HTTP, enforces encryption, disables weak auth)
    - Enables WinRM & Windows Event Collector service
    - Configures firewall rules for HTTPS (port 5986)
    - Increases ForwardedEvents log size and sets retention policy to archive when full
    - Creates all recommended subscriptions (Security, System, PowerShell, Sysmon, etc.)
    - Adds source computers automatically via GPO name or manual list
    - Uses the official high-quality subscription XMLs from Microsoft/Community

.NOTES
    Run on your central log server (e.g., Windows Server 2022/2019 or Windows 11 Enterprise)
    Requires the "events" folder in the same directory (same structure as before)
    Must be run as Administrator

    Author: Robert Weber

    For production with trusted CA (e.g., AD CS):
    - Provide -ServerCertThumbprint <thumbprint> of an existing server cert in LocalMachine\My store.
    - Assumes the issuing CA is already trusted domain-wide; no CA export needed.
    - Skip self-signed generation with -NoSelfSigned.

    Security Recommendations:
    - For production: Use -ServerCertThumbprint with certs from a trusted enterprise CA (e.g., AD CS).
    - If using self-signed, export the CA cert and import on all clients to establish trust.
    - Monitor WinRM logs: wevtutil sl Microsoft-Windows-WinRM/Operational /e:true
    - Use Group Policy for scalable deployment and to enforce settings.
    - Regularly rotate certs and revoke if compromised.
    - Network segmentation: Place server in secure subnet; monitor port 5986 with IDS.
    - Least privilege: Ensure only necessary accounts in 'Event Log Readers' and 'Remote Management Users'.
    - This setup hardens WinRM by: Disabling HTTP/unencrypted, disabling Basic/CredSSP, strict CBT hardening, Kerberos priority.
#>

param (
    [switch]$AddAllDomainComputers,   # Automatically add all domain computers (requires domain admin)
    [string[]]$ComputerNames = @(),   # Optional: specific computer names to add manually
    [string]$ArchivePath = "D:\Logs", # Optional: Path for ForwardedEvents log and archives (will create if missing)
    [string]$CaCertExportPath = "$PSScriptRoot\WEC_CA.cer",  # Path to export CA cert for clients (self-signed only)
    [string]$ServerCertThumbprint = "",  # Thumbprint of existing server cert (for trusted CA; skips generation)
    [switch]$NoSelfSigned  # Skip self-signed generation; requires -ServerCertThumbprint
)

# Elevate check
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator!"
    exit 1
}

$eventsPath = Join-Path $PSScriptRoot "events"

# ────────────────────────────────────────────────────────────────────────────────
#  Paths & Validation
# ────────────────────────────────────────────────────────────────────────────────
$required = @(
    @{ Path = "$eventsPath\add_subscriptions.ps1"; Name = "add_subscriptions.ps1" },
    @{ Path = "$eventsPath\set_subscriptions_sources.ps1"; Name = "set_subscriptions_sources.ps1" },
    @{ Path = "$eventsPath\subscriptions\Security.xml"; Name = "Security.xml" },
    @{ Path = "$eventsPath\subscriptions\System.xml"; Name = "System.xml" },
    @{ Path = "$eventsPath\subscriptions\PowerShell.xml"; Name = "PowerShell.xml" },
    @{ Path = "$eventsPath\subscriptions\Sysmon.xml"; Name = "Sysmon.xml" },
    @{ Path = "$eventsPath\subscriptions\Application.xml"; Name = "Application.xml" }
)

$missingFiles = @()
foreach ($item in $required) {
    if (-not (Test-Path $item.Path)) {
        $missingFiles += $item.Name
    }
}

if ($missingFiles.Count -gt 0) {
    Write-Error "Missing required files:`n  - $($missingFiles -join "`n  - ")"
    Write-Warning "Please ensure the 'events' folder is in the same directory as this script and contains all necessary files."
    exit 1
}

Write-Host "All required configuration files found." -ForegroundColor Green

Write-Host "`n=== Windows Event Collector Server Setup (Secure HTTPS) ===`n" -ForegroundColor Cyan

# ────────────────────────────────────────────────────────────────────────────────
#  Certificate Handling: Generate Self-Signed or Use Existing
# ────────────────────────────────────────────────────────────────────────────────
try {
    Write-Host "Handling server certificate..." -ForegroundColor Yellow
    $fqdn = "$env:COMPUTERNAME.$env:USERDNSDOMAIN".ToLower()
    if (-not $fqdn.Contains('.')) { $fqdn = "$env:COMPUTERNAME.local" }  # Fallback for workgroup

    $caThumbprint = ""
    $serverThumbprint = ""

    if ($ServerCertThumbprint -ne "") {
        # Use existing server cert (assumes issued by trusted CA)
        $serverCert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $ServerCertThumbprint }
        if (-not $serverCert) {
            throw "Server certificate with thumbprint $ServerCertThumbprint not found in LocalMachine\My store."
        }
        $serverThumbprint = $serverCert.Thumbprint
        Write-Host "Using existing server certificate (Thumbprint: $serverThumbprint)" -ForegroundColor Green
        Write-Warning "Assuming issuing CA is already trusted; no CA export performed."
    } elseif (-not $NoSelfSigned) {
        # Generate self-signed CA and server cert
        Write-Host "Generating self-signed CA and server certificate..." -ForegroundColor Yellow

        # Create self-signed CA
        $caParams = @{
            Subject = "CN=WEC Self-Signed CA"
            KeyLength = 4096
            KeyAlgorithm = 'RSA'
            HashAlgorithm = 'SHA256'
            CertStoreLocation = 'Cert:\LocalMachine\My'
            Provider = 'Microsoft Enhanced RSA and AES Cryptographic Provider'
            KeyExportPolicy = 'Exportable'
            KeyUsage = 'CertSign', 'CRLSign'
            TextExtension = @("2.5.29.19={text}ca=TRUE&pathlength=0")
            NotAfter = (Get-Date).AddYears(5)
        }
        $caCert = New-SelfSignedCertificate @caParams
        $caThumbprint = $caCert.Thumbprint

        # Export CA cert for clients
        Export-Certificate -Cert $caCert -FilePath $CaCertExportPath -Type CERT -Force
        Write-Host "CA cert exported to: $CaCertExportPath (share this with clients)" -ForegroundColor Green

        # Create server cert signed by CA
        $serverParams = @{
            DnsName = $fqdn
            Subject = "CN=$fqdn"
            Signer = $caCert
            KeyLength = 2048
            KeyAlgorithm = 'RSA'
            HashAlgorithm = 'SHA256'
            CertStoreLocation = 'Cert:\LocalMachine\My'
            Provider = 'Microsoft Enhanced RSA and AES Cryptographic Provider'
            KeyExportPolicy = 'Exportable'
            KeyUsage = 'KeyEncipherment', 'DigitalSignature'
            TextExtension = @("2.5.29.37={text}1.3.6.1.5.5.7.3.1")
            NotAfter = (Get-Date).AddYears(2)
        }
        $serverCert = New-SelfSignedCertificate @serverParams
        $serverThumbprint = $serverCert.Thumbprint

        # Trust CA in Root store (for local testing)
        $rootStore = Get-Item Cert:\LocalMachine\Root
        $rootStore.Open('ReadWrite')
        $rootStore.Add($caCert)
        $rootStore.Close()

        Write-Host "Self-signed certificates generated: CA Thumbprint=$caThumbprint, Server Thumbprint=$serverThumbprint" -ForegroundColor Green
    } else {
        throw "No certificate provided. Use -ServerCertThumbprint or remove -NoSelfSigned to generate self-signed."
    }

    # Validate server certificate
    Write-Host "Validating server certificate..." -ForegroundColor Yellow
    if (-not $serverCert) { $serverCert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $serverThumbprint } }

    # Check Server Authentication EKU
    $hasServerAuth = $serverCert.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq "1.3.6.1.5.5.7.3.1" }
    if (-not $hasServerAuth) { throw "Certificate missing Server Authentication EKU (1.3.6.1.5.5.7.3.1)." }

    # Check validity period
    if ($serverCert.NotBefore -gt (Get-Date) -or $serverCert.NotAfter -lt (Get-Date)) { throw "Certificate is not valid (expired or not yet valid)." }

    # Check DNS name matches FQDN
    if ($serverCert.DnsNameList.Unicode -notcontains $fqdn) { throw "Certificate DNS names do not include $fqdn." }

    # Basic key usage check
    if (-not $serverCert.Verify()) { throw "Certificate verification failed." }

    Write-Host "Server certificate validated successfully." -ForegroundColor Green
}
catch {
    Write-Error "Certificate handling/validation failed: $($_.Exception.Message)"
    Write-Warning "In production, ensure certs are from a trusted CA."
    exit 1
}

# ────────────────────────────────────────────────────────────────────────────────
#  Configure Secure HTTPS WinRM Listener & Hardening
# ────────────────────────────────────────────────────────────────────────────────
try {
    Write-Host "Configuring hardened HTTPS WinRM..." -ForegroundColor Yellow

    # Create HTTPS listener
    winrm create winrm/config/Listener?Address=*+Transport=HTTPS "@{Hostname='$fqdn'; CertificateThumbprint='$serverThumbprint'}" -ErrorAction Stop

    # Disable HTTP listener
    try { winrm delete winrm/config/Listener?Address=*+Transport=HTTP -ErrorAction Stop } catch { Write-Verbose "HTTP listener not present." }

    # Harden service config: Enforce encryption, disable weak auth, strict CBT
    winrm set winrm/config/service '@{AllowUnencrypted="false"}' -ErrorAction Stop
    winrm set winrm/config/service/auth '@{Basic="false"; Kerberos="true"; Negotiate="true"; Certificate="true"; CredSSP="false"; CbtHardeningLevel="Strict"}' -ErrorAction Stop

    # Enable WinRM logging for monitoring
    wevtutil sl Microsoft-Windows-WinRM/Operational /e:true -ErrorAction Stop | Out-Null

    Write-Host "WinRM hardened and configured for HTTPS." -ForegroundColor Green
}
catch {
    Write-Error "Failed to configure WinRM: $($_.Exception.Message)"
    exit 1
}

# ────────────────────────────────────────────────────────────────────────────────
#  Enable Services
# ────────────────────────────────────────────────────────────────────────────────
try {
    Write-Host "Enabling WinRM and Windows Event Collector service..." -ForegroundColor Yellow
    Set-Service WinRM -StartupType Automatic -ErrorAction Stop
    Start-Service WinRM -ErrorAction Stop

    Set-Service Wecsvc -StartupType Automatic -ErrorAction Stop
    Start-Service Wecsvc -ErrorAction Stop
    Write-Host "Services enabled successfully." -ForegroundColor Green
}
catch {
    Write-Error "Failed to enable services: $($_.Exception.Message)"
    exit 1
}

# ────────────────────────────────────────────────────────────────────────────────
#  Firewall Rules (HTTPS only)
# ────────────────────────────────────────────────────────────────────────────────
try {
    Write-Host "Configuring firewall rules for HTTPS..." -ForegroundColor Yellow
    Enable-NetFirewallRule -DisplayGroup "Windows Remote Management" -ErrorAction Stop
    New-NetFirewallRule -DisplayName "WinRM HTTPS (WEF-In)" `
                        -Direction Inbound -Protocol TCP -LocalPort 5986 `
                        -Action Allow -Profile Domain,Private -ErrorAction Stop | Out-Null
    Write-Host "Firewall rules configured." -ForegroundColor Green
}
catch {
    Write-Error "Failed to configure firewall: $($_.Exception.Message)"
    exit 1
}

# ────────────────────────────────────────────────────────────────────────────────
#  ForwardedEvents Log Configuration (Size + Retention)
# ────────────────────────────────────────────────────────────────────────────────
try {
    Write-Host "Configuring ForwardedEvents log (size, retention, and archive)..." -ForegroundColor Yellow

    # Create archive directory if specified and missing
    if ($ArchivePath -and -not (Test-Path $ArchivePath)) {
        New-Item -Path $ArchivePath -ItemType Directory -Force -ErrorAction Stop | Out-Null
        # Set recommended ACLs: EventLog (full), System (full), Administrators (full)
        $acl = Get-Acl $ArchivePath
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Event Log Readers", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
        Set-Acl $ArchivePath $acl -ErrorAction Stop
        Write-Host "Created archive directory '$ArchivePath' with ACLs." -ForegroundColor Green
    }

    $logFilePath = if ($ArchivePath) { Join-Path $ArchivePath "ForwardedEvents.evtx" } else { "%SystemRoot%\System32\Winevt\Logs\ForwardedEvents.evtx" }

    # Set size to 2GB, retention: false (do not overwrite), auto-backup: true (archive when full)
    wevtutil sl ForwardedEvents /ms:2147483648 /rt:false /ab:true /lfn:"$logFilePath" -ErrorAction Stop | Out-Null
    Write-Host "ForwardedEvents log configured (2GB, archive when full)." -ForegroundColor Green
}
catch {
    Write-Error "Failed to configure ForwardedEvents log: $($_.Exception.Message)"
    exit 1
}

# ────────────────────────────────────────────────────────────────────────────────
#  Create Subscriptions
# ────────────────────────────────────────────────────────────────────────────────
try {
    Write-Host "Creating event subscriptions..." -ForegroundColor Yellow
    Push-Location $eventsPath
    try {
        & .\add_subscriptions.ps1
        if ($LASTEXITCODE -ne 0) { throw "add_subscriptions.ps1 failed with exit code $LASTEXITCODE" }
    }
    finally {
        Pop-Location
    }
    Write-Host "Subscriptions created successfully." -ForegroundColor Green
}
catch {
    Write-Error "Failed to create subscriptions: $($_.Exception.Message)"
    exit 1
}

# ────────────────────────────────────────────────────────────────────────────────
#  Add Source Computers
# ────────────────────────────────────────────────────────────────────────────────
try {
    Write-Host "Adding source computers to subscriptions..." -ForegroundColor Yellow

    $sourceList = @()

    if ($AddAllDomainComputers) {
        Write-Host "Adding ALL domain computers (requires Domain Admin rights)..." -ForegroundColor Magenta
        try {
            $domainComputers = Get-ADComputer -Filter * -ErrorAction Stop | Select-Object -ExpandProperty Name
            $sourceList = $domainComputers
        }
        catch {
            throw "Failed to get domain computers: $($_.Exception.Message). Ensure you have AD module and permissions."
        }
    }
    elseif ($ComputerNames.Count -gt 0) {
        $sourceList = $ComputerNames
    }
    else {
        Write-Warning "No computers specified. You must add source computers later via Event Viewer → Subscriptions → Properties → Select Computers."
        Write-Host "Usage tips: -AddAllDomainComputers or -ComputerNames 'PC01','PC02'" -ForegroundColor Yellow
    }

    if ($sourceList.Count -gt 0) {
        $tempFile = "$env:TEMP\wef_sources.txt"
        $sourceList | Where-Object { $_ -ne $env:COMPUTERNAME } | Sort-Object -Unique | Out-File $tempFile -Encoding UTF8 -ErrorAction Stop

        Push-Location $eventsPath
        try {
            & .\set_subscriptions_sources.ps1 -SourceFilePath $tempFile
            if ($LASTEXITCODE -ne 0) { throw "set_subscriptions_sources.ps1 failed with exit code $LASTEXITCODE" }
            Write-Host "$($sourceList.Count) computers added to all subscriptions!" -ForegroundColor Green
        }
        finally {
            Pop-Location
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        }
    }
}
catch {
    Write-Error "Failed to add source computers: $($_.Exception.Message)"
    # Continue, as this is optional
}

# ────────────────────────────────────────────────────────────────────────────────
#  Final Instructions
# ────────────────────────────────────────────────────────────────────────────────
Write-Host "`n=== SETUP COMPLETE ===`n" -ForegroundColor Green
Write-Host "Your secure Windows Event Collector server is now configured with HTTPS!" -ForegroundColor Green
if ($caThumbprint) { Write-Host "CA Thumbprint: $caThumbprint" -ForegroundColor Cyan }
Write-Host "Server Thumbprint: $serverThumbprint" -ForegroundColor Cyan
Write-Host "Server FQDN: $fqdn (use this in client -LogServer)" -ForegroundColor Cyan
Write-Host ""
Write-Host "Forwarded events will appear in:" -ForegroundColor Cyan
Write-Host "   Event Viewer → Applications and Services Logs → Microsoft → Windows → ForwardedEvents"
Write-Host "   Archives will be saved in: $(if ($ArchivePath) { $ArchivePath } else { 'default log directory' })"
Write-Host ""
Write-Host "Subscriptions created:" -ForegroundColor Cyan
try {
    Get-WinEventSubscription | Select-Object SubscriptionId, SubscriptionType, Enabled, Description | Format-Table -AutoSize
}
catch {
    Write-Warning "Failed to list subscriptions: $($_.Exception.Message)"
}
Write-Host ""
Write-Host "Next steps on client machines:" -ForegroundColor Yellow
if ($caThumbprint) {
    Write-Host "   1. Copy $CaCertExportPath to clients (for self-signed trust)."
} else {
    Write-Host "   1. Ensure enterprise CA is trusted domain-wide."
}
Write-Host "   2. Run client script: .\Enable-WindowsEventLogging.ps1 -LogServer $fqdn -CaCertPath <path_to_ca.cer> (if self-signed)"
Write-Host "   Or deploy via GPO/SCCM/Intune."
Write-Host ""
Write-Host "Tip: For maximum visibility, join this server to Microsoft Defender for Endpoint, Sentinel, Splunk, Elastic, Graylog, etc." -ForegroundColor Magenta
Write-Host "Monitor disk usage for archives and implement backup procedures." -ForegroundColor Magenta
Write-Host "For production hardening: Use trusted CA-issued certs; enable certificate revocation checks." -ForegroundColor Magenta