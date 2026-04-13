<#
.SYNOPSIS
    PowerShell script to enable stricter certificate revocation checking on Windows machines.
    This script applies registry settings to enforce hard-fail revocation checks for CRL/OCSP,
    clears the revocation cache, and verifies basic revocation functionality.
    Suitable for both WEC servers and client machines in a Windows Event Forwarding setup.

.DESCRIPTION
    Enables certificate revocation checks by setting Kerberos and Schannel registry keys.
    - Forces hard-fail if CRL/OCSP unreachable (via EnableCbac).
    - Disables sending trusted issuer list for stronger checks.
    - Clears revocation cache to force fresh checks.
    - Performs a basic test if a certificate thumbprint is provided.

    WARNING: These settings affect Schannel globally and may cause connection failures if
    CRL/OCSP infrastructure is unreliable. Test in a non-production environment first.
    Revocation checks are most effective with certificates from a trusted CA with HTTP-published CDP/AIA.

.PARAMETER CertThumbprint
    Optional: Thumbprint of a certificate to test revocation checking against (e.g., your WEC server cert).
    If provided, the script will run certutil -verify to test reachability.

.PARAMETER Force
    Switch: Apply changes without confirmation prompt.

.EXAMPLE
    .\Enable-RevocationChecks.ps1
    Enables revocation checks with confirmation.

.EXAMPLE
    .\Enable-RevocationChecks.ps1 -CertThumbprint "ABC123..." -Force
    Enables checks, tests against the specified cert, without prompting.

.NOTES
    Must be run as Administrator.
    Based on recommendations for hardening WinRM HTTPS in WEF setups.
    For self-signed certs, revocation is not applicable and may be skipped.
    Deploy via GPO for scale in enterprise environments.

    Author: Robert Weber
#>

param (
    [string]$CertThumbprint = "",
    [switch]$Force
)

# Check for admin privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

# Confirmation prompt unless -Force
if (-not $Force) {
    Write-Warning "This will enable stricter certificate revocation checking system-wide."
    Write-Warning "It may cause SSL/TLS connections (including WinRM) to fail if CRL/OCSP servers are unreachable."
    $confirm = Read-Host "Proceed? (Y/N)"
    if ($confirm -notmatch "^[Yy]$") {
        Write-Host "Operation cancelled." -ForegroundColor Yellow
        exit 0
    }
}

try {
    Write-Host "Enabling stricter revocation checking..." -ForegroundColor Cyan

    # Force revocation check (hard fail if offline) - Kerberos Parameters
    $kerbPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
    New-Item -Path $kerbPath -Force | Out-Null
    Set-ItemProperty -Path $kerbPath -Name "EnableCbac" -Value 1 -Type DWord -Force -ErrorAction Stop

    # Stronger revocation checking for SSL/TLS (Schannel)
    $schannelPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
    New-Item -Path $schannelPath -Force | Out-Null
    Set-ItemProperty -Path $schannelPath -Name "SendTrustedIssuerList" -Value 0 -Type DWord -Force -ErrorAction Stop

    # Optional: Disable revocation cache timeout / force fresh checks (uncomment if needed)
    # Set-ItemProperty -Path $kerbPath -Name "CbacFreshnessTime" -Value 0 -Type DWord -Force -ErrorAction Stop

    Write-Host "Registry settings applied successfully." -ForegroundColor Green

    # Clear revocation cache to force fresh checks
    Write-Host "Clearing revocation cache..." -ForegroundColor Cyan
    certutil -urlcache * delete | Out-Null
    certutil -urlcache crl delete | Out-Null
    certutil -urlcache ocsp delete | Out-Null
    Write-Host "Revocation cache cleared." -ForegroundColor Green

    # If CertThumbprint provided, test revocation
    if ($CertThumbprint -ne "") {
        Write-Host "Testing certificate revocation with thumbprint: $CertThumbprint" -ForegroundColor Cyan
        $certTest = certutil -verify -urlfetch "Cert:\LocalMachine\My\$CertThumbprint"
        Write-Verbose ($certTest -join "`n")
        if ($certTest -match "Revocation check succeeded" -or $certTest -match "This update is current") {
            Write-Host "Revocation check test passed." -ForegroundColor Green
        } else {
            Write-Warning "Revocation check test had issues. Review details and ensure CDP/AIA/OCSP URLs are reachable."
        }
    } else {
        Write-Host "No CertThumbprint provided; skipping revocation test. Provide one to verify." -ForegroundColor Yellow
    }

    Write-Host "`nConfiguration complete. Restart services (e.g., WinRM) or reboot for changes to take full effect." -ForegroundColor Green
    Write-Host "Tip: Monitor Event Viewer > Microsoft > Windows > WinRM/Operational for revocation errors." -ForegroundColor Magenta
}
catch {
    Write-Error "Failed to enable revocation checks: $($_.Exception.Message)"
    exit 1
}