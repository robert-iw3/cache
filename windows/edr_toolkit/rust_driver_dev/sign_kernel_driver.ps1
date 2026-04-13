<#

PowerShell Script: Sign Kernel Driver for HVCI Compatibility
Author: Robert Weber
Description: This script downloads/installs required tools (Windows SDK for signtool/inf2cat),
validates the EV cert, signs the kernel driver (.sys) with an EV cert, generates .cat file,
and provides guidance for HLK testing/submittal to Microsoft for WHCP attestation.
Run as Administrator. Assumes .inf and .sys files in current dir.
Prerequisites: EV code signing cert (.pfx) with password; driver files ready.

To obtain an Extended Validation (EV) Code Signing Certificate:

Choose a CA: Select a trusted Certificate Authority like DigiCert, GlobalSign, Sectigo, or SSL.com. Prices start at ~$340/year for multi-year plans.
Prepare Validation: Provide organization docs (e.g., business registration, phone verification) for EV vetting.
Generate CSR: Create a Certificate Signing Request on secure hardware (e.g., FIPS 140-2 HSM or YubiKey).
Order Online: Log into CA portal, submit CSR, pay, and await approval (1-10 days).
Receive/Install: Cert delivered on USB token or cloud HSM; sign code with tools like signtool.

For kernel drivers/HVCI: Submit signed driver to Microsoft for WHCP attestation after obtaining cert.

#>

param (
    [string]$SysFile = "endpoint_monitor_driver.sys",  # Path to .sys
    [string]$InfFile = "driver.inf",                  # Path to .inf
    [string]$CertPath = "your_ev_cert.pfx",           # EV cert path
    [securestring]$CertPassword = (Read-Host -AsSecureString "Enter cert password"),  # Cert password
    [string]$TimestampUrl = "http://timestamp.digicert.com",  # Timestamp server
    [string]$SdkUrl = "https://go.microsoft.com/fwlink/?linkid=2262345",  # Latest Windows SDK ISO (update as needed)
    [string]$LogFile = "sign_log.txt"                 # Log output
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
    # Step 1: Check prerequisites
    if (-not (Test-Path $SysFile)) { throw "SYS file not found: $SysFile" }
    if (-not (Test-Path $InfFile)) { throw "INF file not found: $InfFile" }
    if (-not (Test-Path $CertPath)) { throw "Cert not found: $CertPath" }
    Log-Message "Prerequisites check passed."

    # Step 2: Validate EV cert (check expiration, type, and trust)
    Log-Message "Validating certificate..."
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertPath, $CertPassword)
    if ($cert.NotAfter -lt (Get-Date)) { throw "Certificate expired: $($cert.NotAfter)" }
    if ($cert.EnhancedKeyUsageList.ObjectId -notcontains "1.3.6.1.5.5.7.3.3") { throw "Not a code signing cert (missing EKU 1.3.6.1.5.5.7.3.3)" }  # Code signing EKU
    if (-not $cert.Verify()) { Log-Message "Cert chain not trusted (may need CA install)." "WARNING" }
    Log-Message "Certificate validation passed: $($cert.Subject), Expires: $($cert.NotAfter)"

    # Step 3: Download/Install Windows SDK if signtool/inf2cat missing
    if (-not (Get-Command signtool -ErrorAction SilentlyContinue)) {
        Log-Message "Downloading Windows SDK ISO..."
        $isoPath = "$env:TEMP\winsdk.iso"
        Invoke-WebRequest -Uri $SdkUrl -OutFile $isoPath -ErrorAction Stop
        Log-Message "Mounting SDK ISO..."
        $mount = Mount-DiskImage -ImagePath $isoPath -StorageType ISO -PassThru -ErrorAction Stop
        $driveLetter = ($mount | Get-Volume).DriveLetter
        Log-Message "Installing SDK (signtool/inf2cat) from $driveLetter..."
        Start-Process -FilePath "$driveLetter:\WinSDKSetup.exe" -ArgumentList "/features OptionId.WindowsDesktopDebuggers OptionId.WindowsDesktopSoftwareDevelopmentKit /q /norestart" -Wait -ErrorAction Stop
        Dismount-DiskImage -ImagePath $isoPath -ErrorAction Stop
        Log-Message "SDK installed. Re-run script if tools not in PATH."
    } else {
        Log-Message "Signtool found."
    }

    # Step 4: Generate .cat file with inf2cat
    Log-Message "Generating .cat file..."
    inf2cat /driver:. /os:Windows11_X64  # Adjust OS for Server 2022/2025
    if ($LASTEXITCODE -ne 0) { throw "inf2cat failed." }
    Log-Message ".cat generated."

    # Step 5: Sign .sys and .cat with signtool
    Log-Message "Signing driver..."
    signtool sign /f $CertPath /p (New-Object PSCredential "dummy", $CertPassword).GetNetworkCredential().Password /t $TimestampUrl /td sha256 /fd sha256 $SysFile
    if ($LASTEXITCODE -ne 0) { throw "Signtool sign .sys failed." }
    signtool sign /f $CertPath /p (New-Object PSCredential "dummy", $CertPassword).GetNetworkCredential().Password /t $TimestampUrl /td sha256 /fd sha256 "endpoint_monitor_driver.cat"
    if ($LASTEXITCODE -ne 0) { throw "Signtool sign .cat failed." }
    Log-Message "Signing complete."

    # Step 6: Guidance for HLK Testing/Submittal
    Log-Message "Next steps for WHCP/HVCI attestation:"
    Log-Message "1. Download HLK: https://learn.microsoft.com/windows-hardware/test/hlk/"
    Log-Message "2. Run HLK tests on driver in test VM."
    Log-Message "3. Submit to Hardware Dev Center: https://partner.microsoft.com/dashboard/hardware (requires MS partner account)."
    Log-Message "4. Once attested, driver is HVCI-ready."
} catch {
    Log-Message "Error: $_" "ERROR"
    exit 1
}

Log-Message "Script complete. Driver signed for local use; proceed to HLK for full HVCI."