# PowerShell Script: Orchestrate Kernel Driver Testing for Endpoint Monitor
# Author: Robert Weber
# Description: Builds, signs, loads/unloads, and tests the Rust kernel driver.
# Run as Administrator in EWDK developer prompt (LaunchBuildEnv.cmd).
# Prerequisites: EWDK mounted, Rust nightly, LLVM 17.0.6, test signing enabled (bcdedit /set testsigning on).
# Assumes driver.inf in project root; outputs to target/release.

param (
    [switch]$Clean = $false,  # Clean build artifacts
    [switch]$UnloadOnly = $false,  # Just unload driver
    [string]$DriverName = "endpoint_monitor_driver",  # .sys name
    [string]$InfPath = "../driver.inf",  # Relative to rust-driver
    [string]$LogFile = "kernel_test_log.txt"
)

# Function for logging
function Log-Message {
    param ([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry
    Add-Content -Path $LogFile -Value $logEntry
}

try {
    # Step 1: Check EWDK environment
    if (-not $env:WDKContentRoot) {
        throw "Run in EWDK developer prompt (LaunchBuildEnv.cmd)."
    }
    Log-Message "EWDK environment detected."

    # Step 2: Optional clean
    if ($Clean) {
        Log-Message "Cleaning artifacts..."
        cargo clean
        if ($LASTEXITCODE -ne 0) { throw "Clean failed." }
    }

    # Step 3: Build driver
    Log-Message "Building kernel driver..."
    cargo build --release --features="registry,network"
    if ($LASTEXITCODE -ne 0) { throw "Build failed." }
    $sysPath = "target/release/$DriverName.dll"
    Rename-Item -Path $sysPath -NewName "$DriverName.sys" -Force
    $sysPath = "target/release/$DriverName.sys"
    Log-Message "Build successful: $sysPath"

    # Step 4: Test signing (self-signed cert example; use EV for prod)
    Log-Message "Signing driver..."
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=TestCert"
    Export-Certificate -Cert $cert -FilePath "testcert.cer"
    signtool sign /f "testcert.cer" /t http://timestamp.digicert.com /td sha256 /fd sha256 $sysPath
    if ($LASTEXITCODE -ne 0) { throw "Signing failed." }
    Log-Message "Signing successful."

    if ($UnloadOnly) {
        # Step 5: Unload only
        Log-Message "Unloading driver..."
        fltmc unload $DriverName
        if ($LASTEXITCODE -ne 0) { Log-Message "Unload failed." "WARNING" }
        Log-Message "Unload complete."
        return
    }

    # Step 6: Install via INF (for minifilter)
    Log-Message "Installing via INF..."
    pnputil /add-driver $InfPath /install
    if ($LASTEXITCODE -ne 0) { throw "INF install failed." }
    Log-Message "INF install successful."

    # Step 7: Load driver
    Log-Message "Loading driver..."
    fltmc load $DriverName
    if ($LASTEXITCODE -ne 0) { throw "Load failed." }
    Log-Message "Load successful."

    # Step 8: Basic verification (check if loaded, simulate events)
    Log-Message "Verifying driver..."
    $loaded = fltmc filters | Select-String $DriverName
    if ($loaded) {
        Log-Message "Driver loaded successfully."
        # Simulate test: e.g., create a process/file to trigger callbacks
        Start-Process notepad.exe  # Triggers process callback
        Start-Sleep -Seconds 2
        Log-Message "Simulated events triggered."
    } else {
        throw "Verification failed: Driver not loaded."
    }

    # Step 9: Unload driver
    Log-Message "Unloading driver..."
    fltmc unload $DriverName
    if ($LASTEXITCODE -ne 0) { throw "Unload failed." }
    Log-Message "Unload successful."
} catch {
    Log-Message "Error: $_" "ERROR"
    exit 1
}

Log-Message "Kernel driver test complete."