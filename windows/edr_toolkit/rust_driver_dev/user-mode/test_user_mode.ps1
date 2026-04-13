# PowerShell Script: Orchestrate User-Mode Testing for Endpoint Monitor Pilot App
# Author: Robert Weber
# Description: This script builds and runs the user-mode Rust pilot app that interacts with the kernel driver via IOCTL polling.
# It checks prerequisites, builds in release mode by default, runs the executable, and handles basic error checking/logging.
# Enhanced to include optional test event triggering (e.g., start notepad.exe to simulate activity).
# Run as Administrator for driver interaction.
# Prerequisites: Rust installed (cargo), kernel driver loaded (use test_kernel_driver.ps1), run from user-mode directory.

param (
    [switch]$Debug = $false,          # Build in debug mode instead of release
    [switch]$TriggerTestEvent = $true, # Automatically trigger a test event (e.g., start notepad.exe)
    [string]$LogFile = "test_log.txt" # Optional log file
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
    # Step 1: Check if in user-mode directory (Cargo.toml exists)
    if (-not (Test-Path "Cargo.toml")) {
        throw "Must run from user-mode directory containing Cargo.toml."
    }
    Log-Message "Directory check passed."

    # Step 2: Check if Rust (cargo) is installed
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw "Cargo (Rust) not found. Install via rustup.rs."
    }
    Log-Message "Rust check passed."

    # Step 3: Check if driver is loaded (optional but recommended)
    $driverLoaded = fltmc filters | Select-String "endpoint_monitor_driver"
    if (-not $driverLoaded) {
        Log-Message "Kernel driver not loaded. Load it first (e.g., via test_kernel_driver.ps1)." "WARNING"
        Read-Host "Press Enter to continue anyway or Ctrl+C to exit"
    } else {
        Log-Message "Kernel driver loaded."
    }

    # Step 4: Build the pilot app
    Log-Message "Building pilot app..."
    $buildArgs = if ($Debug) { "build" } else { "build --release" }
    cargo $buildArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed. Check cargo output."
    }
    Log-Message "Build successful."

    # Step 5: Run the executable
    Log-Message "Running pilot app..."
    $exePath = if ($Debug) { "target/debug/pilot_app.exe" } else { "target/release/pilot_app.exe" }
    if (Test-Path $exePath) {
        # Optional: Trigger test event (e.g., start notepad to simulate process creation)
        if ($TriggerTestEvent) {
            Log-Message "Triggering test event: Starting notepad.exe..."
            Start-Process notepad.exe
            Start-Sleep -Seconds 2  # Give time for event to queue
        }

        # Run app (background if needed; here foreground for logs)
        & $exePath
        if ($LASTEXITCODE -ne 0) {
            Log-Message "App run failed." "ERROR"
        } else {
            Log-Message "App completed successfully."
        }
    } else {
        throw "Executable not found at $exePath."
    }
} catch {
    Log-Message "Error: $_" "ERROR"
    exit 1
}

Log-Message "Orchestration complete. For testing: Load driver, trigger events (e.g., start notepad.exe), watch app output."