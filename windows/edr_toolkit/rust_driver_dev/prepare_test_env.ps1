# PowerShell Script: Prepare Test Environment for Rust Kernel Driver
# Author: Robert Weber
# Description: This script creates/provisions/tunes a Hyper-V VM for Windows 11 development,
# installs prerequisites inside the VM, copies the ./rust-driver directory and driver.inf to the Administrator's Desktop in the VM,
# and sets up for driver testing. Enhanced with robust error handling, logging, readiness checks, and expanded guest setup.
# Run as Administrator on a Windows host with Hyper-V enabled.
# Prerequisites: Windows 11 ISO, EWDK ISO.

param (
    [string]$VMName = "RustDriverTestVM",
    [string]$VMPath = "C:\HyperV\VMs\$VMName",
    [int64]$VMRAM = 8192MB,  # 8GB RAM
    [int]$VMCPU = 8,         # 8 vCPUs
    [string]$WindowsISO = "C:\ISOs\Windows11.iso",
    [string]$EWDKISO = "C:\ISOs\EWDK.iso",
    [string]$HostProjectPath = "$PSScriptRoot\rust-driver",  # Kernel driver dir
    [string]$HostInfPath = "$PSScriptRoot\driver.inf",       # INF file in root
    [string]$GuestProjectPath = "C:\Users\Administrator\Desktop\rust-driver",  # VM dest
    [string]$GuestInfPath = "C:\Users\Administrator\Desktop\driver.inf",       # VM dest for INF
    [string]$LogFile = "prepare_test_env_log.txt",  # Log file
    [switch]$Force = $false,  # Force recreate VM if exists
    [int]$MaxWaitSeconds = 300  # Max wait for VM readiness
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
    # Step 0: Validate paths and inputs
    if (-not (Test-Path $HostProjectPath)) {
        throw "Error: ./rust-driver directory not found at $HostProjectPath."
    }
    if (-not (Test-Path $HostInfPath)) {
        Log-Message "Warning: driver.inf not found at $HostInfPath. Skipping copy." "WARNING"
    }
    if (-not (Test-Path $WindowsISO)) { throw "Windows ISO not found at $WindowsISO." }
    if (-not (Test-Path $EWDKISO)) { throw "EWDK ISO not found at $EWDKISO." }
    Log-Message "Path validation passed."

    # Step 1: Enable Hyper-V
    $hyperVFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction Stop
    if ($hyperVFeature.State -ne 'Enabled') {
        Log-Message "Enabling Hyper-V... Reboot may be required."
        Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart -ErrorAction Stop
        Log-Message "Hyper-V enabled. Reboot if prompted, then re-run." "WARNING"
    } else {
        Log-Message "Hyper-V already enabled."
    }

    # Step 2: Check if VM exists; delete if Force
    $existingVM = Get-VM -Name $VMName -ErrorAction SilentlyContinue
    if ($existingVM) {
        if ($Force) {
            Log-Message "Force enabled: Deleting existing VM $VMName."
            Stop-VM -Name $VMName -Force -ErrorAction SilentlyContinue
            Remove-VM -Name $VMName -Force -ErrorAction Stop
            Remove-Item -Path $VMPath -Recurse -Force -ErrorAction SilentlyContinue
        } else {
            throw "VM $VMName already exists. Use -Force to recreate."
        }
    }

    # Step 3: Create VM
    Log-Message "Creating VM: $VMName with $VMRAM RAM and $VMCPU CPUs."
    New-VM -Name $VMName -MemoryStartupBytes $VMRAM -Path $VMPath -Generation 2 -NoVHD -ErrorAction Stop
    Set-VMProcessor -VMName $VMName -Count $VMCPU -ErrorAction Stop
    Set-VMFirmware -VMName $VMName -EnableSecureBoot On -SecureBootTemplate MicrosoftWindows -ErrorAction Stop
    Set-VM -Name $VMName -DynamicMemory -MemoryMinimumBytes 1024MB -MemoryMaximumBytes $VMRAM -ErrorAction Stop

    # Step 4: Create/attach VHDX
    $VHDPath = "$VMPath\$VMName.vhdx"
    if (-not (Test-Path $VHDPath)) {
        New-VHD -Path $VHDPath -SizeBytes 100GB -Dynamic -ErrorAction Stop
    }
    Add-VMHardDiskDrive -VMName $VMName -Path $VHDPath -ErrorAction Stop

    # Step 5: Attach Windows ISO
    Add-VMDvdDrive -VMName $VMName -Path $WindowsISO -ErrorAction Stop

    # Step 6: Start VM for install
    Log-Message "Starting VM for Windows install. Install manually, enable Admin account."
    Start-VM -Name $VMName -ErrorAction Stop
    Read-Host "Press Enter after install and VM shutdown"

    # Step 7: Swap ISOs
    $dvdDrive = Get-VMDvdDrive -VMName $VMName -ErrorAction Stop
    if ($dvdDrive) {
        Set-VMDvdDrive -VMName $VMName -ControllerNumber $dvdDrive.ControllerNumber -ControllerLocation $dvdDrive.ControllerLocation -Path $null -ErrorAction Stop
    }
    Add-VMDvdDrive -VMName $VMName -Path $EWDKISO -ErrorAction Stop

    # Step 8: Start VM again
    Start-VM -Name $VMName -ErrorAction Stop

    # Step 9: Expanded Guest setup script (with checks and error handling)
    $GuestSetupScript = @"
# Guest Setup Script: Run as Admin inside VM (Expanded with checks)

try {
    # Enable Test Signing
    bcdedit /set testsigning on
    if ($LASTEXITCODE -ne 0) { throw 'Failed to enable test signing.' }
    Write-Host 'Test signing enabled.'

    # Install Chocolatey
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    if ($LASTEXITCODE -ne 0) { throw 'Chocolatey install failed.' }
    Write-Host 'Chocolatey installed.'

    # Install Visual Studio Build Tools
    choco install visualstudio2022buildtools --params '--add Microsoft.VisualStudio.Workload.NativeDesktop --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64' -y
    if ($LASTEXITCODE -ne 0) { throw 'Visual Studio Build Tools install failed.' }
    Write-Host 'Visual Studio Build Tools installed.'

    # Install Rust nightly
    Invoke-WebRequest -Uri 'https://static.rust-lang.org/rustup/rustup-init.exe' -OutFile 'rustup-init.exe'
    ./rustup-init.exe -y --default-toolchain nightly
    rustup component add rust-src
    if ($LASTEXITCODE -ne 0) { throw 'Rust install failed.' }
    Write-Host 'Rust installed.'

    # Install LLVM 17.0.6
    Invoke-WebRequest -Uri 'https://github.com/llvm/llvm-project/releases/download/llvmorg-17.0.6/LLVM-17.0.6-win64.exe' -OutFile 'LLVM-17.0.6-win64.exe'
    Start-Process -FilePath 'LLVM-17.0.6-win64.exe' -ArgumentList '/S' -Wait
    if ($LASTEXITCODE -ne 0) { throw 'LLVM install failed.' }
    Write-Host 'LLVM installed.'

    # Install WinDbg
    choco install windbg -y
    if ($LASTEXITCODE -ne 0) { throw 'WinDbg install failed.' }
    Write-Host 'WinDbg installed.'

    # Install Git and cargo-make
    choco install git -y
    cargo install --locked cargo-make --no-default-features --features tls-native
    if ($LASTEXITCODE -ne 0) { throw 'Git/cargo-make install failed.' }
    Write-Host 'Git and cargo-make installed.'

    # Create Desktop folder
    New-Item -Path 'C:\Users\Administrator\Desktop' -ItemType Directory -Force

    # Reboot VM
    Restart-Computer -Force
} catch {
    Write-Host "Guest Setup Error: $_"
    exit 1
}
"@

    $GuestScriptPath = "$env:TEMP\GuestSetup.ps1"
    $GuestSetupScript | Out-File -FilePath $GuestScriptPath -Encoding utf8 -ErrorAction Stop

    # Step 10: Enable guest services and copy files
    Enable-VMIntegrationService -VMName $VMName -Name "Guest Service Interface" -ErrorAction Stop

    $VMAdminUser = "Administrator"
    $VMAdminPass = ConvertTo-SecureString "YourVMPassword" -AsPlainText -Force
    $Cred = New-Object System.Management.Automation.PSCredential ($VMAdminUser, $VMAdminPass)

    # Wait for VM readiness (loop with heartbeat check)
    $waited = 0
    while ((Get-VM -Name $VMName -ErrorAction Stop).Heartbeat -ne "OkApplicationsHealthy" -and $waited -lt $MaxWaitSeconds) {
        Start-Sleep -Seconds 10
        $waited += 10
        Log-Message "Waiting for VM readiness... ($waited seconds)"
    }
    if ($waited -ge $MaxWaitSeconds) { throw "VM not ready after $MaxWaitSeconds seconds." }

    # Copy files with error checks
    Copy-VMFile -VMName $VMName -SourcePath $GuestScriptPath -DestinationPath "C:\GuestSetup.ps1" -CreateFullPath -FileSource Host -Force -ErrorAction Stop
    Copy-VMFile -VMName $VMName -SourcePath $HostProjectPath -DestinationPath $GuestProjectPath -CreateFullPath -FileSource Host -Force -Recurse -ErrorAction Stop
    if (Test-Path $HostInfPath) {
        Copy-VMFile -VMName $VMName -SourcePath $HostInfPath -DestinationPath $GuestInfPath -CreateFullPath -FileSource Host -Force -ErrorAction Stop
    }

    # Step 11: Run guest setup with session error handling
    $Session = New-PSSession -VMName $VMName -Credential $Cred -ErrorAction Stop
    Invoke-Command -Session $Session -ScriptBlock { Set-ExecutionPolicy RemoteSigned -Scope Process; C:\GuestSetup.ps1 } -ErrorAction Stop
    Remove-PSSession $Session -ErrorAction Stop

    Log-Message "VM setup complete."
} catch {
    Log-Message "Error: $_" "ERROR"
    # Cleanup on error (optional)
    if ($existingVM -and $Force) {
        Stop-VM -Name $VMName -Force -ErrorAction SilentlyContinue
        Remove-VM -Name $VMName -Force -ErrorAction SilentlyContinue
    }
    exit 1
}