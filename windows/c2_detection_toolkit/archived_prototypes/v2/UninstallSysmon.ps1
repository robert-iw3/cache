#Requires -RunAsAdministrator

<#
.SYNOPSIS
    PowerShell script to uninstall Sysmon and rollback configuration.
.DESCRIPTION
    Stops the Sysmon service, uninstalls Sysmon, clears the Sysmon event log, removes registry entries, and cleans up temporary files.
.EXAMPLE
    .\UninstallSysmon.ps1
.NOTES
    Author: Robert Weber
#>

$sysmonExePath = "C:\Windows\Sysmon64.exe"  # Default install path; adjust if custom
$sysmonLogName = "Microsoft-Windows-Sysmon/Operational"
$sysmonRegKey = "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv"

try {
    # Stop Sysmon service if running
    $sysmonService = Get-Service -Name Sysmon* -ErrorAction SilentlyContinue
    if ($sysmonService) {
        Stop-Service -Name $sysmonService.Name -Force
        Write-Output "Sysmon service stopped."
    }

    # Uninstall Sysmon
    if (Test-Path $sysmonExePath) {
        & $sysmonExePath -u force
        Write-Output "Sysmon uninstalled."
    } else {
        Write-Warning "Sysmon executable not found at $sysmonExePath. Uninstall may be incomplete."
    }

    # Clear Sysmon event log
    try {
        wevtutil cl $sysmonLogName
        Write-Output "Sysmon event log cleared."
    } catch {
        Write-Warning "Failed to clear Sysmon event log: $($_.Exception.Message)"
    }

    # Remove Sysmon registry entries
    if (Test-Path $sysmonRegKey) {
        Remove-Item -Path $sysmonRegKey -Recurse -Force
        Write-Output "Sysmon registry entries removed."
    } else {
        Write-Output "No Sysmon registry entries found to remove."
    }

    # Clean up temp directory if exists
    $tempDir = "$env:TEMP\SysmonInstall"
    if (Test-Path $tempDir) {
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Output "Temporary installation files cleaned up."
    }

    Write-Output "Uninstallation complete. Reboot recommended to clear any remaining drivers."
} catch {
    Write-Error "Uninstall failed: $($_.Exception.Message)"
}