<#
.SYNOPSIS
    Enforces a strict Default Deny (Block) inbound Windows Firewall posture with binary state rollback.

.DESCRIPTION
    Safely transitions the Windows Defender Firewall to a strict 'Block Inbound' default.
    Generates a full binary export of the firewall state prior to mutation.
    Includes built-in validation to ensure pre-existing explicit 'Allow' rules continue to function.

.PARAMETER Rollback
    Switch. Triggers the restoration of a previous firewall state.

.PARAMETER BackupPath
    String. The absolute path to the .wfw backup file to restore (Required if -Rollback is used).

.EXAMPLE
    # Enforce strict policy (Auto-creates backup in C:\FirewallBackups)
    .\Enforce-StrictFirewall.ps1

.EXAMPLE
    # Rollback to a known good state
    .\Enforce-StrictFirewall.ps1 -Rollback -BackupPath "C:\FirewallBackups\FW_State_20260417_1300.wfw"

.NOTES
    Enforcing a strict "Default Deny" inbound firewall posture physically neutralizes an adversary's ability to
    establish listening posts or execute lateral movement across the network. By eliminating these quiet,
    peer-to-peer pathways, we force the attacker to rely exclusively on outbound beaconing to maintain command
    and control. Pairing this inbound lockdown with the ML-driven outbound C2 sensor creates a strategic,
    unavoidable chokepoint. We operate under the "Assume Breach" paradigm: by denying horizontal movement, we
    force the adversary's traffic vertically into our behavioral analytics engine, ensuring rapid, mathematical
    detection of evasive tradecraft.

@RW
#>

param (
    [switch]$Rollback,
    [string]$BackupPath
)

$ErrorActionPreference = 'Stop'
$Host.UI.RawUI.WindowTitle = "Windows Firewall State Manager"

# ==============================================================================
# 1. ELEVATION CHECK
# ==============================================================================
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[CRITICAL FATAL] This script requires NT AUTHORITY\SYSTEM or High Integrity Administrator privileges."
    Exit
}

# ==============================================================================
# 2. ROLLBACK EXECUTION PATH
# ==============================================================================
if ($Rollback) {
    Write-Host "[*] INITIATING FIREWALL STATE ROLLBACK..." -ForegroundColor Yellow
    if ([string]::IsNullOrWhiteSpace($BackupPath) -or -not (Test-Path $BackupPath)) {
        Write-Error "[CRITICAL] Rollback aborted. Invalid or missing backup file: $BackupPath"
        Exit
    }

    try {
        Write-Host "    -> Restoring binary state from: $BackupPath" -ForegroundColor Cyan
        $importResult = netsh advfirewall import $BackupPath 2>&1
        if ($LASTEXITCODE -ne 0) { throw $importResult }

        Write-Host "[SUCCESS] Firewall state successfully rolled back to exact backup configuration." -ForegroundColor Green
    } catch {
        Write-Error "[CRITICAL FATAL] Failed to import firewall state. Exception: $($_.Exception.Message)"
    }
    Exit
}

# ==============================================================================
# 3. ENFORCEMENT EXECUTION PATH
# ==============================================================================
Write-Host "[*] INITIATING STRICT INBOUND ENFORCEMENT..." -ForegroundColor Cyan

$BackupDir = "C:\FirewallBackups"
$Timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
$ActiveBackupPath = Join-Path $BackupDir "FW_State_$Timestamp.wfw"

try {
    # --- A. BINARY STATE BACKUP ---
    if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Path $BackupDir | Out-Null }

    Write-Host "    -> [1/4] Exporting active state to $ActiveBackupPath" -ForegroundColor Gray
    $exportResult = netsh advfirewall export $ActiveBackupPath 2>&1

    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $ActiveBackupPath)) {
        throw "Binary export failed or file not created. Halting to prevent data loss."
    }

    # --- B. PRE-REQUISITE RULE PRESERVATION ---
    # Ensure Core Networking explicitly allowed so the host doesn't isolate itself
    Write-Host "    -> [2/4] Verifying Core Networking rules are explicitly permitted..." -ForegroundColor Gray
    Enable-NetFirewallRule -DisplayGroup "Core Networking" -ErrorAction SilentlyContinue

    # --- C. ENFORCE DEFAULT DENY ---
    Write-Host "    -> [3/4] Mutating DefaultInboundAction to 'Block' across all profiles..." -ForegroundColor Yellow
    Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Allow

    # --- D. STATE VALIDATION ---
    Write-Host "    -> [4/4] Validating state enforcement..." -ForegroundColor Gray
    $profiles = Get-NetFirewallProfile -Profile Any

    foreach ($profile in $profiles) {
        if ($profile.DefaultInboundAction -ne 'Block') {
            throw "State Mismatch: $($profile.Name) profile is currently set to $($profile.DefaultInboundAction). Expected: Block."
        }
    }

    Write-Host "`n[SUCCESS] Firewall is strictly locked down. All unhandled inbound traffic drops silently." -ForegroundColor Green
    Write-Host "[INFO] Pre-existing enabled Allow rules remain fully functional." -ForegroundColor Green
    Write-Host "[INFO] Backup safely stored at: $ActiveBackupPath" -ForegroundColor DarkGray

} catch {
    Write-Host "`n[!] CRITICAL ERROR DURING ENFORCEMENT" -ForegroundColor Red
    Write-Host "Exception: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "The firewall state may be inconsistent. It is highly recommended to rollback using the previous backup." -ForegroundColor Yellow
}