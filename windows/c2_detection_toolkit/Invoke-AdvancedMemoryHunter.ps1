<#
.SYNOPSIS
    APT Memory Scanner & Heuristic Hunter
.DESCRIPTION
    An evasion-aware memory forensics engine that uses P/Invoke Windows API calls
    to read process memory space dynamically without dropping external binaries.

    Advanced Tradecraft Heuristics to detect custom, zero-day C2 frameworks:
    1. Unbacked Thread Execution (Volatile RAM)
    2. Abnormal RWX Module Stomping (Memory Protection Anomalies)
    3. Reflective DLL Injection (Hidden MZ Headers)
    4. Direct Syscall Stubs (EDR Evasion / Hell's Gate / Halo's Gate)
    5. Raw x64 Shellcode Prologues

.NOTES
    Author: Robert Weber
    Version: 5.0
#>
#Requires -RunAsAdministrator

param (
    [int[]]$ProcessIds = $null,
    [switch]$ScanAll,
    [string]$ArtifactDirectory = "C:\Temp\DFIR_Collect",
    [switch]$Orchestrated # <-- REQUIRED FOR DUAL MODE
)

# =================================================================
# DUAL-MODE UI
# =================================================================
$ESC = [char]27
$cRed    = "$ESC[91;40m"
$cCyan   = "$ESC[96;40m"
$cGreen  = "$ESC[92;40m"
$cDark   = "$ESC[90;40m"
$cYellow = "$ESC[93;40m"
$cReset  = "$ESC[0m$ESC[40m"

if (-not $Orchestrated) {
    $Host.UI.RawUI.WindowTitle = "V5 DFIR // ADVANCED MEMORY HUNTER"
    [Console]::CursorVisible = $false
    Clear-Host
    [Console]::SetCursorPosition(0, 6) # Reserve 6 lines for Standalone HUD
}

function Update-UI([int]$Progress, [int]$Threats, [string]$ActionText) {
    if ($Orchestrated) {
        # Stream up to Master Orchestrator
        Write-Output "[HUD]|$Progress|$Threats|$ActionText"
    } else {
        # Draw Standalone HUD
        $curLeft = [Console]::CursorLeft; $curTop = [Console]::CursorTop
        [Console]::SetCursorPosition(0, 0)

        # --- DYNAMIC PADDING MATH ---
        $EngineName = "ADVANCED MEMORY FORENSICS ENGINE"
        $TitleStr   = "  ⚡ C2 HUNTER V5  | $EngineName"
        $StatsStr   = "  Progress : $Progress% | Detections: $Threats"

        # Manage Action text length to prevent line-wrapping
        if ($ActionText.Length -gt 70) { $ActionText = $ActionText.Substring(0, 67) + "..." }
        $ActionStr  = "  Action   : $ActionText"

        # Calculate exact padding for an 86-character interior width
        $PadTitle  = " " * [math]::Max(0, (86 - $TitleStr.Length))
        $PadStats  = " " * [math]::Max(0, (86 - $StatsStr.Length))
        $PadAction = " " * [math]::Max(0, (86 - $ActionStr.Length))

        # --- RENDER DASHBOARD ---
        Write-Host "$cCyan╔══════════════════════════════════════════════════════════════════════════════════════╗$cReset"
        Write-Host "$cCyan║$cReset  $cRed⚡ C2 HUNTER V5$cReset | $EngineName$PadTitle$cCyan║$cReset"
        Write-Host "$cCyan╠══════════════════════════════════════════════════════════════════════════════════════╣$cReset"
        Write-Host "$cCyan║$cReset  Progress : $cCyan$Progress%$cReset | Detections: $cRed$Threats$cReset$PadStats$cCyan║$cReset"
        Write-Host "$cCyan║$cReset  Action   : $cYellow$ActionText$cReset$PadAction$cCyan║$cReset"
        Write-Host "$cCyan╚══════════════════════════════════════════════════════════════════════════════════════╝$cReset"

        if ($curTop -lt 6) { $curTop = 6 }
        [Console]::SetCursorPosition($curLeft, $curTop)
    }
}

$ErrorActionPreference = "SilentlyContinue"
if (-not (Test-Path $ArtifactDirectory)) { New-Item -Path $ArtifactDirectory -ItemType Directory | Out-Null }
if ([IntPtr]::Size -ne 8) { Write-Host "  $cRed[!] CRITICAL ERROR: 64-bit host required.$cReset"; exit }

# ---------------------------------------------------------
# 1. P/INVOKE ENGINE
# ---------------------------------------------------------
$Win32API = @"
using System;
using System.Runtime.InteropServices;

public class MemHunter {
    [Flags] public enum ProcessAccessFlags : uint { QueryInformation = 0x0400, VMRead = 0x0010 }

    public const uint PAGE_NOACCESS = 0x01;
    public const uint PAGE_EXECUTE = 0x10;
    public const uint PAGE_EXECUTE_READ = 0x20;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint PAGE_EXECUTE_WRITECOPY = 0x80;

    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_PRIVATE = 0x20000;
    public const uint MEM_IMAGE = 0x1000000;
    public const uint MEM_MAPPED = 0x40000;

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, ulong dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    // Fast Byte Pattern Matcher
    public static bool FastMatch(byte[] data, int validLength, byte[] pattern) {
        if (pattern.Length == 0 || validLength == 0 || validLength < pattern.Length) return false;
        for (int i = 0; i <= validLength - pattern.Length; i++) {
            bool match = true;
            for (int j = 0; j < pattern.Length; j++) {
                if (data[i + j] != pattern[j]) { match = false; break; }
            }
            if (match) return true;
        }
        return false;
    }

    // Wildcard Byte Pattern Matcher (Uses Int16 where -1 is a wildcard)
    public static bool WildcardMatch(byte[] data, int validLength, short[] pattern) {
        if (pattern.Length == 0 || validLength == 0 || validLength < pattern.Length) return false;
        for (int i = 0; i <= validLength - pattern.Length; i++) {
            bool match = true;
            for (int j = 0; j < pattern.Length; j++) {
                if (pattern[j] != -1 && data[i + j] != (byte)pattern[j]) { match = false; break; }
            }
            if (match) return true;
        }
        return false;
    }
}
"@
Add-Type -TypeDefinition $Win32API

# ---------------------------------------------------------
# 2. C2 PROFILE SIGNATURES (Raw Bytes)
# ---------------------------------------------------------
$Signatures = @(
    # Cobalt Strike Sleep Mask / Obfuscation Routines (very stable even with custom profiles)
    @{
        Name = "YARA: Cobalt Strike (Sleep Mask x64 - b54b94ac)";
        Pattern = [short[]](0x4C, 0x8B, 0x53, 0x08, 0x45, 0x8B, 0x0A, 0x45, 0x8B, 0x5A, 0x04, 0x4D, 0x8D, 0x52, 0x08, 0x45, 0x85, 0xC9, 0x75, 0x05, 0x45, 0x85, 0xDB, 0x74, 0x33, 0x45, 0x3B, 0xCB, 0x73, 0xE6, 0x49, 0x8B, 0xF9, 0x4C, 0x8B, 0x03)
    },
    @{
        Name = "YARA: Cobalt Strike (Sleep Mask SMB/TCP Variant)";
        Pattern = [short[]](0x4C, 0x8B, 0x07, 0xB8, 0x4F, 0xEC, 0xC4, 0x4E, 0x41, 0xF7, 0xE1, 0x41, 0x8B, 0xC1, 0xC1, 0xEA, 0x02, 0x41, 0xFF, 0xC1, 0x6B, 0xD2, 0x0D, 0x2B, 0xC2, 0x8A, 0x4C, 0x38, 0x10, 0x42, 0x30, 0x0C, 0x06, 0x48)
    },

    # Classic x64 Raw Shellcode / PIC Loader prologue (MSF, CS stageless, Sliver, Havoc, Mythic, custom/zero-day loaders)
    @{
        Name = "YARA: Raw Shellcode Loader (Stack Align + Call)";
        Pattern = [short[]](0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, -1, -1, -1, -1)
    },

    # Direct Syscall Stub (Hell's Gate / Tartarus Gate / SysWhispers / common EDR evasion - stable across frameworks)
    @{
        Name = "YARA: Direct Syscall Execution Stub";
        Pattern = [short[]](0x4C, 0x8B, 0xD1, 0xB8, -1, -1, -1, -1, 0x0F, 0x05)
    },

    # Meterpreter / MSF x64 initialization (common in Metasploit and many custom implants)
    @{
        Name = "YARA: Meterpreter (x64 Initialization)";
        Pattern = [short[]](0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, -1, 0x48, 0x83, 0xE4, 0xF0)
    },

    # Cobalt Strike Reflective Loader (MZ + loader stub - 29374056 / f0b627fc variants)
    @{
        Name = "YARA: Cobalt Strike (Reflective Loader MZ Stub x64)";
        Pattern = [short[]](0x4D, 0x5A, 0x41, 0x52, 0x55, 0x48, 0x89, 0xE5, 0x48, 0x81, 0xEC, 0x20, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x1D, -1, -1, -1, -1, 0x48, 0x81, 0xC3, -1, -1, 0x00, 0x00, 0xFF, 0xD3)
    },

    # Havoc Demon (DEADBEEF magic header - extremely stable in memory and packets)
    @{
        Name = "YARA: Havoc Demon (DEADBEEF Magic)";
        Pattern = [short[]](0xDE, 0xAD, 0xBE, 0xEF)
    },

    # Generic API Hashing / Resolution Stub (common in Havoc Demon, many custom loaders, and modern C2)
    # (adapted from public Havoc analysis - DJB2-style hashing routines)
    @{
        Name = "YARA: Havoc / Generic C2 (API Hashing Routine)";
        Pattern = [short[]](0x53, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x89, 0xD8, 0x48, 0xC1, 0xE8, 0x20, 0x48, 0x89, 0xC2, 0x48, 0xC1, 0xEA, 0x10)
    },

    # Havoc Demon Beacon Packet Structure (DEADBEEF magic + AgentID + DEMON_INIT command 0x0063)
    # Extremely stable in memory and network buffers (Immersive Labs / Havoc forensics)
    @{
        Name = "YARA: Havoc Demon (Beacon INIT Packet Structure)";
        Pattern = [short[]](0xDE, 0xAD, 0xBE, 0xEF, -1, -1, -1, -1, 0x00, 0x63)
    },

    # Cobalt Strike Beacon Config / Formatting Strings (Elastic rules - appear in beacon metadata & logging)
    # These survive most malleable profiles and are present in memory even after obfuscation
    @{ Name = "String: Cobalt Strike (Beacon Config - Date Format)"; Pattern = [short[]][byte[]][char[]]"%02d/%02d/%02d %02d:%02d:%02d" }
    @{ Name = "String: Cobalt Strike (Beacon Config - Process Format)"; Pattern = [short[]][byte[]][char[]]"%s as %s\\%s: %d" }

    # Generic Beacon Metadata / Named Pipe Artifacts (SMB beacons, common across CS/Havoc)
    @{ Name = "String: C2 Beacon (Named Pipe - msagent)"; Pattern = [short[]][byte[]][char[]]"\\pipe\\msagent_" }
    @{ Name = "String: C2 Beacon (Named Pipe - status)"; Pattern = [short[]][byte[]][char[]]"\\pipe\\status_" }

    # ====================== LEGACY + MODERN C2 STRING / ARTIFACT SIGNATURES ======================
    # Converted to short[] for WildcardMatch compatibility. Still highly effective when present.

    # --- Modern Commercial / Open-Source C2 ---
    @{ Name = "String: Cobalt Strike (Reflective DLL)"; Pattern = [short[]]([System.Text.Encoding]::ASCII.GetBytes("beacon.x64.dll")) }
    @{ Name = "String: Cobalt Strike (ReflectiveLoader)"; Pattern = [short[]]([System.Text.Encoding]::ASCII.GetBytes("ReflectiveLoader")) }
    @{ Name = "String: Sliver C2 (Protobuf Namespace)"; Pattern = [short[]]([System.Text.Encoding]::ASCII.GetBytes("sliverpb")) }
    @{ Name = "String: Sliver C2 (Github Path)"; Pattern = [short[]]([System.Text.Encoding]::ASCII.GetBytes("github.com/bishopfox/sliver")) }
    @{ Name = "String: Sliver C2 (ChaCha20)"; Pattern = [short[]]([System.Text.Encoding]::ASCII.GetBytes("chacha20poly1305")) }  # Go crypto artifact
    @{ Name = "String: Havoc C2 (Demon Loader)"; Pattern = [short[]]([System.Text.Encoding]::ASCII.GetBytes("Demon.x64.dll")) }
    @{ Name = "String: Brute Ratel (Badger Wide)"; Pattern = [short[]]([System.Text.Encoding]::Unicode.GetBytes("B.R.u.t.e")) }
    @{ Name = "String: Brute Ratel (Chkin)"; Pattern = [short[]]([System.Text.Encoding]::ASCII.GetBytes("`"chkin`":")) }
    @{ Name = "String: Nighthawk C2 (Artifact)"; Pattern = [short[]]([System.Text.Encoding]::ASCII.GetBytes("Nighthawk.x64.dll")) }
    @{ Name = "String: Mythic C2 (Apollo Core)"; Pattern = [short[]]([System.Text.Encoding]::ASCII.GetBytes("Apollo.Core.dll")) }
    @{ Name = "String: Mythic C2 (Poseidon)"; Pattern = [short[]]([System.Text.Encoding]::ASCII.GetBytes("poseidon/pkg/profiles")) }
    @{ Name = "String: Covenant (Grunt Models)"; Pattern = [short[]]([System.Text.Encoding]::ASCII.GetBytes("Grunt.Models")) }
    @{ Name = "String: Merlin (Go Agent)"; Pattern = [short[]]([System.Text.Encoding]::ASCII.GetBytes("Ne0nd0g/merlin")) }
    @{ Name = "String: Ninja C2 (Loader)"; Pattern = [short[]]([System.Text.Encoding]::ASCII.GetBytes("Ninja.x64.dll")) }
    @{ Name = "String: Caldera (Sandcat)"; Pattern = [short[]]([System.Text.Encoding]::ASCII.GetBytes("sandcat.go")) }
    @{ Name = "String: Deimos C2"; Pattern = [short[]]([System.Text.Encoding]::ASCII.GetBytes("DeimosC2")) }
    @{ Name = "String: PoshC2 (Default)"; Pattern = [short[]]([System.Text.Encoding]::ASCII.GetBytes("PoshC2_Project")) }
    @{ Name = "String: Metasploit (Meterpreter)"; Pattern = [short[]]([System.Text.Encoding]::ASCII.GetBytes("metsrv.dll")) }

    # --- Commodity RATs & Botnets ---
    @{ Name = "String: AsyncRAT"; Pattern = [short[]]([System.Text.Encoding]::ASCII.GetBytes("AsyncRAT.Properties")) }
    @{ Name = "String: Remcos RAT"; Pattern = [short[]]([System.Text.Encoding]::ASCII.GetBytes("Remcos-Pro")) }
    @{ Name = "String: QuasarRAT"; Pattern = [short[]]([System.Text.Encoding]::ASCII.GetBytes("Quasar.Client")) }
    @{ Name = "String: NanoCore"; Pattern = [short[]]([System.Text.Encoding]::ASCII.GetBytes("NanoCore.ClientPlugin")) }
    @{ Name = "String: NjRAT (Version Tag)"; Pattern = [short[]]([System.Text.Encoding]::ASCII.GetBytes("njRAT v")) }

    # --- Nation-State / APT / Ransomware Brokers ---
    @{ Name = "Magic: PlugX (PXJV Header)"; Pattern = [short[]](0x50, 0x58, 0x4A, 0x56) }
    @{ Name = "String: ShadowPad (Mutex)"; Pattern = [short[]]([System.Text.Encoding]::ASCII.GetBytes("ShadowPad_Mutex")) }
    @{ Name = "String: Qakbot/Qbot"; Pattern = [short[]]([System.Text.Encoding]::ASCII.GetBytes("qbot_version")) }
    @{ Name = "String: IcedID (Core DLL)"; Pattern = [short[]]([System.Text.Encoding]::ASCII.GetBytes("icedid.dll")) }
    @{ Name = "String: Trickbot (Loader)"; Pattern = [short[]]([System.Text.Encoding]::ASCII.GetBytes("trickbot_loader")) }
    @{ Name = "String: DarkGate (Strings)"; Pattern = [short[]]([System.Text.Encoding]::ASCII.GetBytes("DarkGate")) }
)

# --- PHASE 2: GC THRASH MITIGATION (BUFFER REUSE) ---
# Pre-allocate a single 50MB buffer to prevent PowerShell's Garbage Collector from freezing
$MaxBufferSize = 52428800
$SharedBuffer = New-Object byte[] $MaxBufferSize

if ($ScanAll) { $Processes = Get-Process }
elseif ($ProcessIds) { $Processes = Get-Process -Id $ProcessIds } else { exit }

# ---------------------------------------------------------
# 3. APT MEMORY ENUMERATION ENGINE
# ---------------------------------------------------------
$Findings = @()
$ScanCount = 0; $TotalProcs = $Processes.Count; $ThreatCount = 0

foreach ($Proc in $Processes) {
    $ScanCount++
    $pct = if ($TotalProcs -gt 0) { [math]::Round(($ScanCount / $TotalProcs) * 100) } else { 0 }

    Update-UI $pct $ThreatCount "Scanning: $($Proc.Name) (PID: $($Proc.Id))"

    # --- PHASE 2: .NET JIT FALSE POSITIVE SUPPRESSION ---
    $isManaged = $false
    try {
        if ($Proc.Modules.ModuleName -match "clr\.dll|mscorlib\.dll|coreclr\.dll") {
            $isManaged = $true
        }
    } catch {} # Ignore access denied on elevated PIDs

    $ThreadStarts = @{}
    try { foreach ($t in $Proc.Threads) { $ThreadStarts[$t.StartAddress.ToInt64()] = $t.Id } } catch {}

    $hProcess = [MemHunter]::OpenProcess([MemHunter+ProcessAccessFlags]::QueryInformation -bor [MemHunter+ProcessAccessFlags]::VMRead, $false, $Proc.Id)
    if ($hProcess -eq [IntPtr]::Zero) { continue }

    $Address = [IntPtr]::Zero
    $MemInfo = New-Object MemHunter+MEMORY_BASIC_INFORMATION
    $StructSize = [System.Runtime.InteropServices.Marshal]::SizeOf($MemInfo)

    while ([MemHunter]::VirtualQueryEx($hProcess, $Address, [ref]$MemInfo, [uint64]$StructSize) -ne 0) {

        if ($MemInfo.State -eq [MemHunter]::MEM_COMMIT -and $MemInfo.Protect -ne [MemHunter]::PAGE_NOACCESS) {

            $BaseInt = $MemInfo.BaseAddress.ToInt64()
            $EndInt = $BaseInt + $MemInfo.RegionSize.ToInt64()

            $isExecutable = ($MemInfo.Protect -eq [MemHunter]::PAGE_EXECUTE_READWRITE -or $MemInfo.Protect -eq [MemHunter]::PAGE_EXECUTE_READ -or $MemInfo.Protect -eq [MemHunter]::PAGE_EXECUTE -or $MemInfo.Protect -eq [MemHunter]::PAGE_EXECUTE_WRITECOPY)
            $isPrivate = ($MemInfo.Type -eq [MemHunter]::MEM_PRIVATE -or $MemInfo.Type -eq [MemHunter]::MEM_MAPPED)

            # --- HEURISTIC 1: UNBACKED THREAD EXECUTION ---
            # Excludes managed processes (.NET/Java) which legitimately execute from private JIT memory.
            if ($MemInfo.Type -ne [MemHunter]::MEM_IMAGE -and -not $isManaged) {
                foreach ($tAddr in $ThreadStarts.Keys) {
                    if ($tAddr -ge $BaseInt -and $tAddr -lt $EndInt) {
                        $ThreatCount++
                        $tid = $ThreadStarts[$tAddr]
                        Write-Output "  $cRed[!] DETECT:$cReset $($Proc.Name) (PID: $($Proc.Id), TID: $tid) -> $cYellow`Unbacked Memory Thread`$cReset"
                        $Findings += [PSCustomObject]@{
                            Process = $Proc.Name; PID = $Proc.Id; Signature = "Unbacked Thread (TID: $tid)"
                            Address = "0x$($MemInfo.BaseAddress.ToString("X"))"; MatchData = "Thread executing outside valid disk-backed image"
                        }
                    }
                }
            }

            # Only read memory if it triggers secondary heuristics OR is executable
            if (($isExecutable -and $isPrivate) -or ($isExecutable -and $MemInfo.Type -eq [MemHunter]::MEM_IMAGE)) {

                # Cap the read size to the Shared Buffer limit
                $ReadSize = if ($MemInfo.RegionSize.ToInt32() -gt $MaxBufferSize) { $MaxBufferSize } else { $MemInfo.RegionSize.ToInt32() }
                $BytesRead = [IntPtr]::Zero

                # Read into the reusable $SharedBuffer (Phase 2 GC Optimization)
                if ([MemHunter]::ReadProcessMemory($hProcess, $MemInfo.BaseAddress, $SharedBuffer, $ReadSize, [ref]$BytesRead)) {

                    # --- HEURISTIC 2: MODULE STOMPING (ABNORMAL RWX ON IMAGE) ---
                    if ($MemInfo.Type -eq [MemHunter]::MEM_IMAGE -and $MemInfo.Protect -eq [MemHunter]::PAGE_EXECUTE_READWRITE -and -not $isManaged) {
                        # Exclude hardware bloatware (ASUS/Intel/NVIDIA/Realtek) which legitimately use RWX packers
                        if ($Proc.Name -notmatch "(?i)Asus|Intel|Armoury|igfx|NVDisplay|nvcontainer|RtkAud") {
                            $ThreatCount++
                            Write-Output "  $cRed[!] DETECT:$cReset $($Proc.Name) (PID: $($Proc.Id)) -> $cYellow`Module Stomping (RWX Anomaly)`$cReset"
                            $Findings += [PSCustomObject]@{
                                Process = $Proc.Name; PID = $Proc.Id; Signature = "Module Stomping"
                                Address = "0x$($MemInfo.BaseAddress.ToString("X"))"; MatchData = "Abnormal PAGE_EXECUTE_READWRITE on disk-backed image"
                            }
                        }
                    }

                    # --- HEURISTIC 3: REFLECTIVE DLL INJECTION ---
                    if ($isPrivate -and $isExecutable -and $SharedBuffer[0] -eq 0x4D -and $SharedBuffer[1] -eq 0x5A) {
                        $ThreatCount++
                        Write-Output "  $cRed[!] DETECT:$cReset $($Proc.Name) (PID: $($Proc.Id)) -> $cYellow`Reflective DLL (Hidden MZ Header)`$cReset"
                        $Findings += [PSCustomObject]@{
                            Process = $Proc.Name; PID = $Proc.Id; Signature = "Reflective DLL"
                            Address = "0x$($MemInfo.BaseAddress.ToString("X"))"; MatchData = "Hidden MZ Header found in MEM_PRIVATE executable RAM"
                        }
                    }

                    # --- HEURISTIC 4: DIRECT SYSCALLS IN PRIVATE MEMORY (EDR EVASION) ---
                    # 4C 8B D1 = mov r10, rcx
                    # B8 ?? ?? ?? ?? = mov eax, [Syscall Number]
                    # 0F 05 = syscall
                    if ($isPrivate -and $isExecutable) {
                        # -1 represents a wildcard (??) byte
                        $SyscallStub = [short[]](0x4C, 0x8B, 0xD1, 0xB8, -1, -1, -1, -1, 0x0F, 0x05)
                        if ([MemHunter]::WildcardMatch($SharedBuffer, $ReadSize, $SyscallStub)) {
                            $ThreatCount++
                            Write-Output "  $cRed[!] DETECT:$cReset $($Proc.Name) (PID: $($Proc.Id)) -> $cYellow`Direct Syscall Stub (EDR Evasion)`$cReset"
                            $Findings += [PSCustomObject]@{
                                Process = $Proc.Name; PID = $Proc.Id; Signature = "Direct Syscall Stub"
                                Address = "0x$($MemInfo.BaseAddress.ToString("X"))"; MatchData = "Syscall signature match in unbacked memory (Hell's/Tartarus Gate)"
                            }
                        }
                    }

                    # --- HEURISTIC 5: RAW SHELLCODE PROLOGUES ---
                    # If memory is executable and starts directly with assembly stack alignment (FC 48 83 E4 F0)
                    # instead of an MZ header, it is highly likely to be a custom position-independent shellcode loader.
                    if ($isPrivate -and $isExecutable -and $SharedBuffer[0] -eq 0xFC -and $SharedBuffer[1] -eq 0x48 -and $SharedBuffer[2] -eq 0x83) {
                        $ThreatCount++
                        Write-Output "  $cRed[!] DETECT:$cReset $($Proc.Name) (PID: $($Proc.Id)) -> $cYellow`Raw x64 Shellcode Prologue`$cReset"
                        $Findings += [PSCustomObject]@{
                            Process = $Proc.Name; PID = $Proc.Id; Signature = "x64 Shellcode Prologue"
                            Address = "0x$($MemInfo.BaseAddress.ToString("X"))"; MatchData = "FC 48 83 (cld; and rsp) standard injection prologue"
                        }
                    }

                    # --- C2 SIGNATURE MATCHING ---
                    foreach ($Sig in $Signatures) {
                        if ([MemHunter]::WildcardMatch($SharedBuffer, $ReadSize, $Sig.Pattern)) {
                            $ThreatCount++
                            Write-Output "  $cRed[!] DETECT:$cReset $($Proc.Name) (PID: $($Proc.Id)) -> $cYellow$($Sig.Name)$cReset"
                            $Findings += [PSCustomObject]@{
                                Process = $Proc.Name; PID = $Proc.Id; Signature = $Sig.Name
                                Address = "0x$($MemInfo.BaseAddress.ToString("X"))"; MatchData = "Confirmed YARA Match"
                            }
                        }
                    }
                }
            }
        }
        # Advance memory pointer mathematically
        $Address = [IntPtr]($MemInfo.BaseAddress.ToInt64() + $MemInfo.RegionSize.ToInt64())
    }
    [MemHunter]::CloseHandle($hProcess) | Out-Null
}

if ($Findings.Count -gt 0) {
    $CsvPath = Join-Path $ArtifactDirectory "advanced_memory_injections.csv"
    $Findings | Export-Csv -Path $CsvPath -NoTypeInformation
}

Update-UI 100 $ThreatCount "Memory Forensics Complete."
if (-not $Orchestrated) { [Console]::CursorVisible = $true }