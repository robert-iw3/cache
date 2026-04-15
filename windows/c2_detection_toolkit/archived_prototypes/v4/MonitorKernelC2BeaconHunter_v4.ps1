<#
.SYNOPSIS
    Windows Kernel C2 Beacon Hunter v4.0 — Hybrid C#/Pwsh
.DESCRIPTION
    A high-performance, real-time Command and Control (C2) detection engine.
    It injects Microsoft.Diagnostics.Tracing.TraceEvent directly into RAM via embedded C#
    to monitor live kernel ETW events, bypassing heavy telemetry trace files.

    Architecture Flow:
      1. Dynamic Pre-Loader: Fetches the correct TraceEvent library based on the host's .NET runtime.
      2. C# Engine: Parses the high-volume ETW firehose at lightning speed, pre-filtering noise.
      3. Native Byte Scanner: Manually extracts IPs/Ports from memory if standard decoders fail.
      4. Hybrid State Manager: Tracks active flows in RAM and flushes dormant flows to a self-grooming
         NTFS JSON database to detect "Low and Slow" beacons across days or system reboots.
      5. ML Daemon: Forwards 4D matrices to BeaconML.py via STDIN for lock-free DBSCAN clustering.

.NOTES
    Author: Robert Weber
    Version: 4.0

    To see the microscopic, millisecond-by-millisecond data flow for debugging, pass the switch when starting the monitor script:
    .\MonitorKernelC2BeaconHunter_v4.ps1 -EnableDiagnostics
#>
#Requires -RunAsAdministrator

# ====================== CONFIGURATION & PARAMETERS ======================
param (
    [string]$OutputPath = "C:\Temp\C2KernelMonitoring_v4.jsonl",
    [int]$BatchAnalysisIntervalSeconds = 30,
    [int]$MinSamplesForML = 3,
    [string]$PythonPath = "python",
    [string]$MLScriptPath = "BeaconML.py",
    [switch]$EnableDiagnostics,
    [string[]]$DnsExclusions = @(".arpa", ".local", ".lan", "trendmicro.com", "windows.com", "visualstudio.com", "microsoft.com", "azurefd.net", "amazonaws.com", "tmok.tm", "asus.com"),

    # Noise Reduction Whitelists
    [string[]]$ProcessExclusions = @("chrome.exe", "spotify.exe", "msedge.exe", "msedgewebview2.exe", "onedrive.exe", "teams.exe", "discord.exe"),
    [string[]]$IpPrefixExclusions = @("^52\.", "^142\.25[0-9]\.", "^13\.", "^20\.", "^23\.", "^74\.125\.")
)

$ScriptDir = Split-Path $PSCommandPath -Parent
$FullMLPath = Join-Path $ScriptDir $MLScriptPath
$now = Get-Date

# ====================== MATH HELPERS ======================
$log2 = [Math]::Log(2)
$Regex_NonDigit = [regex]::new('[^0-9]', 'Compiled')
$vowels = [System.Collections.Generic.HashSet[char]]::new([char[]]"aeiou")

function Get-Entropy([string]$inputString) {
    <# Calculates Shannon Entropy to evaluate domain randomness #>
    if ([string]::IsNullOrEmpty($inputString)) { return 0.0 }
    $charCounts = @{}
    foreach ($c in $inputString.ToCharArray()) { $charCounts[$c]++ }
    $entropy = 0.0
    $len = $inputString.Length
    foreach ($count in $charCounts.Values) {
        $p = $count / $len
        $entropy -= $p * ([Math]::Log($p) / $log2)
    }
    return $entropy
}

function Is-AnomalousDomain([string]$domain) {
    <# Evaluates domains against common DGA (Domain Generation Algorithm) heuristics #>
    if ([string]::IsNullOrEmpty($domain)) { return $false }
    if ($domain.Length -gt 35) { return $true }

    $digits = $Regex_NonDigit.Replace($domain, "").Length
    if (($digits / $domain.Length) -gt 0.45) { return $true }

    $vowelCount = 0
    foreach ($char in $domain.ToLower().ToCharArray()) { if ($vowels.Contains($char)) { $vowelCount++ } }
    if (($vowelCount / $domain.Length) -lt 0.15) { return $true }

    return (Get-Entropy $domain) -gt 3.8
}

# ====================== DIAGNOSTIC ENGINE ======================
$DiagLogPath = "C:\Temp\C2Hunter_Diagnostic.log"

if (Test-Path $DiagLogPath) { Remove-Item -Path $DiagLogPath -Force -ErrorAction SilentlyContinue }

function Write-Diag {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "IPC-TX", "IPC-RX", "MATH")]
        [string]$Level = "INFO"
    )
    # Architectural Performance Gate: Prevents disk I/O penalties during normal operation.
    # Only writes to disk if -EnableDiagnostics is invoked, UNLESS the event is a fatal error.
    if (-not $EnableDiagnostics -and $Level -ne "ERROR" -and $Level -ne "WARN") { return }

    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    $logLine = "[$ts] [$Level] $Message"
    Add-Content -Path $DiagLogPath -Value $logLine -Encoding UTF8
}

Write-Diag "=== C2 HUNTER V4 DIAGNOSTIC LOG INITIALIZED ===" "INFO"
Write-Diag "Host: $env:COMPUTERNAME | PS Version: $($PSVersionTable.PSVersion.ToString())" "INFO"

# ====================== 1. TRACEEVENT LIBRARY FETCH ======================
# Resolves and stages the TraceEvent ETW parser dynamically based on the active host environment.
# Provides seamless cross-compatibility between PowerShell 5.1 (.NET 4.8) and PowerShell 7+ (.NET Core).
Write-Host "[v4.0] Initializing C# TraceEvent Engine..." -ForegroundColor Cyan
$ExtractPath = "C:\Temp\TraceEventPackage"

$DotNetTarget = if ($PSVersionTable.PSVersion.Major -ge 7) { "netstandard2.0" } else { "net45" }
$ManagedDllPath = "$ExtractPath\lib\$DotNetTarget\Microsoft.Diagnostics.Tracing.TraceEvent.dll"

if (-not (Test-Path $ManagedDllPath)) {
    Write-Host "      [*] Downloading Microsoft.Diagnostics.Tracing.TraceEvent..." -ForegroundColor DarkGray
    New-Item -Path $ExtractPath -ItemType Directory -Force | Out-Null
    $NugetUrl = "https://www.nuget.org/api/v2/package/Microsoft.Diagnostics.Tracing.TraceEvent/2.0.61"
    Invoke-WebRequest -Uri $NugetUrl -OutFile "C:\Temp\TraceEvent.zip"
    Expand-Archive -Path "C:\Temp\TraceEvent.zip" -DestinationPath $ExtractPath -Force
}

Get-ChildItem -Path $ExtractPath -Recurse | Unblock-File
[System.Reflection.Assembly]::LoadFrom($ManagedDllPath) | Out-Null
Write-Host "      [+] TraceEvent Library Loaded ($DotNetTarget)." -ForegroundColor Green


# ====================== 2. EMBEDDED C# ENGINE ======================
# Translates the PowerShell exclusion array into a static C# string array for native compilation.
$DnsExclusionCS = ($DnsExclusions | ForEach-Object { "`"$($_.ToLower())`"" }) -join ", "

$CSharpCode = @"
using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;

// High-performance ETW listener class compiled natively into the PowerShell runspace.
public class RealTimeC2Hunter {
    // Thread-safe queue utilized as a lock-free data bridge between the C# background task and PowerShell foreground loop.
    public static ConcurrentQueue<string> EventQueue = new ConcurrentQueue<string>();
    private static TraceEventSession _session;
    private static readonly string[] DnsExclusions = new string[] { $DnsExclusionCS };

    // Universal IP Parser: Handles raw byte arrays, IPv6-mapped IPv4 strings, and native Kernel Integers.
    private static string ParseIp(object val) {
        if (val == null) return "";
        string result = "";

        if (val is byte[]) {
            byte[] b = (byte[])val;
            try {
                if (b.Length >= 8 && b[0] == 2 && b[1] == 0) result = new System.Net.IPAddress(new byte[] { b[4], b[5], b[6], b[7] }).ToString();
                else if (b.Length >= 24 && b[0] == 23 && b[1] == 0 && b[18] == 255 && b[19] == 255) result = new System.Net.IPAddress(new byte[] { b[20], b[21], b[22], b[23] }).ToString();
                else if (b.Length == 4 || b.Length == 16) result = new System.Net.IPAddress(b).ToString();
            } catch {}
        }
        else if (val is int || val is uint || val is long) {
            try {
                byte[] bytes = BitConverter.GetBytes(Convert.ToInt64(val));
                result = new System.Net.IPAddress(new byte[] { bytes[0], bytes[1], bytes[2], bytes[3] }).ToString();
            } catch {}
        }
        else { result = val.ToString(); }

        // Strip DualMode socket artifacts generated by modern .NET Core applications
        if (result.Contains("::ffff:")) result = result.Replace("::ffff:", "");
        return result;
    }

    // Raw Memory Byte Scanner: Executed as a fallback if ETW providers omit formatting or dependencies are missing.
    private static string FallbackIpExtract(byte[] payload, out string extractedPort) {
        extractedPort = "";
        if (payload == null || payload.Length < 8) return "DECODER_FAILED";
        string lastFound = "DECODER_FAILED";

        // Slide a matching window across the unmanaged byte payload looking for Socket network structures
        for (int i = 0; i < payload.Length - 7; i++) {

            // Pattern 1: Match standard IPv4 SOCKADDR_IN (Family 0x02 0x00)
            if (payload[i] == 2 && payload[i+1] == 0) {

                // Validates port bytes to prevent structure collisions with adjacent 32-bit integers in memory
                if (payload[i+2] == 0 && payload[i+3] == 0) continue;

                int ip1 = payload[i+4]; int ip2 = payload[i+5]; int ip3 = payload[i+6]; int ip4 = payload[i+7];
                if (ip1 == 0 || ip1 == 127 || ip1 == 255) continue;

                string ipStr = ip1 + "." + ip2 + "." + ip3 + "." + ip4;
                lastFound = ipStr;

                // Bypass internal Source IPs to guarantee extraction of the external Destination IP
                if (ip1 == 10 || (ip1 == 192 && ip2 == 168) || (ip1 == 172 && ip2 >= 16 && ip2 <= 31) || (ip1 == 169 && ip2 == 254) || ip1 >= 224) continue;

                extractedPort = ((payload[i+2] << 8) | payload[i+3]).ToString();
                return ipStr;
            }
            // Pattern 2: Match IPv6 SOCKADDR_IN6 (Family 0x17 0x00) used by DualMode sockets
            else if (i < payload.Length - 23 && payload[i] == 23 && payload[i+1] == 0) {

                // Validates port bytes to prevent structure collisions
                if (payload[i+2] == 0 && payload[i+3] == 0) continue;

                if (payload[i+18] == 255 && payload[i+19] == 255) {
                    int ip1 = payload[i+20]; int ip2 = payload[i+21]; int ip3 = payload[i+22]; int ip4 = payload[i+23];
                    if (ip1 == 0 || ip1 == 127 || ip1 == 255) continue;

                    string ipStr = ip1 + "." + ip2 + "." + ip3 + "." + ip4;
                    lastFound = ipStr;

                    if (ip1 == 10 || (ip1 == 192 && ip2 == 168) || (ip1 == 172 && ip2 >= 16 && ip2 <= 31) || (ip1 == 169 && ip2 == 254) || ip1 >= 224) continue;

                    extractedPort = ((payload[i+2] << 8) | payload[i+3]).ToString();
                    return ipStr;
                }
            }
        }
        return lastFound;
    }

    // Initializes the ETW trace session in an asynchronous background thread
    public static void StartSession() {
        Task.Run(() => {
            try {
                if (TraceEventSession.GetActiveSessionNames().Contains("C2RealTimeSession")) {
                    var oldSession = new TraceEventSession("C2RealTimeSession");
                    oldSession.Dispose();
                }

                _session = new TraceEventSession("C2RealTimeSession");
                _session.EnableProvider("Microsoft-Windows-TCPIP");
                _session.EnableProvider("Microsoft-Windows-DNS-Client");
                _session.EnableProvider("Microsoft-Windows-Kernel-Process");
                _session.EnableProvider("Microsoft-Windows-Kernel-File");

                _session.Source.Dynamic.All += delegate (TraceEvent data) {
                    try {
                        // Pre-filtering: Drop high-volume benign events instantly to preserve CPU cycles
                        if (data.ProviderName.Contains("File") && !data.EventName.Contains("Create")) return;
                        if (data.ProviderName.Contains("DNS") && (int)data.ID != 3008) return;

                        string destIp = ""; string port = ""; string query = ""; string cmdLine = ""; string size = "0";
                        string pid = data.ProcessID.ToString();

                        // Native Process Resolution: Replaces payload extraction to guarantee population of the friendly process name
                        string image = string.IsNullOrEmpty(data.ProcessName) ? "Unknown" : data.ProcessName;

                        bool isNetworkEvent = data.ProviderName.Contains("TCPIP") || data.ProviderName.Contains("Network");

                        // PASS 1: Object hierarchy parsing prevents underlying COM exception dependencies
                        // from interrupting valid telemetry extraction.
                        for (int i = 0; i < data.PayloadNames.Length; i++) {
                            string name = data.PayloadNames[i].ToLower();
                            object pVal = data.PayloadValue(i);

                            // Extracts raw IP array bytes directly from the object prior to TraceEvent formatting
                            if (name == "destinationip" || name == "daddr" || name == "destaddress" || name == "destination") {
                                string parsedIp = ParseIp(pVal);
                                if (!string.IsNullOrEmpty(parsedIp) && !parsedIp.Contains("EXCEPTION")) {
                                    destIp = parsedIp;
                                }
                                continue;
                            }

                            string pStr = pVal != null ? pVal.ToString() : "";
                            if (pStr.Contains("EXCEPTION") || string.IsNullOrEmpty(pStr)) continue;

                            if (name == "queryname" || name == "query") query = pStr;
                            else if (name == "commandline") cmdLine = pStr;
                            else if (name == "size" || name == "bytessent" || name == "length") size = pStr;
                            else if (name.Contains("port") && !name.Contains("source") && !name.Contains("sport")) {
                                // Variable pre-declaration ensures compatibility with older C# 5.0 compilers used by PowerShell 5.1
                                int rp;
                                if (int.TryParse(pStr, out rp)) {
                                    if (rp > 65535) rp = rp & 0xFFFF;
                                    // Safely parses integers and corrects Network Byte Order (Big Endian) formatting applied by ETW
                                    int swapped = ((rp & 0xFF) << 8) | ((rp >> 8) & 0xFF);
                                    if (swapped == 80 || swapped == 443 || swapped == 8080 || swapped == 8443) port = swapped.ToString();
                                    else port = (swapped < rp && swapped > 0) ? swapped.ToString() : rp.ToString();
                                } else { port = pStr; }
                            }
                        }

                        // PASS 2: Memory Scanner Fallback Execution
                        // Forces execution strictly on Network events if standard decoders failed to extract a valid destination structure
                        if (isNetworkEvent && (string.IsNullOrEmpty(destIp) || string.IsNullOrEmpty(port) || port == "0")) {
                            try {
                                byte[] rawPayload = data.EventData();
                                string fbPort;
                                string fbIp = FallbackIpExtract(rawPayload, out fbPort);

                                if (string.IsNullOrEmpty(destIp)) destIp = fbIp;
                                if (string.IsNullOrEmpty(port) || port == "0") port = fbPort;
                            } catch { if (string.IsNullOrEmpty(destIp)) destIp = "DECODER_FAILED"; }
                        }

                        // Post-Extraction Rule: Drop unroutable, internal LAN, and broadcast traffic
                        if (isNetworkEvent) {
                            if (string.IsNullOrEmpty(destIp) || destIp.StartsWith("192.168.") || destIp.StartsWith("10.") || destIp.StartsWith("127.") ||
                                destIp.StartsWith("169.254.") || destIp.StartsWith("224.") || destIp.StartsWith("239.") ||
                                destIp.StartsWith("fe80") || destIp == "::1" || destIp == "DECODER_FAILED") return;
                        }

                        // Post-Extraction Rule: Drop excluded DNS domains
                        if (data.ProviderName.Contains("DNS") && !string.IsNullOrEmpty(query)) {
                            string qLow = query.ToLower().TrimEnd('.');
                            bool skipDns = false;
                            for (int e = 0; e < DnsExclusions.Length; e++) {
                                if (qLow.EndsWith(DnsExclusions[e])) { skipDns = true; break; }
                            }
                            if (skipDns) return;
                        }

                        // Manual JSON concatenation provides ultra-low latency string building for the inter-process queue
                        string json = "{\"Provider\":\"" + data.ProviderName + "\", \"EventName\":\"" + data.EventName + "\", \"TimeStamp\":\"" + data.TimeStamp.ToString("O") + "\", \"DestIp\":\"" + destIp + "\", \"Port\":\"" + port + "\", \"Query\":\"" + query + "\", \"Image\":\"" + image.Replace("\\", "\\\\") + "\", \"CommandLine\":\"" + cmdLine.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\", \"PID\":\"" + pid + "\", \"Size\":\"" + size + "\"}";
                        EventQueue.Enqueue(json);

                    } catch {}
                };
                _session.Source.Process();
            } catch (Exception ex) {
                EventQueue.Enqueue("{\"Error\": \"" + ex.Message.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"}");
            }
        });
    }

    public static void StopSession() {
        if (_session != null) { _session.Dispose(); }
    }
}
"@
Add-Type -TypeDefinition $CSharpCode -ReferencedAssemblies $ManagedDllPath
Write-Host "      [+] C# Engine Compiled Natively." -ForegroundColor Green


# ====================== 3. ML DAEMON STARTUP ======================
# Instantiates the Python ML Engine as a parallel background daemon.
# STDIN/STDOUT piping is used to forward telemetry batches without incurring Disk I/O penalties.
$pyStartInfo = New-Object System.Diagnostics.ProcessStartInfo
$pyStartInfo.FileName = $PythonPath
$pyStartInfo.Arguments = '-u "' + $FullMLPath + '"'
$pyStartInfo.RedirectStandardInput = $true
$pyStartInfo.RedirectStandardOutput = $true
# Architectural Health Check: Captures native Python tracebacks for orchestrator visibility.
$pyStartInfo.RedirectStandardError = $true
$pyStartInfo.UseShellExecute = $false
$pyStartInfo.CreateNoWindow = $true
$pyProcess = [System.Diagnostics.Process]::Start($pyStartInfo)
$pyIn = $pyProcess.StandardInput
$pyOut = $pyProcess.StandardOutput
$pyErr = $pyProcess.StandardError

# Validation Engine: Ensures the interpreter successfully loaded the C-libraries and ML matrices before entering the operational loop.
Start-Sleep -Seconds 2
if ($pyProcess.HasExited) {
    $fatalErr = $pyErr.ReadToEnd()
    Write-Host "`n[FATAL] The Python ML Daemon terminated unexpectedly during initialization." -ForegroundColor Red
    Write-Host "Native Exception Trace:`n$fatalErr" -ForegroundColor DarkRed
    Write-Diag "Python daemon crashed on startup. STDERR: $fatalErr" "ERROR"
    exit
}

# ====================== 4. RUNTIME STRUCTURES ======================
# High-speed memory structures utilized by the foreground loop to aggregate and track flow states
$connectionHistory = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.Queue[datetime]]]::new()
$lastPingTime = @{}
$flowMetadata = @{}
$dataBatch = [System.Collections.Generic.List[PSObject]]::new()

# Deduplication log structures
$loggedFlows = @{}
$MonitorLogPath = "C:\Temp\OutboundNetwork_Monitor.log"

$lastMLRunTime = Get-Date
$globalMlSent = 0
$globalMlRcvd = 0
$globalMlEvaluated = 0
$globalMlAlerts = 0
$OutboundNetEvents = 0

$StateDBPath = "C:\Temp\C2_StateDB"
if (-not (Test-Path $StateDBPath)) {
    New-Item -ItemType Directory -Force -Path $StateDBPath | Out-Null
} else {
    # Database Grooming: Preserves temporal memory across reboots but prevents disk exhaustion.
    # Automatically purges any dormant state file older than 14 days upon daemon startup.
    Get-ChildItem -Path $StateDBPath -Filter "*.json" | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-14) } | Remove-Item -Force -ErrorAction SilentlyContinue
}

Write-Host "[v4.0] Starting Real-Time ETW Session (No Disk IO)..." -ForegroundColor Yellow
[RealTimeC2Hunter]::StartSession()

Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "   [v4.0] C2 HUNTER SYSTEM HEALTH CHECK" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host " [+] C# ETW Engine        : RUNNING (In-Memory)" -ForegroundColor Green
Write-Host " [+] Native IP Decoders   : BYPASSED (Using Raw Byte Scanner)" -ForegroundColor Green
Write-Host " [+] Kernel Provider      : LISTENING (TCPIP/DNS/Process)" -ForegroundColor Green
if ($pyProcess -and -not $pyProcess.HasExited) {
    Write-Host " [+] ML Analysis Daemon   : CONNECTED (PID: $($pyProcess.Id))" -ForegroundColor Green
} else {
    Write-Host " [-] ML Analysis Daemon   : FAILED TO START" -ForegroundColor Red
}
Write-Host "========================================================`n" -ForegroundColor Cyan


# ====================== 5. MAIN EVENT LOOP ======================
try {
    while ($true) {
        $now = Get-Date
        $eventCount = 0
        $jsonStr = ""

        # Drain the C# Queue constantly to maintain a low memory footprint
        while ([RealTimeC2Hunter]::EventQueue.TryDequeue([ref]$jsonStr)) {
            $eventCount++
            $evt = $jsonStr | ConvertFrom-Json -ErrorAction SilentlyContinue
            if (-not $evt -or $evt.Error) { continue }

            # --- NOISE REDUCTION FILTERS ---
            $procName = if ($evt.Image -and $evt.Image -ne "Unknown") { [System.IO.Path]::GetFileName($evt.Image).ToLower() } else { "" }
            $skipEvent = $false

            # Process Filter: Drop notoriously noisy applications
            if (-not [string]::IsNullOrEmpty($procName) -and ($ProcessExclusions -contains $procName)) {
                $skipEvent = $true
            }

            # Subnet Filter: Drop known Microsoft/Google CDN ranges
            if (-not $skipEvent -and -not [string]::IsNullOrEmpty($evt.DestIp)) {
                foreach ($prefix in $IpPrefixExclusions) {
                    if ($evt.DestIp -match $prefix) { $skipEvent = $true; break }
                }
            }

            if ($skipEvent) { continue }
            # ------------------------------------

            $props = [ordered]@{
                EventType = $evt.EventName
                Timestamp = [datetime]$evt.TimeStamp
                Image = $evt.Image
                SuspiciousFlags = [System.Collections.Generic.List[string]]::new()
                ATTCKMappings = [System.Collections.Generic.List[string]]::new()
                DestinationHostname = $evt.Query
                Confidence = 85
            }

            # --- STATIC SIGNATURE DETECTION ---
            if ($evt.Provider -match "Process" -and $evt.CommandLine -match '-EncodedCommand|-enc|IEX') {
                $props.SuspiciousFlags.Add("Anomalous CommandLine")
                $props.ATTCKMappings.Add("TA0002: T1059.001")
            }
            if ($evt.Provider -match "File" -and $evt.Image -match '\.ps1$|\.exe$') {
                $props.SuspiciousFlags.Add("Executable File Created")
                $props.ATTCKMappings.Add("TA0002: T1059")
            }
            if ($evt.Provider -match "DNS" -and $evt.Query -match '^[a-zA-Z0-9\-\.]+$') {
                $cleanQuery = $evt.Query.TrimEnd('.')
                if (Is-AnomalousDomain $cleanQuery) {
                    $props.SuspiciousFlags.Add("DGA DNS Query Detected")
                    $props.ATTCKMappings.Add("TA0011: T1568.002")
                }
            }

            # --- BEACONING TRACKER (STATE MANAGEMENT) ---
            if ($evt.Provider -match "TCPIP|Network" -and $evt.DestIp -and $evt.DestIp -notmatch '^192\.168\.|^10\.|^127\.|^172\.') {
                $OutboundNetEvents++

                # Dictionary Tracker: Enforces Destination IP isolation for shared OS processes (System/Idle)
                # to prevent background network noise from polluting the ML clustering matrices.
                $safePort = if ([string]::IsNullOrWhiteSpace($evt.Port) -or $evt.Port -eq "0") { "IP_$($evt.DestIp)" } else { $evt.Port }
                $key = if ($evt.PID -eq "4" -or $evt.PID -eq "0") { "PID_$($evt.PID)_IP_$($evt.DestIp)_Port_$safePort" } else { "PID_$($evt.PID)_Port_$safePort" }

                # --- HYBRID STATE MANAGER (RAM + DISK) ---
                if (-not $connectionHistory.ContainsKey($key)) {
                    $dbFile = Join-Path $StateDBPath "$key.json"

                    if (Test-Path $dbFile) {
                        # LOW AND SLOW DETECTED: Restore historical state from Disk to RAM
                        $restored = Get-Content $dbFile -Raw | ConvertFrom-Json
                        $connectionHistory[$key] = [System.Collections.Generic.Queue[datetime]]::new()
                        foreach ($ts in $restored.timestamps) { $connectionHistory[$key].Enqueue([datetime]$ts) }

                        $flowMetadata[$key] = @{
                            dst_ips = [System.Collections.Generic.List[string]]::new([string[]]$restored.dst_ips)
                            packet_sizes = [System.Collections.Generic.List[int]]::new([int[]]$restored.packet_sizes)
                            domain = $restored.domain
                            image = $restored.image
                        }

                        # Purge the DB file since the flow is active in RAM again
                        Remove-Item $dbFile -Force -ErrorAction SilentlyContinue
                        Write-Diag "Restored historical temporal state for $key from Disk DB." "INFO"
                    } else {
                        # Standard New Connection
                        $connectionHistory[$key] = [System.Collections.Generic.Queue[datetime]]::new()
                        $flowMetadata[$key] = @{
                            dst_ips = [System.Collections.Generic.List[string]]::new()
                            packet_sizes = [System.Collections.Generic.List[int]]::new()
                            domain = if ($evt.Query) { $evt.Query } else { $evt.DestIp }
                            image = $evt.Image
                        }
                    }
                }

                $isNewPing = $true

                # Debounce Filter: Discards rapid payload fragments (e.g., TCP handshakes) to isolate true beacon intervals
                if ($lastPingTime.ContainsKey($key) -and ($props.Timestamp - $lastPingTime[$key]).TotalMilliseconds -lt 100) {
                    $isNewPing = $false
                }

                # Data Alignment: Metadata is appended exclusively on debounced intervals to maintain parallel arrays
                if ($isNewPing) {
                    $connectionHistory[$key].Enqueue($props.Timestamp)
                    $lastPingTime[$key] = $props.Timestamp
                    $flowMetadata[$key].dst_ips.Add($evt.DestIp)

                    if ($evt.Size -match '^\d+$' -and $evt.Size -ne "0") {
                        $flowMetadata[$key].packet_sizes.Add([int]$evt.Size)
                    } else {
                        $flowMetadata[$key].packet_sizes.Add(0)
                    }
                }
            }

            if ($props.SuspiciousFlags.Count -gt 0) {
                $outObj = New-Object PSObject -Property $props
                $outObj.SuspiciousFlags = $props.SuspiciousFlags -join '; '
                $outObj.ATTCKMappings = $props.ATTCKMappings -join '; '
                $dataBatch.Add($outObj)
                Write-Host "`n[STATIC ALERT] $($outObj.SuspiciousFlags)" -ForegroundColor DarkYellow
            }
        }

        # ---------------- ML HANDOFF PIPELINE ----------------
        if (($now - $lastMLRunTime).TotalSeconds -ge $BatchAnalysisIntervalSeconds) {
            $payload = @{}

            foreach ($key in $connectionHistory.Keys) {
                $count = $connectionHistory[$key].Count
                if ($count -ge $MinSamplesForML) {
                    $arr = $connectionHistory[$key].ToArray()

                    # Telemetry Pruning: Only forward the matrix to the ML daemon if new data points
                    # were intercepted during the current batch cycle. Prevents extreme compute bloat.
                    if (($now - $arr[-1]).TotalSeconds -gt ($BatchAnalysisIntervalSeconds + 5)) {
                        continue
                    }

                    # Structured Deduplication Logging
                    if (-not $loggedFlows.ContainsKey($key) -or $loggedFlows[$key] -ne $count) {
                        $loggedFlows[$key] = $count
                        $duration = [Math]::Round(($arr[-1] - $arr[0]).TotalSeconds, 2)
                        $firstPing = $arr[0].ToString("yyyy-MM-dd HH:mm:ss")

                        $destIp = $flowMetadata[$key].dst_ips[-1]
                        $domain = $flowMetadata[$key].domain

                        $portParts = $key -split "_Port_"
                        $portVal = if ($portParts.Count -gt 1) { $portParts[1] } else { "Unknown" }
                        $pidParts = ($portParts[0] -split "PID_")
                        $pidVal = if ($pidParts.Count -gt 1) { ($pidParts[1] -split "_IP_")[0] } else { "Unknown" }

                        # Process Name Fallback: If ETW missed the image load event, explicitly fetch the process name via the OS.
                        $procName = "Unknown"
                        if ($flowMetadata[$key].image -and $flowMetadata[$key].image -ne "Unknown") {
                            $procName = [System.IO.Path]::GetFileNameWithoutExtension($flowMetadata[$key].image)
                        } elseif ($pidVal -match '^\d+$') {
                            try {
                                $procName = (Get-Process -Id $pidVal -ErrorAction Stop).Name
                                if ($pidVal -eq "4") { $procName = "System" }
                            } catch { $procName = "Terminated" }
                        }

                        $logEntry = "Timestamp: $firstPing, Destination IP: $destIp, Destination Domain: $domain, Port: $portVal, PID: $pidVal, Process Name: $procName, Connection Amount over duration: $count connections over ${duration}s"
                        Add-Content -Path $MonitorLogPath -Value $logEntry -Encoding UTF8
                    }

                    $intervals = @()
                    $aligned_ips = @()
                    $aligned_sizes = @()

                    # Array Slicing: Extracts N-1 intervals to ensure perfectly aligned matrices for Scikit-Learn processing
                    for ($i = 1; $i -lt $arr.Count; $i++) {
                        $intervals += [Math]::Round(($arr[$i] - $arr[$i-1]).TotalSeconds, 2)
                        if ($i -lt $flowMetadata[$key].dst_ips.Count) { $aligned_ips += $flowMetadata[$key].dst_ips[$i] }
                        if ($i -lt $flowMetadata[$key].packet_sizes.Count) { $aligned_sizes += $flowMetadata[$key].packet_sizes[$i] }
                    }

                    $payload[$key] = @{
                        intervals = $intervals
                        domain = $flowMetadata[$key].domain
                        dst_ips = $aligned_ips
                        packet_sizes = $aligned_sizes
                    }
                }
            }

            if ($payload.Count -gt 0) {
                $globalMlSent++
                $jsonPayload = $payload | ConvertTo-Json -Depth 6 -Compress

                # --- DIAGNOSTIC INJECTION: TRACK TRANSMISSION ---
                Write-Diag "Flushing matrix to Python STDIN. Flows: $($payload.Count) | ByteSize: $($jsonPayload.Length)" "IPC-TX"

                $pyIn.WriteLine($jsonPayload)
                $pyIn.Flush()

                $timeout = 150
                $responseReceived = $false

                while ($timeout-- -gt 0 -and -not $pyProcess.HasExited) {
                    if (-not $pyOut.EndOfStream) {
                        $pyResponse = $pyOut.ReadLine()

                        if ($pyResponse) {
                            $responseReceived = $true
                            $globalMlRcvd++

                            # --- DIAGNOSTIC INJECTION: TRACK RAW RECEIPT ---
                            Write-Diag "Raw payload received from Python STDOUT: $pyResponse" "IPC-RX"

                            try {
                                $mlResults = $pyResponse | ConvertFrom-Json -ErrorAction Stop
                            } catch {
                                Write-Host "`n[!] ML Daemon IPC Error: Python emitted non-JSON string. Check Diagnostic Log." -ForegroundColor Red
                                Write-Diag "JSON Parse Failure. Python emitted corrupted/non-JSON data: $pyResponse" "ERROR"
                                break
                            }

                            foreach ($alertKey in $mlResults.PSObject.Properties.Name) {
                                if ($alertKey -eq "_health_metrics") {
                                    $globalMlEvaluated += $mlResults.$alertKey.flows_evaluated
                                    $globalMlAlerts += $mlResults.$alertKey.alerts_generated
                                    Write-Diag "Python Health Metrics -> Evaluated: $($mlResults.$alertKey.flows_evaluated) | Alerts Generated: $($mlResults.$alertKey.alerts_generated)" "MATH"
                                    continue
                                }

                                if ($alertKey -eq "daemon_error") {
                                    Write-Host "`n[!] ML Daemon Runtime Error: $($mlResults.$alertKey)" -ForegroundColor Red
                                    Write-Diag "Fatal Python Daemon Error: $($mlResults.$alertKey)" "ERROR"
                                    continue
                                }

                                $alertData = $mlResults.$alertKey
                                if ($alertData.error) {
                                    Write-Host "`n[!] ML Flow Processing Error ($alertKey): $($alertData.error)" -ForegroundColor DarkRed
                                    Write-Diag "Python flow math error on $alertKey : $($alertData.error)" "ERROR"
                                    continue
                                }

                                if ($alertData.alert) {
                                    Write-Host "`n[ML ALERT] $alertKey - $($alertData.alert)" -ForegroundColor Red
                                    Write-Diag "DETECTION TRIGGERED: $alertKey -> $($alertData.alert) (Confidence: $($alertData.confidence))" "INFO"

                                    $dataBatch.Add([PSCustomObject]@{
                                        EventType = "ML_Beacon"
                                        Timestamp = $now
                                        Destination = $alertKey
                                        Image = $flowMetadata[$alertKey].image
                                        SuspiciousFlags = $alertData.alert
                                        Confidence = $alertData.confidence
                                    })
                                }
                            }
                            break
                        }
                    }
                    Start-Sleep -Milliseconds 100
                }

                if (-not $responseReceived) {
                    if ($pyProcess.HasExited) {
                        $fatalErr = $pyErr.ReadToEnd()
                        Write-Host "`n[!] ML IPC FATAL: The Python Daemon crashed. STDERR:`n$fatalErr" -ForegroundColor Red
                        Write-Diag "IPC FATAL CRASH: Python Daemon exited prematurely. STDERR: $fatalErr" "ERROR"
                    } else {
                        Write-Host "`n[!] ML IPC Timeout: The Daemon did not respond within 15000ms." -ForegroundColor DarkRed
                        Write-Diag "IPC TIMEOUT: Python Daemon failed to return a response line within 15000ms." "ERROR"
                    }
                }
            }

            # --- HYBRID STATE GARBAGE COLLECTION (FLUSH TO DISK) ---
            $staleKeys = @()
            foreach ($k in $connectionHistory.Keys) {
                $historyArr = $connectionHistory[$k].ToArray()
                if ($historyArr.Count -gt 0) {
                    $lastActivity = $historyArr[-1]
                    if (($now - $lastActivity).TotalSeconds -gt 300) {

                        # Instead of destroying the temporal data, serialize it to the local State DB
                        $dbFile = Join-Path $StateDBPath "$k.json"

                        $diskState = @{ timestamps = @(); dst_ips = @(); packet_sizes = @(); domain = $flowMetadata[$k].domain; image = $flowMetadata[$k].image }

                        # If the DB file already exists (multiple flushes over days), append to it
                        if (Test-Path $dbFile) {
                            $existing = Get-Content $dbFile -Raw | ConvertFrom-Json
                            $diskState.timestamps = [System.Collections.Generic.List[string]]::new([string[]]$existing.timestamps)
                            $diskState.dst_ips = [System.Collections.Generic.List[string]]::new([string[]]$existing.dst_ips)
                            $diskState.packet_sizes = [System.Collections.Generic.List[int]]::new([int[]]$existing.packet_sizes)
                        }

                        foreach ($t in $historyArr) { $diskState.timestamps += $t.ToString("O") }
                        $diskState.dst_ips += $flowMetadata[$k].dst_ips
                        $diskState.packet_sizes += $flowMetadata[$k].packet_sizes

                        $diskState | ConvertTo-Json -Compress | Set-Content $dbFile -Encoding UTF8

                        $staleKeys += $k
                        Write-Diag "Flushed $k to Disk DB (Low and Slow Tracking)." "INFO"
                    }
                }
            }
            foreach ($k in $staleKeys) {
                [void]$connectionHistory.Remove($k); [void]$flowMetadata.Remove($k); [void]$loggedFlows.Remove($k)
            }
            $lastMLRunTime = $now
        }

        if ($dataBatch.Count -gt 0) {
            foreach ($obj in $dataBatch) { $obj | ConvertTo-Json -Compress | Add-Content $OutputPath -Encoding UTF8 }
            $dataBatch.Clear()
        }

        $activeFlows = $connectionHistory.Keys.Count
        Write-Host "`r[Status] Processed: $eventCount | Flows: $activeFlows | ML Sent: $globalMlSent | Rcvd: $globalMlRcvd | Evaluated: $globalMlEvaluated | Alerts: $globalMlAlerts " -NoNewline -ForegroundColor DarkGray
        Start-Sleep -Milliseconds 2000
    }

# ====================== 6. TEARDOWN SEQUENCE ======================
} finally {
    Write-Diag "Initiating Teardown Sequence..." "INFO"

    [RealTimeC2Hunter]::StopSession()
    Write-Diag "C# TraceEvent Session Halted." "INFO"

    if ($pyProcess -and -not $pyProcess.HasExited) {
        $pyProcess.StandardInput.WriteLine("QUIT")
        Start-Sleep -Milliseconds 200
        if (-not $pyProcess.HasExited) {
            $pyProcess.Kill()
            Write-Diag "Python Daemon forcefully killed." "WARN"
        } else {
            Write-Diag "Python Daemon exited gracefully." "INFO"
        }
    }

    $ProjectArtifacts = @(
        "C:\Temp\TraceEventPackage",
        "C:\Temp\TraceEvent.zip",
        "C:\Temp\TraceEventSupport.zip",
        "C:\Temp\C2Kernel.etl"
    )
    foreach ($Item in $ProjectArtifacts) {
        if (Test-Path $Item) {
            Remove-Item -Path $Item -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    Write-Diag "=== DIAGNOSTIC LOG CLOSED ===" "INFO"
}
