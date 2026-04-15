/********************************************************************************
 * SYSTEM:          C2 Beacon Sensor - Active Defense / Infrastructure Exploitation
 * COMPONENT:       C2Sensor.cs (Unmanaged ETW Engine)
 * AUTHOR:          Robert Weber
 * VERSION:         1.0
 * * DESCRIPTION:
 * A high-performance, real-time Event Tracing for Windows (ETW) listener compiled
 * natively into the PowerShell runspace. It acts as the primary telemetry bridge,
 * parsing the high-volume ETW firehose at lightning speed without Disk I/O.
* * ARCHITECTURAL FEATURES:
 * - Universal AppGuard: Monitors Kernel-Process events to instantly intercept
 * web shells and database RCEs spawning command interpreters. Utilizes an O(1)
 * Integer PID cache and directory heuristics for zero-overhead evaluation.
 * - Cryptographic DPI (NDIS): Subscribes to raw Layer 2 Ethernet frames, using
 * a sliding window byte-scanner to extract TLS Client Hello signatures and
 * generate JA3 hashes for external threat intelligence correlation.
 * - Telemetry Grooming: Aggressively pre-filters benign network noise (RFC 1918,
 * Multicast, Broadcast, idle routing) and resolved DNS exclusions prior to
 * machine learning handoff.
 * - Anti-Tamper Failsafes: Monitors Kernel-Memory for anomalous VirtualProtect
 * RWX permission changes indicative of sensor unhooking or telemetry blinding.
 * * ACCEPTED RISKS:
 * - WMI Breakaway (Win32_Process.Create): Executions invoked via WMI will parent
 * under WmiPrvSE.exe rather than the originating web/database daemon. Cross-process
 * RPC correlation is intentionally omitted to preserve O(1) ETW performance.
 * Subsequent payloads will be caught downstream by Phase 3 Memory Forensics.
 * * DEPLOYMENT NOTE:
 * This module is designed to be initialized dynamically at runtime by the
 * primary Monitor daemon, which passes exclusion arrays directly into the
 * C# memory space prior to session execution.
 ********************************************************************************/

using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using System.Text;
using System.Security.Cryptography;
using System.Collections.Generic;

// High-performance ETW listener class compiled natively into the PowerShell runspace.
public class RealTimeC2Hunter {
    // Thread-safe queue utilized as a lock-free data bridge between the C# background task and PowerShell foreground loop.
    public static ConcurrentQueue<string> EventQueue = new ConcurrentQueue<string>();
    private static TraceEventSession _session;
    private static HashSet<string> DnsExclusions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    // Initialization method to receive the exclusions from PowerShell at runtime
    public static void InitializeEngine(string[] dnsExclusions) {
        foreach (string domain in dnsExclusions) {
            DnsExclusions.Add(domain);
        }
    }

    // AppGuard Web Server Hashsets
    private static readonly HashSet<string> WebDaemons = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        // Microsoft / IIS
        "w3wp", "iisexpress",

        // Standard Web Servers & Proxies
        "httpd", "nginx", "lighttpd", "caddy", "traefik", "envoy", "haproxy",

        // Java Ecosystem
        "tomcat", "tomcat7", "tomcat8", "tomcat9", "java", "javaw",

        // Interpreters & Runtimes (Often hosting APIs/Web Shells)
        "node", "dotnet", "python", "python3", "php", "php-cgi", "ruby"
    };

    // AppGuard Database Server Hashsets
    private static readonly HashSet<string> DbDaemons = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        // Relational SQL
        "sqlservr", "mysqld", "mariadbd", "postgres", "oracle", "tnslsnr", "db2sysc", "fbserver",

        // NoSQL / In-Memory / Time-Series
        "mongod", "redis-server", "memcached", "couchdb", "influxd", "arangod"
    };

    // LOLBin Matrix (Living off the Land)
    private static readonly HashSet<string> ShellInterpreters = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "cmd", "powershell", "pwsh", "wscript", "cscript", "bash", "sh", "whoami",
            "csc", "cvtres", "certutil", "wmic", "rundll32", "regsvr32", "msbuild", "bitsadmin"
        };

    // AppGuard: High-speed Integer PID trackers for active daemons
    private static ConcurrentDictionary<int, string> ActiveWebDaemons = new ConcurrentDictionary<int, string>();
    private static ConcurrentDictionary<int, string> ActiveDbDaemons = new ConcurrentDictionary<int, string>();

    // AppGuard: Suspicious Execution Paths
    private static readonly string[] SuspiciousPaths = new string[] {
        "\\temp\\", "\\programdata\\", "\\inetpub\\wwwroot\\", "\\appdata\\", "\\users\\public\\"
    };

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

    // --- JA3 HASHING ENGINE ---
    private static bool IsGrease(ushort val) {
        // GREASE values follow the pattern 0x?A?A
        return (val & 0x0F0F) == 0x0A0A;
    }

    private static string ExtractJA3(byte[] payload, int offset, int length) {
        try {
            // Validate TLS Record: 0x16 (Handshake), 0x03 (Major Version)
            if (payload[offset] != 0x16 || payload[offset + 1] != 0x03) return null;

            // Validate Handshake Type: 0x01 (Client Hello)
            if (payload[offset + 5] != 0x01) return null;

            int ptr = offset + 9; // Jump to Client Version

            // 1. SSL Version
            ushort sslVersion = (ushort)((payload[ptr] << 8) | payload[ptr + 1]);
            ptr += 2; // Jump over version
            ptr += 32; // Jump over Random (32 bytes)

            // Jump over Session ID
            int sessionLength = payload[ptr];
            ptr += 1 + sessionLength;

            // 2. Cipher Suites
            int cipherLength = (payload[ptr] << 8) | payload[ptr + 1];
            ptr += 2;
            List<ushort> ciphers = new List<ushort>();
            for (int i = 0; i < cipherLength; i += 2) {
                ushort cipher = (ushort)((payload[ptr + i] << 8) | payload[ptr + i + 1]);
                if (!IsGrease(cipher)) ciphers.Add(cipher);
            }
            ptr += cipherLength;

            // Jump over Compression Methods
            int compLength = payload[ptr];
            ptr += 1 + compLength;

            // 3, 4, 5. Extensions, Curves, and Point Formats
            List<ushort> extensions = new List<ushort>();
            List<ushort> curves = new List<ushort>();
            List<ushort> pointFormats = new List<ushort>();

            if (ptr + 2 <= offset + length) {
                int extTotalLength = (payload[ptr] << 8) | payload[ptr + 1];
                ptr += 2;
                int extEnd = ptr + extTotalLength;

                while (ptr + 4 <= extEnd) {
                    ushort extType = (ushort)((payload[ptr] << 8) | payload[ptr + 1]);
                    int extLen = (payload[ptr + 2] << 8) | payload[ptr + 3];
                    ptr += 4;

                    if (!IsGrease(extType)) {
                        extensions.Add(extType);

                        // Extension 10: Supported Groups (Elliptic Curves)
                        if (extType == 10 && extLen >= 2) {
                            int curveListLen = (payload[ptr] << 8) | payload[ptr + 1];
                            for (int i = 2; i < curveListLen + 2; i += 2) {
                                ushort curve = (ushort)((payload[ptr + i] << 8) | payload[ptr + i + 1]);
                                if (!IsGrease(curve)) curves.Add(curve);
                            }
                        }
                        // Extension 11: EC Point Formats
                        else if (extType == 11 && extLen >= 1) {
                            int formatListLen = payload[ptr];
                            for (int i = 1; i < formatListLen + 1; i++) {
                                pointFormats.Add(payload[ptr + i]);
                            }
                        }
                    }
                    ptr += extLen; // Jump to next extension
                }
            }

            // Construct the JA3 String: SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurveFormat
            string ja3String = string.Format("{0},{1},{2},{3},{4}",
                sslVersion,
                string.Join("-", ciphers),
                string.Join("-", extensions),
                string.Join("-", curves),
                string.Join("-", pointFormats)
            );

            // Compute MD5 Hash natively
            using (MD5 md5 = MD5.Create()) {
                byte[] hashBytes = md5.ComputeHash(Encoding.UTF8.GetBytes(ja3String));
                StringBuilder sb = new StringBuilder();
                foreach (byte b in hashBytes) sb.Append(b.ToString("x2"));
                return sb.ToString();
            }
        } catch { return null; } // Catch out-of-bounds index errors on malformed packets
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
                // Enable Kernel Memory provider to watch for ETW patching (VirtualProtect)
                _session.EnableProvider("Microsoft-Windows-Kernel-Memory");
                // Raw Layer 2 Packet Capture
                _session.EnableProvider("Microsoft-Windows-NDIS-PacketCapture");

                _session.Source.Dynamic.All += delegate (TraceEvent data) {
                    try {
                        // TAMPER DETECTION: Monitor for Logman stopping our specific session
                        if (data.ProviderName.Contains("Kernel-Process") && data.EventName.Contains("Start")) {
                            string cmd = data.PayloadStringByName("CommandLine").ToLower();
                            if (cmd.Contains("logman") && (cmd.Contains("stop") || cmd.Contains("delete")) && cmd.Contains("c2realtimesession")) {
                                EventQueue.Enqueue("{\"Provider\":\"TamperGuard\", \"EventName\":\"ETW_STOP_ATTEMPT\", \"Details\":\"A process attempted to blind the C2 ETW Session via Logman.\"}");
                            }
                        }

                        // TAMPER DETECTION: Watch for VirtualProtect RWX (0x40) indicating potential NTDLL unhooking/patching
                        if (data.ProviderName.Contains("Kernel-Memory") && data.EventName.Contains("VirtualProtect")) {
                            // Note: In a production ETW trace, you would map the exact address of ntdll.dll per process.
                            // Here, we flag anomalous RWX permission changes.
                            object protectionObj = data.PayloadByName("NewProtection");
                            if (protectionObj != null) {
                                uint protection = Convert.ToUInt32(protectionObj);
                                if (protection == 0x40) { // PAGE_EXECUTE_READWRITE
                                    string proc = string.IsNullOrEmpty(data.ProcessName) ? data.ProcessID.ToString() : data.ProcessName;
                                    EventQueue.Enqueue("{\"Provider\":\"TamperGuard\", \"EventName\":\"MEMORY_PATCH_DETECTED\", \"Details\":\"Suspicious RWX permission change detected in process: " + proc + "\"}");
                                }
                            }
                        }

                        // APPGUARD PROCESS INTERCEPTOR
                        if (data.ProviderName.Contains("Kernel-Process")) {

                            // TRACKING: Add daemon PIDs to the ultra-fast integer cache when they start
                            if (data.EventName.Contains("Start")) {
                                string imageClean = System.IO.Path.GetFileNameWithoutExtension(data.PayloadStringByName("ImageFileName") ?? "").ToLower();

                                if (WebDaemons.Contains(imageClean)) {
                                    string context = data.PayloadStringByName("CommandLine") ?? imageClean;
                                    ActiveWebDaemons[data.ProcessID] = context;
                                }
                                else if (DbDaemons.Contains(imageClean)) {
                                    string context = data.PayloadStringByName("CommandLine") ?? imageClean;
                                    ActiveDbDaemons[data.ProcessID] = context;
                                }
                            }
                            // TRACKING: Remove PIDs when the daemon naturally stops to prevent ID collision
                            else if (data.EventName.Contains("Stop")) {
                                string removedContext;
                                ActiveWebDaemons.TryRemove(data.ProcessID, out removedContext);
                                ActiveDbDaemons.TryRemove(data.ProcessID, out removedContext);
                            }

                            // DETECTION: Evaluate child process spawns
                            if (data.EventName.Contains("Start")) {
                                int parentPid = Convert.ToInt32(data.PayloadByName("ParentProcessID") ?? -1);

                                // O(1) Integer Lookup: Instantly bypass 99.9% of OS process creations
                                bool isWebParent = ActiveWebDaemons.ContainsKey(parentPid);
                                bool isDbParent = ActiveDbDaemons.ContainsKey(parentPid);

                                if (isWebParent || isDbParent) {
                                    string childPath = data.PayloadStringByName("ImageFileName") ?? "";
                                    string childClean = System.IO.Path.GetFileNameWithoutExtension(childPath).ToLower();
                                    string cmdLine = data.PayloadStringByName("CommandLine") ?? "";

                                    bool isInterpreter = ShellInterpreters.Contains(childClean);
                                    bool isSuspiciousPath = false;

                                    foreach (string path in SuspiciousPaths) {
                                        if (childPath.ToLower().Contains(path)) { isSuspiciousPath = true; break; }
                                    }

                                    // The Detection Gate
                                    if (isInterpreter || isSuspiciousPath) {

                                        // JIT False Positive Suppression
                                        if (isWebParent && (childClean == "csc" || childClean == "cvtres") && cmdLine.IndexOf("Temporary ASP.NET Files", StringComparison.OrdinalIgnoreCase) >= 0) {
                                            return;
                                        }

                                        string parentContext = isWebParent ? ActiveWebDaemons[parentPid] : ActiveDbDaemons[parentPid];
                                        string eventType = isWebParent ? "WEB_SHELL_DETECTED" : "DB_RCE_DETECTED";
                                        string trigger = isInterpreter ? "Command Interpreter" : "Unauthorized Directory";

                                        string json = "{\"Provider\":\"AppGuard\", \"EventName\":\"" + eventType + "\", \"ParentContext\":\"" + parentContext.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\", \"Child\":\"" + childClean + "\", \"Trigger\":\"" + trigger + "\", \"CommandLine\":\"" + cmdLine.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"}";
                                        EventQueue.Enqueue(json);
                                    }
                                }
                            }
                        }

                        // --- NDIS RAW PACKET INTERCEPTION ---
                        if (data.ProviderName.Contains("NDIS-PacketCapture")) {
                            try {
                                byte[] frame = (byte[])data.PayloadByName("Fragment");
                                if (frame != null && frame.Length > 54) { // Minimum size for Eth + IPv4 + TCP

                                    // 1. Ethernet Header (14 bytes)
                                    // Check EtherType (bytes 12-13) for IPv4 (0x0800)
                                    if (frame[12] == 0x08 && frame[13] == 0x00) {

                                        // 2. IPv4 Header
                                        int ipHeaderStart = 14;
                                        // Check Protocol (byte 9 of IP header) for TCP (0x06)
                                        if (frame[ipHeaderStart + 9] == 0x06) {

                                            // Calculate IP Header Length (IHL is lower 4 bits of the first byte)
                                            int ihl = (frame[ipHeaderStart] & 0x0F) * 4;
                                            int tcpHeaderStart = ipHeaderStart + ihl;

                                            // Ensure we don't read out of bounds
                                            if (frame.Length >= tcpHeaderStart + 20) {

                                                // 3. TCP Header
                                                // Extract Destination Port (bytes 2-3 of TCP header)
                                                int destPort = (frame[tcpHeaderStart + 2] << 8) | frame[tcpHeaderStart + 3];

                                                // 4. The CPU Defense Gate
                                                // Only proceed if traffic is destined for standard TLS ports
                                                if (destPort == 443 || destPort == 8443) {
                                                    int dataOffset = (frame[tcpHeaderStart + 12] >> 4) * 4;
                                                    int payloadStart = tcpHeaderStart + dataOffset;
                                                    int payloadLength = frame.Length - payloadStart;

                                                    if (payloadLength > 5) {
                                                        // Extract the JA3 Fingerprint from the Raw Frame
                                                        string ja3Hash = ExtractJA3(frame, payloadStart, payloadLength);

                                                        if (!string.IsNullOrEmpty(ja3Hash)) {
                                                            // Manually extract IP for correlation (Renamed to prevent C# scope collision)
                                                            string ndisDestIp = frame[ipHeaderStart + 16] + "." + frame[ipHeaderStart + 17] + "." + frame[ipHeaderStart + 18] + "." + frame[ipHeaderStart + 19];

                                                            // Send the JA3 payload directly to PowerShell's EventQueue (Renamed)
                                                            string ndisJson = "{\"Provider\":\"NDIS\", \"EventName\":\"TLS_JA3_FINGERPRINT\", \"DestIp\":\"" + ndisDestIp + "\", \"Port\":\"" + destPort + "\", \"JA3\":\"" + ja3Hash + "\"}";
                                                            EventQueue.Enqueue(ndisJson);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            } catch {}

                            // Return immediately. Do not let raw NDIS frames hit the legacy TCPIP parser below.
                            return;
                        }
                        // Pre-filtering: Drop high-volume benign events instantly to preserve CPU cycles
                        if (data.ProviderName.Contains("File") && !data.EventName.Contains("Create")) return;
                        if (data.ProviderName.Contains("DNS") && (int)data.ID != 3008) return;

                        string destIp = ""; string port = ""; string query = ""; string cmdLine = ""; string size = "0";
                        string pid = data.ProcessID.ToString();
                        // Extract Native Thread ID
                        string tid = data.ThreadID.ToString();

                        // Native Process Resolution
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
                            if (string.IsNullOrEmpty(destIp) || destIp.StartsWith("192.168.") || destIp.StartsWith("10.") ||
                                (destIp.StartsWith("127.") && destIp != "127.0.0.99") ||
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

                        // Manual JSON concatenation provides ultra-low latency string building
                        string json = "{\"Provider\":\"" + data.ProviderName + "\", \"EventName\":\"" + data.EventName + "\", \"TimeStamp\":\"" + data.TimeStamp.ToString("O") + "\", \"DestIp\":\"" + destIp + "\", \"Port\":\"" + port + "\", \"Query\":\"" + query + "\", \"Image\":\"" + image.Replace("\\", "\\\\") + "\", \"CommandLine\":\"" + cmdLine.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\", \"PID\":\"" + pid + "\", \"TID\":\"" + tid + "\", \"Size\":\"" + size + "\"}";
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