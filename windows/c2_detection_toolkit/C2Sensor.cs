/********************************************************************************
 * SYSTEM:          C2 Beacon Sensor - Active Defense / Infrastructure Exploitation
 * COMPONENT:       C2Sensor.cs (Unmanaged ETW Engine & FFI Bridge)
 * AUTHOR:          Robert Weber
 * VERSION:         1.0
 * * DESCRIPTION:
 * A high-performance, real-time Event Tracing for Windows (ETW) listener compiled
 * natively into the PowerShell runspace. Incorporates Native FFI boundaries
 * to execute the Rust ML engine (c2sensor_ml.dll) directly in memory, bypassing
 * IPC pipe latency.
 * * ARCHITECTURAL FEATURES:
 * - Native FFI Memory Map: Bypasses all IPC pipelines for zero-latency ML evaluation.
 * - Universal AppGuard: Monitors Kernel-Process events to intercept web shells.
 * - Cryptographic DPI (NDIS): Extracts TLS Client Hello signatures (JA3).
 * - O(1) Network Threat Intel: Implements zero-allocation binary searches to parse
 * compiled Suricata network signatures against live ETW streams at wire speed.
 ********************************************************************************/

using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using System.Text;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

public class RealTimeC2Sensor {
    // --- NATIVE RUST FFI BOUNDARIES ---
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool SetDllDirectory(string lpPathName);

    // Watchdog state
    private static int _lastEventsLost = 0;

    [DllImport("c2sensor_ml.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private static extern IntPtr init_engine();

    [DllImport("c2sensor_ml.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private static extern IntPtr evaluate_telemetry(IntPtr engine, string jsonPayload);

    [DllImport("c2sensor_ml.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr evaluate_flow(string json_payload);

    [DllImport("c2sensor_ml.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern void free_string(IntPtr s);

    [DllImport("c2sensor_ml.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern void teardown_engine(IntPtr engine);

    private static IntPtr _mlEnginePtr = IntPtr.Zero;

    // --- NATIVE CLR OBJECT BINDING ---
    public class C2Event {
        public string Provider { get; set; }
        public string EventName { get; set; }
        public string TimeStamp { get; set; }
        public string DestIp { get; set; }
        public string Port { get; set; }
        public string Query { get; set; }
        public string Image { get; set; }
        public string CommandLine { get; set; }
        public string PID { get; set; }
        public string TID { get; set; }
        public string Size { get; set; }
        public string ThreatIntel { get; set; }
        public string TrafficDirection { get; set; }
        public string Message { get; set; }
        public string Details { get; set; }
        public string Parent { get; set; }
        public string Child { get; set; }
        public string Trigger { get; set; }
        public string JA3 { get; set; }
        public string SuspiciousFlags { get; set; }
        public string RawJson { get; set; }
        public string Error { get; set; }
    }

    // Thread-safe queue passing strongly-typed objects instead of strings
    public static ConcurrentQueue<C2Event> EventQueue = new ConcurrentQueue<C2Event>();
    // Thread-safe cache to map PIDs to their Command Lines natively
    private static ConcurrentDictionary<int, string> ProcessCmdLines = new ConcurrentDictionary<int, string>();
    private static TraceEventSession _session;
    private static HashSet<string> DnsExclusions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    private static HashSet<string> ProcessExclusions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    private static List<System.Text.RegularExpressions.Regex> IpPrefixExclusions = new List<System.Text.RegularExpressions.Regex>();

    // --- NETWORK THREAT INTEL BINARY SEARCH ARRAYS ---
    private static uint[] CompiledIps = Array.Empty<uint>();
    private static ulong[] CompiledDomains = Array.Empty<ulong>();
    private static Dictionary<string, string> TiContext = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    // --- P2P LATERAL MOVEMENT STATE ---
    private static readonly string[] MaliciousPipes = {
        "\\msagent_", "\\postex_", "\\status_", // Cobalt Strike defaults
        "\\mypipe-f", "\\mypipe-h", "\\gilgamesh", // Common malleable profiles
        "\\mythic_", "\\sliver_", "\\psexec_svc" 
    };

    // AppGuard Web Server Hashsets
    private static HashSet<string> WebDaemons = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    private static HashSet<string> DbDaemons = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    private static HashSet<string> ShellInterpreters = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    private static string[] SuspiciousPaths = Array.Empty<string>();

    public static string EvaluateBatch(string jsonPayload) {
        if (_mlEnginePtr == IntPtr.Zero || string.IsNullOrEmpty(jsonPayload)) return "{}";

        IntPtr resultPtr = IntPtr.Zero;
        try {
            // MUST use evaluate_telemetry and pass the stateful _mlEnginePtr
            resultPtr = evaluate_telemetry(_mlEnginePtr, jsonPayload);

            if (resultPtr == IntPtr.Zero) return "{}";

            // Marshal the pointer back to a managed C# string
            string resultJson = Marshal.PtrToStringAnsi(resultPtr);
            return resultJson ?? "{}";

        } catch (Exception ex) {
            EventQueue.Enqueue(new C2Event { Provider = "DiagLog", Message = $"FFI MARSHAL ERROR: {ex.Message}" });
            return "{}";
        } finally {
            // Strict Memory Reclamation (CWE-415/416)
            if (resultPtr != IntPtr.Zero) {
                free_string(resultPtr);
            }
        }
    }

    // Initialization method to receive the exclusions, DLL path, and Threat Intel from PowerShell
    public static void InitializeEngine(
        string scriptDir, 
        string[] dnsExclusions, 
        string[] processExclusions, 
        string[] ipExclusions, 
        uint[] maliciousIps, 
        ulong[] maliciousDomains, 
        Dictionary<string, string> tiMap,
        string[] webDaemons, 
        string[] dbDaemons, 
        string[] shellInterpreters, 
        string[] suspiciousPaths)
    {
        // 1. Load DNS Exclusions
        foreach (string d in dnsExclusions) {
            DnsExclusions.Add(d.ToLowerInvariant());
        }

        // 2. Load Process Exclusions (O(1) Hash Lookup)
        foreach (string p in processExclusions) {
            ProcessExclusions.Add(p);
        }

        // 3. Load and Compile IP Regex Exclusions (Wire-speed regex)
        foreach (string ip in ipExclusions) {
            IpPrefixExclusions.Add(new System.Text.RegularExpressions.Regex(ip, System.Text.RegularExpressions.RegexOptions.Compiled));
        }

        SetDllDirectory(@"C:\ProgramData\C2Sensor\Bin");

        try {
            _mlEnginePtr = init_engine();
            if (_mlEnginePtr != IntPtr.Zero) {
                EventQueue.Enqueue(new C2Event { Provider = "DiagLog", Message = "[ML ENGINE] Native DLL successfully mapped at memory address: 0x" });
            } else {
                EventQueue.Enqueue(new C2Event { Provider = "DiagLog", Message = "[ML ENGINE ERROR] init_engine returned NULL." });
            }
        } catch (Exception ex) {
            EventQueue.Enqueue(new C2Event { Provider = "DiagLog", Message = "[ML ENGINE ERROR] FFI Import Failed: " + EscapeJson(ex.Message) });
        }

        // Load Network Threat Intel Binary Search Arrays
        if (maliciousIps != null && maliciousDomains != null) {
            CompiledIps = maliciousIps;
            CompiledDomains = maliciousDomains;
            TiContext = tiMap ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            EventQueue.Enqueue(new C2Event { Provider = "DiagLog", Message = $"[THREAT INTEL] Binary Search arrays loaded: {CompiledIps.Length} IPs, {CompiledDomains.Length} Domains." });
        }

        // Load AppGuard lists
        foreach (string w in webDaemons) WebDaemons.Add(w);
        foreach (string d in dbDaemons) DbDaemons.Add(d);
        foreach (string s in shellInterpreters) ShellInterpreters.Add(s);
        SuspiciousPaths = suspiciousPaths ?? Array.Empty<string>();

    }

    private static string EscapeJson(string s) {
        if (string.IsNullOrEmpty(s)) return "";
        return s
            .Replace("\\", "\\\\")
            .Replace("\"", "\\\"")
            .Replace("\n", "\\n")
            .Replace("\r", "\\r")
            .Replace("\t", "\\t")
            .Replace("\b", "\\b")
            .Replace("\f", "\\f");
    }

    private static ConcurrentDictionary<int, string> ActiveWebDaemons = new ConcurrentDictionary<int, string>();
    private static ConcurrentDictionary<int, string> ActiveDbDaemons = new ConcurrentDictionary<int, string>();

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

        if (result.Contains("::ffff:")) result = result.Replace("::ffff:", "");
        return result;
    }

    private static string FallbackIpExtract(byte[] payload, out string extractedPort) {
        extractedPort = "";
        if (payload == null || payload.Length < 8) return "DECODER_FAILED";
        string lastFound = "DECODER_FAILED";

        for (int i = 0; i < payload.Length - 7; i++) {
            if (payload[i] == 2 && payload[i+1] == 0) {
                if (payload[i+2] == 0 && payload[i+3] == 0) continue;

                int ip1 = payload[i+4]; int ip2 = payload[i+5]; int ip3 = payload[i+6]; int ip4 = payload[i+7];
                if (ip1 == 0 || ip1 == 127 || ip1 == 255) continue;

                string ipStr = ip1 + "." + ip2 + "." + ip3 + "." + ip4;
                lastFound = ipStr;

                if (ip1 == 10 || (ip1 == 192 && ip2 == 168) || (ip1 == 172 && ip2 >= 16 && ip2 <= 31) || (ip1 == 169 && ip2 == 254) || ip1 >= 224) continue;

                extractedPort = ((payload[i+2] << 8) | payload[i+3]).ToString();
                return ipStr;
            }
            else if (i < payload.Length - 23 && payload[i] == 23 && payload[i+1] == 0) {
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

    private static bool IsGrease(ushort val) { return (val & 0x0F0F) == 0x0A0A; }

    private static string ExtractJA3(byte[] payload, int offset, int length) {
        try {
            if (payload[offset] != 0x16 || payload[offset + 1] != 0x03) return null;
            if (payload[offset + 5] != 0x01) return null;

            int ptr = offset + 9;
            ushort sslVersion = (ushort)((payload[ptr] << 8) | payload[ptr + 1]);
            ptr += 2; ptr += 32;

            int sessionLength = payload[ptr];
            ptr += 1 + sessionLength;

            int cipherLength = (payload[ptr] << 8) | payload[ptr + 1];
            ptr += 2;
            List<ushort> ciphers = new List<ushort>();
            for (int i = 0; i < cipherLength; i += 2) {
                ushort cipher = (ushort)((payload[ptr + i] << 8) | payload[ptr + i + 1]);
                if (!IsGrease(cipher)) ciphers.Add(cipher);
            }
            ptr += cipherLength;

            int compLength = payload[ptr];
            ptr += 1 + compLength;

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
                        if (extType == 10 && extLen >= 2) {
                            int curveListLen = (payload[ptr] << 8) | payload[ptr + 1];
                            for (int i = 2; i < curveListLen + 2; i += 2) {
                                ushort curve = (ushort)((payload[ptr + i] << 8) | payload[ptr + i + 1]);
                                if (!IsGrease(curve)) curves.Add(curve);
                            }
                        }
                        else if (extType == 11 && extLen >= 1) {
                            int formatListLen = payload[ptr];
                            for (int i = 1; i < formatListLen + 1; i++) {
                                pointFormats.Add(payload[ptr + i]);
                            }
                        }
                    }
                    ptr += extLen;
                }
            }

            string ja3String = string.Format("{0},{1},{2},{3},{4}", sslVersion, string.Join("-", ciphers), string.Join("-", extensions), string.Join("-", curves), string.Join("-", pointFormats));

            using (MD5 md5 = MD5.Create()) {
                byte[] hashBytes = md5.ComputeHash(Encoding.UTF8.GetBytes(ja3String));
                StringBuilder sb = new StringBuilder();
                foreach (byte b in hashBytes) sb.Append(b.ToString("x2"));
                return sb.ToString();
            }
        } catch { return null; }
    }

    public static void StartSession() {
        Task.Run(() => {
            try {
                if (TraceEventSession.GetActiveSessionNames().Contains("C2RealTimeSession")) {
                    var oldSession = new TraceEventSession("C2RealTimeSession");
                    oldSession.Dispose();
                }

                _session = new TraceEventSession("C2RealTimeSession");
                _session.EnableProvider("Microsoft-Windows-Kernel-Process", TraceEventLevel.Informational, 0x10);
                _session.EnableProvider("Microsoft-Windows-TCPIP", TraceEventLevel.Informational, 0xFFFFFFFF);
                _session.EnableProvider("Microsoft-Windows-NetworkProfile", TraceEventLevel.Informational, 0xFFFFFFFF);
                _session.EnableProvider("Microsoft-Windows-DNS-Client");
                _session.EnableProvider("Microsoft-Windows-Kernel-File");
                _session.EnableProvider("Microsoft-Windows-Kernel-Memory");
                _session.EnableProvider("Microsoft-Windows-NDIS-PacketCapture");

                _session.Source.Dynamic.All += delegate (TraceEvent data) {
                    try {
                        string evName = data.EventName;

                        // Immediately drop high-frequency background noise before doing ANY work
                        if (evName == "ThreadWorkOnBehalfUpdate" ||
                            evName == "CpuPriorityChange" ||
                            evName.StartsWith("Thread") ||
                            evName == "TcpConnectionRundown" ||
                            evName == "UdpEndpointRundown" ||
                            evName == "ImageLoad" ||
                            evName == "ImageUnload" ||
                            evName == "SystemCall" ||
                            evName == "Acg" ||
                            evName == "CreateNewFile" ||
                            evName.StartsWith("MemInfo") ||
                            evName.StartsWith("File"))
                        {
                            return;
                        }

                        string pName = data.ProviderName;

                        // Pwsh passed exclusion arrays
                        string imagePath = data.PayloadStringByName("ImageFileName") ?? "";
                        if (!string.IsNullOrEmpty(imagePath)) {
                            string cleanProc = System.IO.Path.GetFileNameWithoutExtension(imagePath);
                            if (ProcessExclusions.Contains(cleanProc)) {
                                return;
                            }
                        }

                        string destIp = data.PayloadStringByName("daddr") ?? data.PayloadStringByName("DestAddress") ?? "";
                        if (!string.IsNullOrEmpty(destIp)) {
                            if (destIp.StartsWith("127.") || destIp.StartsWith("224.") || destIp.StartsWith("239.") || destIp == "255.255.255.255") {
                                return;
                            }
                            foreach (var rx in IpPrefixExclusions) {
                                if (rx.IsMatch(destIp)) return;
                            }
                        }

                        if (data.ProviderName.Contains("Kernel-Process") && data.EventName.Contains("Start")) {
                            string cmd = (data.PayloadStringByName("CommandLine") ?? "").ToLower();
                            if (cmd.Contains("logman") && (cmd.Contains("stop") || cmd.Contains("delete")) && cmd.Contains("c2realtimesession")) {
                                EventQueue.Enqueue(new C2Event { Provider = "TamperGuard", EventName = "ETW_STOP_ATTEMPT", Details = "A process attempted to blind the C2 ETW Session via Logman." });
                            }
                        }

                        if (data.ProviderName.Contains("Kernel-Memory") && data.EventName.Contains("VirtualProtect")) {
                            object protectionObj = data.PayloadByName("NewProtection");
                            if (protectionObj != null) {
                                uint protection = Convert.ToUInt32(protectionObj);
                                if (protection == 0x40) {
                                    string proc = string.IsNullOrEmpty(data.ProcessName) ? data.ProcessID.ToString() : data.ProcessName;
                                        EventQueue.Enqueue(new C2Event { Provider = "TamperGuard", EventName = "MEMORY_PATCH_DETECTED", Details = "Suspicious RWX permission change detected in process: " + proc });                              }
                            }
                        }

                        if (data.ProviderName.Contains("Kernel-Process")) {
                            if (data.EventName.Contains("Start")) {
                                string imageClean = System.IO.Path.GetFileNameWithoutExtension(data.PayloadStringByName("ImageFileName") ?? "").ToLower();
                                string processCmd = data.PayloadStringByName("CommandLine") ?? "";

                                // Uncontrolled Resource Consumption Protection (CWE-400)
                                if (processCmd.Length > 4096) {
                                    processCmd = processCmd.Substring(0, 4096) + " ...[TRUNCATED BY SENSOR LIMIT]";
                                }

                                if (!string.IsNullOrEmpty(processCmd)) {
                                    ProcessCmdLines[data.ProcessID] = processCmd;
                                }

                                if (WebDaemons.Contains(imageClean)) {
                                    string context = data.PayloadStringByName("CommandLine") ?? imageClean;
                                    ActiveWebDaemons[data.ProcessID] = context;
                                }
                                else if (DbDaemons.Contains(imageClean)) {
                                    string context = data.PayloadStringByName("CommandLine") ?? imageClean;
                                    ActiveDbDaemons[data.ProcessID] = context;
                                }
                            }
                            else if (data.EventName.Contains("Stop")) {
                                string removedContext;
                                ActiveWebDaemons.TryRemove(data.ProcessID, out removedContext);
                                ActiveDbDaemons.TryRemove(data.ProcessID, out removedContext);
                                ProcessCmdLines.TryRemove(data.ProcessID, out removedContext);
                            }

                            if (data.EventName.Contains("Start")) {
                                int parentPid = Convert.ToInt32(data.PayloadByName("ParentProcessID") ?? -1);

                                bool isWebParent = ActiveWebDaemons.ContainsKey(parentPid);
                                bool isDbParent = ActiveDbDaemons.ContainsKey(parentPid);

                                if (isWebParent || isDbParent) {
                                    string childPath = data.PayloadStringByName("ImageFileName") ?? "";
                                    string childClean = System.IO.Path.GetFileNameWithoutExtension(childPath).ToLower();
                                    string childCmdLine = data.PayloadStringByName("CommandLine") ?? "";

                                    bool isInterpreter = ShellInterpreters.Contains(childClean);
                                    bool isSuspiciousPath = false;

                                    foreach (string path in SuspiciousPaths) {
                                        if (childPath.ToLower().Contains(path)) { isSuspiciousPath = true; break; }
                                    }

                                    if (isInterpreter || isSuspiciousPath) {
                                        if (isWebParent && (childClean == "csc" || childClean == "cvtres") && childCmdLine.IndexOf("Temporary ASP.NET Files", StringComparison.OrdinalIgnoreCase) >= 0) {
                                            return;
                                        }

                                        string parentContext = isWebParent ? ActiveWebDaemons[parentPid] : ActiveDbDaemons[parentPid];
                                        string eventType = isWebParent ? "WEB_SHELL_DETECTED" : "DB_RCE_DETECTED";
                                        string trigger = isInterpreter ? "Command Interpreter" : "Unauthorized Directory";

                                        EventQueue.Enqueue(new C2Event { Provider = "AppGuard", EventName = eventType, Parent = parentContext, Child = childClean, Trigger = trigger, CommandLine = childCmdLine });
                                    }
                                }
                            }
                        }

                        if (data.ProviderName.Contains("NDIS-PacketCapture")) {
                            try {
                                byte[] frame = (byte[])data.PayloadByName("Fragment");
                                if (frame == null || frame.Length < 60) return;   // Minimum Ethernet+IP+TCP header

                                // Ethernet II header: EtherType IPv4 (0x0800)
                                if (frame.Length < 14 || frame[12] != 0x08 || frame[13] != 0x00) return;

                                int ipHeaderStart = 14;
                                if (frame.Length < ipHeaderStart + 20) return;

                                // IPv4 only for now (protocol 6 = TCP)
                                if (frame[ipHeaderStart + 9] != 0x06) return;

                                int ihl = (frame[ipHeaderStart] & 0x0F) * 4;           // Internet Header Length
                                int tcpHeaderStart = ipHeaderStart + ihl;

                                if (frame.Length < tcpHeaderStart + 20) return;

                                int destPort = (frame[tcpHeaderStart + 2] << 8) | frame[tcpHeaderStart + 3];
                                if (destPort != 443 && destPort != 8443) return;      // Only interested in common HTTPS ports

                                int dataOffset = (frame[tcpHeaderStart + 12] >> 4) * 4;
                                int payloadStart = tcpHeaderStart + dataOffset;
                                int payloadLength = frame.Length - payloadStart;

                                if (payloadLength > 5) {
                                    string ja3Hash = ExtractJA3(frame, payloadStart, payloadLength);
                                    if (!string.IsNullOrEmpty(ja3Hash)) {
                                        string ndisDestIp = $"{frame[ipHeaderStart + 16]}.{frame[ipHeaderStart + 17]}.{frame[ipHeaderStart + 18]}.{frame[ipHeaderStart + 19]}";
                                        EventQueue.Enqueue(new C2Event { Provider = "NDIS", EventName = "TLS_JA3_FINGERPRINT", DestIp = ndisDestIp, Port = destPort.ToString(), JA3 = ja3Hash });
                                    }
                                }
                            } catch {
                            }
                            return;
                        }

                        if (data.ProviderName.Contains("Kernel-File") && (data.EventName == "Create" || data.EventName == "NameCreate")) {
                            string fileName = (data.PayloadStringByName("FileName") ?? "").ToLowerInvariant();

                            // High-speed filter: only process Named Pipes
                            if (fileName.Contains("\\device\\namedpipe\\") || fileName.Contains("\\pipe\\")) {
                                foreach (string pipePattern in MaliciousPipes) {
                                    if (fileName.Contains(pipePattern)) {
                                        string pipeProc = string.IsNullOrEmpty(data.ProcessName) ? data.ProcessID.ToString() : data.ProcessName;
                                        EventQueue.Enqueue(new C2Event { Provider = "P2P_Guard", EventName = "MALICIOUS_PIPE_CREATED", Image = pipeProc, CommandLine = fileName, SuspiciousFlags = "Known C2 Named Pipe" });
                                        break;
                                    }
                                }
                            }
                            return; // Drop all other file events to preserve CPU
                        }

                        if (data.ProviderName.Contains("DNS") && (int)data.ID != 3008) return;

                        destIp = ""; string port = ""; string query = ""; string size = "0";
                        string pid = data.ProcessID.ToString();
                        string tid = data.ThreadID.ToString();
                        string image = string.IsNullOrEmpty(data.ProcessName) ? "Unknown" : data.ProcessName;

                        string cmdLine = "";
                        if (ProcessCmdLines.TryGetValue(data.ProcessID, out string cachedCmd)) {
                            cmdLine = cachedCmd;
                        }

                        bool isNetworkEvent = data.ProviderName.Contains("TCPIP") || data.ProviderName.Contains("Network");

                        for (int i = 0; i < data.PayloadNames.Length; i++) {
                            string name = data.PayloadNames[i].ToLower();
                            object pVal = data.PayloadValue(i);

                            if (name == "destinationip" || name == "daddr" || name == "destaddress" || name == "destination") {
                                string parsedIp = ParseIp(pVal);
                                if (!string.IsNullOrEmpty(parsedIp) && !parsedIp.Contains("EXCEPTION")) { destIp = parsedIp; }
                                continue;
                            }

                            string pStr = pVal != null ? pVal.ToString() : "";
                            if (pStr.Contains("EXCEPTION") || string.IsNullOrEmpty(pStr)) continue;

                            if (name == "queryname" || name == "query") query = pStr;
                            else if (name == "commandline") cmdLine = pStr;
                            else if (name == "size" || name == "bytessent" || name == "length") size = pStr;
                            else if (name.Contains("port") && !name.Contains("source") && !name.Contains("sport")) {
                                int rp;
                                if (int.TryParse(pStr, out rp)) {
                                    if (rp > 65535) rp = rp & 0xFFFF;
                                    int swapped = ((rp & 0xFF) << 8) | ((rp >> 8) & 0xFF);
                                    if (swapped == 80 || swapped == 443 || swapped == 8080 || swapped == 8443) port = swapped.ToString();
                                    else port = (swapped < rp && swapped > 0) ? swapped.ToString() : rp.ToString();
                                } else { port = pStr; }
                            }
                        }

                        if (isNetworkEvent && (string.IsNullOrEmpty(destIp) || string.IsNullOrEmpty(port) || port == "0")) {
                            try {
                                byte[] rawPayload = data.EventData();
                                string fbPort;
                                string fbIp = FallbackIpExtract(rawPayload, out fbPort);

                                if (string.IsNullOrEmpty(destIp)) destIp = fbIp;
                                if (string.IsNullOrEmpty(port) || port == "0") port = fbPort;
                            } catch { if (string.IsNullOrEmpty(destIp)) destIp = "DECODER_FAILED"; }
                        }

                        string trafficDirection = "Egress";

                        if (isNetworkEvent) {
                            bool isPrivateIp = destIp.StartsWith("192.168.") || destIp.StartsWith("10.") || destIp.StartsWith("172.");

                            if (isPrivateIp) {
                                // Only allow lateral tracking for specific P2P ports (SMB, RPC, WinRM)
                                if (port == "445" || port == "135" || port == "5985" || port == "5986") {
                                    trafficDirection = "Lateral";
                                } else {
                                    return; // Drop internal web/broadcast noise
                                }
                            } else if (destIp.StartsWith("127.") && destIp != "127.0.0.99" || 
                                       destIp.StartsWith("169.254.") || destIp.StartsWith("224.") || 
                                       destIp.StartsWith("239.") || destIp.StartsWith("fe80") || destIp == "::1" || destIp == "DECODER_FAILED") {
                                return;
                            }
                        }

                        // --- NETWORK THREAT INTEL BINARY SEARCH EVALUATION ---
                        string threatIntelTag = "";

                        if (isNetworkEvent && !string.IsNullOrEmpty(destIp)) {
                            uint ipVal = IpToUint(destIp);
                            if (ipVal != 0 && Array.BinarySearch(CompiledIps, ipVal) >= 0) {
                                TiContext.TryGetValue(destIp, out string ruleName);
                                threatIntelTag = ruleName ?? "Suricata: Malicious IP Match";
                            }
                        }

                        if (string.IsNullOrEmpty(threatIntelTag) && data.ProviderName.Contains("DNS") && !string.IsNullOrEmpty(query)) {
                            string cleanQuery = !query.StartsWith(".") ? "." + query : query;
                            int idx = 0;
                            while (idx < cleanQuery.Length) {
                                ulong domHash = 14695981039346656037;
                                for (int i = idx; i < cleanQuery.Length; i++) {
                                    domHash ^= char.ToLowerInvariant(cleanQuery[i]);
                                    domHash *= 1099511628211;
                                }
                                if (domHash != 0 && Array.BinarySearch(CompiledDomains, domHash) >= 0) {
                                    // Match found. Allocate string exclusively for the dictionary lookup.
                                    string matchedSub = cleanQuery.Substring(idx);
                                    TiContext.TryGetValue(matchedSub, out string ruleName);
                                    threatIntelTag = ruleName ?? "Suricata: Malicious Domain Match";
                                    break;
                                }
                                // Shift index to the next subdomain segment
                                idx = cleanQuery.IndexOf('.', idx + 1);
                                if (idx == -1) break;
                            }
                        }

                        if (data.ProviderName.Contains("DNS") && !string.IsNullOrEmpty(query)) {
                            string qLow = query.ToLower().TrimEnd('.');
                            bool skipDns = false;
                            foreach (string exclusion in DnsExclusions) {
                                if (qLow.EndsWith(exclusion)) { skipDns = true; break; }
                            }
                            if (skipDns) return;
                        }

                        // Embed the Threat Intel tag AND Traffic Direction directly into the standard telemetry payload
                        string effectiveDest = string.IsNullOrEmpty(destIp) ? query : destIp;
                        string effectivePort = (string.IsNullOrEmpty(port) || port == "0") ? (data.ProviderName.Contains("DNS") ? "53" : "0") : port;
                        string safeProvider = EscapeJson(data.ProviderName ?? "Unknown");
                        string safeEventName = EscapeJson(data.EventName ?? "Unknown");
                        string safeDestIp    = EscapeJson(effectiveDest ?? "");
                        string safePort      = EscapeJson(effectivePort ?? "");
                        string safeQuery     = EscapeJson(query ?? "");
                        string safeImage     = EscapeJson(image ?? "Unknown");
                        string safeCmdLine   = EscapeJson(cmdLine ?? "");
                        string safeThreatIntel = EscapeJson(threatIntelTag ?? "");
                        string safeTrafficDirection = EscapeJson(trafficDirection ?? "Egress");

                        string timeStampStr = data.TimeStamp.ToString("O");
                        string json = null;

                        json = string.Format(@"{{""Provider"":""{0}"",""EventName"":""{1}"",""TimeStamp"":""{2}"",""DestIp"":""{3}"",""Port"":""{4}"",""Query"":""{5}"",""Image"":""{6}"",""CommandLine"":""{7}"",""PID"":""{8}"",""TID"":""{9}"",""Size"":""{10}"",""ThreatIntel"":""{11}"",""TrafficDirection"":""{12}""}}",
                            safeProvider, safeEventName, timeStampStr, safeDestIp, safePort, safeQuery, safeImage, safeCmdLine, pid, tid, size, safeThreatIntel, safeTrafficDirection);

                        EventQueue.Enqueue(new C2Event {
                            Provider = data.ProviderName,
                            EventName = data.EventName,
                            TimeStamp = timeStampStr,
                            DestIp = destIp,
                            Port = port,
                            Query = query,
                            Image = image,
                            CommandLine = cmdLine,
                            PID = pid,
                            TID = tid,
                            Size = size,
                            ThreatIntel = threatIntelTag,
                            TrafficDirection = trafficDirection,
                            RawJson = json
                        });

                    } catch (Exception ex) {
                        try {
                            EventQueue.Enqueue(new C2Event { Provider = "DiagLog", Message = "[ETW HOTPATH ERROR] " + EscapeJson(ex.Message) });
                        } catch { /* prevent recursive failure if enqueue itself fails */ }
                    }
                };
                _session.Source.Process();
            } catch (Exception ex) {
                EventQueue.Enqueue(new C2Event { Error = EscapeJson(ex.Message) });
            }
        });

        // Telemetry Blinding - Background Watchdog for ETW Buffer Exhaustion
        Task.Run(async () => {
            while (IsSessionHealthy()) {
                await Task.Delay(2000); // Check every 2 seconds
                if (_session != null && _session.EventsLost > _lastEventsLost) {
                    int dropped = _session.EventsLost - _lastEventsLost;
                    _lastEventsLost = _session.EventsLost;

                    EventQueue.Enqueue(new C2Event { 
                        Provider = "DiagLog", 
                        Message = $"SENSOR_BLINDING_DETECTED:{dropped}" 
                    });
                }
            }
        });
    }

    // ZERO-ALLOCATION THREAT INTEL MATH HELPERS
    public static ulong HashDomain(string domain) {
        if (string.IsNullOrEmpty(domain)) return 0;
        ulong hash = 14695981039346656037;
        for (int i = 0; i < domain.Length; i++) {
            hash ^= char.ToLowerInvariant(domain[i]);
            hash *= 1099511628211;
        }
        return hash;
    }

    public static uint IpToUint(string ipAddress) {
        if (System.Net.IPAddress.TryParse(ipAddress, out var address)) {
            byte[] bytes = address.GetAddressBytes();
            if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
            return BitConverter.ToUInt32(bytes, 0);
        }
        return 0;
    }

    public static void StopSession() {
        if (_session != null) {
            _session.Stop();
            _session.Dispose();
            _session = null;
        }

        if (_mlEnginePtr != IntPtr.Zero) {
            teardown_engine(_mlEnginePtr);
            _mlEnginePtr = IntPtr.Zero;
            EventQueue.Enqueue(new C2Event { Provider = "DiagLog", Message = "[ML ENGINE] Native Rust DLL safely unloaded and DB flushed." });
        }
    }

    // Healthcheck
    public static bool IsSessionHealthy() {
        if (_session == null) return false;
        try {
            return _session.Source != null;
        }
        catch {
            return false;
        }
    }
}