using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace C2Console
{
    // ====================== DATA STRUCTURES ======================
    public class FlowMetadata {
        public Queue<string> DstIps { get; set; } = new Queue<string>();
        public Queue<int> PacketSizes { get; set; } = new Queue<int>();
        public string Domain { get; set; } = "Unknown";
        public string Image { get; set; } = "Unknown";
        
        // TUNE: Data Exfiltration Trackers
        public long TotalBytesOut { get; set; } = 0;
        public long TotalBytesIn { get; set; } = 0;
    }

    public class AlertEvent {
        public string EventID { get; set; } = Guid.NewGuid().ToString();
        public int Count { get; set; } = 1;
        public string Timestamp_Local { get; set; } = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
        public string ComputerName { get; set; } = Environment.MachineName;
        public string HostIP { get; set; }
        public string SensorUser { get; set; }
        public string EventType { get; set; }
        public string Destination { get; set; }
        public string Image { get; set; }
        public string SuspiciousFlags { get; set; }
        public string ATTCKMappings { get; set; }
        public int Confidence { get; set; }
        public string Action { get; set; }
    }

    class Program
    {
        // ====================== NATIVE OS API CALLS ======================
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetStdHandle(int nStdHandle);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);

        public static void DisableQuickEdit() {
            IntPtr consoleHandle = GetStdHandle(-10);
            if (GetConsoleMode(consoleHandle, out uint consoleMode)) {
                consoleMode &= ~0x0040U;
                SetConsoleMode(consoleHandle, consoleMode);
            }
        }

        // ====================== V2 CONFIGURATION ======================
        static readonly bool ArmedMode = true;
        static readonly int ConfidenceThreshold = 85;
        static readonly int BatchAnalysisIntervalSeconds = 15;
        static readonly int MinSamplesForML = 3;

        static readonly string BaseDir = @"C:\ProgramData\C2Sensor";
        static readonly string DataDir = $@"{BaseDir}\Data";
        static readonly string LogDir = $@"{BaseDir}\Logs";
        static readonly string AlertLogPath = $@"{LogDir}\C2Sensor_Alerts.jsonl";
        static readonly string UebaLogPath = $@"{LogDir}\C2Sensor_UEBA.jsonl";
        static readonly string DiagLogPath = $@"{LogDir}\C2Sensor_Diagnostic.log";
        static readonly string TamperLogPath = $@"{DataDir}\C2Sensor_TamperGuard.log";
        static readonly string Ja3CachePath = $@"{DataDir}\C2Sensor_JA3_Cache.json";

        // Global State & UI
        static string HostIP = "Unknown";
        static string SensorUser = Environment.UserDomainName + "\\" + Environment.UserName;
        static StreamWriter DiagWriter;
        static StreamWriter TamperWriter;
        static readonly object FileLock = new object();

        // Tracker Dictionaries
        static ConcurrentDictionary<string, Queue<DateTime>> ConnectionHistory = new();
        static ConcurrentDictionary<string, FlowMetadata> FlowMeta = new();
        static ConcurrentDictionary<string, DateTime> LastPingTime = new();
        static ConcurrentDictionary<string, int> LoggedFlows = new();
        
        // Single-Threaded Trackers (Safe within main event loop)
        static Dictionary<string, AlertEvent> CycleAlerts = new();
        static Dictionary<string, int> UebaLearningCache = new();
        static Dictionary<string, DateTime> LateralTrack = new();
        static Dictionary<string, DateTime> EgressTrack = new();
        static Dictionary<int, string> ProcessCache = new();
        static HashSet<string> MaliciousJA3Cache = new(StringComparer.OrdinalIgnoreCase);

        // Batches
        static List<string> UebaBatch = new();
        static List<AlertEvent> DataBatch = new();

        // Metrics
        static int TotalMitigations = 0;
        static int GlobalMlSent = 0;
        static int GlobalMlAlerts = 0;
        static long OutboundNetEvents = 0;
        static int TotalLateralFlows = 0;
        static bool SensorBlinded = false;
        static DateTime LastEventReceived = DateTime.Now;

        static async Task Main(string[] args)
        {
            DisableQuickEdit();
            InitializeEnvironment();
            GetHostIP();
            
            Console.Title = "C2 Beacon Sensor v2 | Native FFI Architecture";
            Console.Clear();
            WriteDiag("=== C2 SENSOR V2 NATIVE EXECUTABLE INITIALIZED ===", "STARTUP");

            string appDir = AppDomain.CurrentDomain.BaseDirectory;

            // 1. Initialize Threat Intel (JA3 & Suricata)
            await SyncJA3Signatures();
            var ti = await ThreatIntelCompiler.SyncAndCompileRules(appDir);

            // 2. Hook Native ETW Engine & Load Configuration
            string configPath = Path.Combine(appDir, "C2Sensor_Config.ini");
            WriteDiag("Loading external configuration...", "STARTUP");
            var config = LoadConfig(configPath);

            WriteDiag("Starting Real-Time ETW Session...", "STARTUP");
            RealTimeC2Sensor.InitializeEngine(
                scriptDir: appDir,
                dnsExclusions: config.GetValueOrDefault("DnsExclusions", Array.Empty<string>()),
                processExclusions: config.GetValueOrDefault("ProcessExclusions", Array.Empty<string>()),
                ipExclusions: config.GetValueOrDefault("IpExclusions", Array.Empty<string>()),
                maliciousIps: ti.Ips,
                maliciousDomains: ti.Domains,
                tiMap: ti.Context,
                webDaemons: config.GetValueOrDefault("WebDaemons", Array.Empty<string>()),
                dbDaemons: config.GetValueOrDefault("DbDaemons", Array.Empty<string>()),
                shellInterpreters: config.GetValueOrDefault("ShellInterpreters", Array.Empty<string>()),
                suspiciousPaths: config.GetValueOrDefault("SuspiciousPaths", Array.Empty<string>())
            );

            RealTimeC2Sensor.StartSession();
            WriteDiag("C# ETW Engine Hooked. Native Event Queue active.", "STARTUP");

            Console.CancelKeyPress += (sender, e) => {
                e.Cancel = true;
                ShutdownSequence();
            };

            // Enter Main Logic Loop
            MainEventLoop();
        }

        // ====================== MAIN EVENT LOOP ======================
        static void MainEventLoop()
        {
            DateTime lastMLRunTime = DateTime.Now;
            DateTime lastCleanupTime = DateTime.Now;
            DateTime lastLightGC = DateTime.Now;
            DateTime lastUebaCleanup = DateTime.Now;

            while (true)
            {
                DateTime now = DateTime.Now;
                int loopCount = 0;

                while (RealTimeC2Sensor.EventQueue.TryDequeue(out var evt))
                {
                    if (evt == null) continue;
                    loopCount++;
                    LastEventReceived = now;

                    if (evt.Provider == "DiagLog") { WriteDiag(evt.Message, "INFO"); continue; }
                    if (!string.IsNullOrEmpty(evt.Error)) {
                        WriteDiag($"FATAL ETW CRASH: {evt.Error}", "ERROR");
                        continue;
                    }

                    // --- NAMED PIPE DETECTION ---
                    if (evt.Provider == "P2P_Guard") {
                        SubmitAlert("Lateral_Movement", "Local_Pipe", evt.Image, $"Malicious Named Pipe: {evt.CommandLine}", 95, "T1570");
                        continue;
                    }

                    // --- TRAFFIC STATE TRACKING & PROXY CORRELATION ---
                    if (!string.IsNullOrEmpty(evt.TrafficDirection)) {
                        string procKey = $"{evt.Image}_{evt.PID}";
                        if (evt.TrafficDirection == "Lateral") {
                            LateralTrack[procKey] = now;
                            TotalLateralFlows++;
                        } else if (evt.TrafficDirection == "Egress" && !string.IsNullOrEmpty(evt.DestIp)) {
                            EgressTrack[procKey] = now;
                        }

                        if (EgressTrack.TryGetValue(procKey, out DateTime eTime) && LateralTrack.TryGetValue(procKey, out DateTime lTime)) {
                            if (Math.Abs((eTime - lTime).TotalSeconds) < 60) {
                                SubmitAlert("Proxy_Node_Behavior", "Network_Bridge", evt.Image, "Simultaneous Internal SMB/RPC and External Egress Routing", 85, "T1090.001");
                            }
                        }
                    }

                    // --- TLS JA3 FINGERPRINT DETECTION ---
                    if (evt.Provider == "NDIS" && evt.EventName == "TLS_JA3_FINGERPRINT") {
                        WriteDiag($"JA3 HASH EXTRACTED: {evt.DestIp} -> {evt.JA3}", "INFO");
                        if (MaliciousJA3Cache.Contains(evt.JA3)) {
                            string owningProcess = "Unknown";
                            foreach (var kvp in FlowMeta) {
                                if (kvp.Key.Contains($"IP_{evt.DestIp}") && kvp.Value.Image != "Unknown") {
                                    owningProcess = Path.GetFileNameWithoutExtension(kvp.Value.Image);
                                    break;
                                }
                            }
                            SubmitAlert("JA3_C2_FINGERPRINT", evt.DestIp, owningProcess, $"Matched Profile: {evt.JA3}", 100, "T1071.001");
                        }
                        continue;
                    }

                    // --- APPGUARD DETECTION ---
                    if (evt.Provider == "AppGuard") {
                        WriteDiag($"APPGUARD HIT: {evt.Parent} spawned {evt.Child} | CMD: {evt.CommandLine}", "WARN");
                        string mitre = evt.EventName == "WEB_SHELL_DETECTED" ? "T1505.003; T1190; T1059" : "T1190; T1569.002; T1059";
                        SubmitAlert(evt.EventName, "Local_Privilege_Escalation", evt.Child, $"Server App ({evt.Parent}) Spawned Shell | Cmd: {evt.CommandLine}", 100, mitre);
                        continue;
                    }

                    // --- NOISE REDUCTION / PROCESS CACHE ---
                    string procName = "Unknown";
                    if (!string.IsNullOrEmpty(evt.Image) && evt.Image != "Unknown") {
                        procName = Path.GetFileNameWithoutExtension(evt.Image).ToLower();
                    } else if (int.TryParse(evt.PID, out int pidInt) && pidInt != 0 && pidInt != 4) {
                        if (!ProcessCache.TryGetValue(pidInt, out procName)) {
                            try { procName = Process.GetProcessById(pidInt).ProcessName.ToLower(); } 
                            catch { procName = "terminated"; }
                            ProcessCache[pidInt] = procName;
                        }
                    }

                    // --- SURICATA -> UEBA DRIVEN ALERT ---
                    if (!string.IsNullOrEmpty(evt.ThreatIntel)) {
                        string learningKey = $"{procName}|{evt.ThreatIntel}";
                        if (!UebaLearningCache.ContainsKey(learningKey)) UebaLearningCache[learningKey] = 0;
                        UebaLearningCache[learningKey]++;
                        
                        int hits = UebaLearningCache[learningKey];
                        bool isAnomaly = hits >= 3;
                        int confidence = isAnomaly ? 95 : 75;
                        string context = hits == 1 ? "NEW LEARNING" : (isAnomaly ? "CONFIRMED ANOMALY" : "LEARNING");
                        
                        string targetDest = !string.IsNullOrEmpty(evt.DestIp) ? evt.DestIp : evt.Query;
                        
                        SubmitAlert("ThreatIntel_Match", targetDest, procName, $"[{context}] {evt.ThreatIntel}", confidence, "T1071", evt.RawJson, hits);
                    }

                    // --- STATIC BEHAVIORAL GATES ---
                    List<string> sFlags = new();
                    List<string> sMitre = new();

                    if (evt.Provider == "Microsoft-Windows-Kernel-Process" && Regex.IsMatch(evt.CommandLine ?? "", @"-EncodedCommand|-enc|IEX", RegexOptions.IgnoreCase)) {
                        sFlags.Add("Anomalous CommandLine"); sMitre.Add("TA0002: T1059.001");
                    }
                    if (evt.Provider == "Microsoft-Windows-Kernel-File" && Regex.IsMatch(evt.Image ?? "", @"\.ps1$|\.exe$", RegexOptions.IgnoreCase)) {
                        sFlags.Add("Executable File Created"); sMitre.Add("TA0002: T1059");
                    }
                    if (evt.Provider == "Microsoft-Windows-DNS-Client" && !string.IsNullOrEmpty(evt.Query)) {
                        if (evt.Query.Length > 10 && Regex.IsMatch(evt.Query, @"^[a-zA-Z0-9\-\.]+$")) {
                            if (MathHelpers.IsAnomalousDomain(evt.Query.TrimEnd('.'))) {
                                sFlags.Add("DGA DNS Query Detected"); sMitre.Add("TA0011: T1568.002");
                            }
                        }
                    }

                    if (sFlags.Count > 0) {
                        string destStatic = !string.IsNullOrEmpty(evt.DestIp) ? evt.DestIp : (!string.IsNullOrEmpty(evt.Query) ? evt.Query : "Unknown");
                        SubmitAlert("Static_Detection", destStatic, procName, string.Join("; ", sFlags), 90, string.Join("; ", sMitre));
                    }

                    // --- SLIDING WINDOWS ---
                    if ((evt.Provider.Contains("TCPIP") || evt.Provider.Contains("Network")) && 
                        !string.IsNullOrEmpty(evt.DestIp) && !Regex.IsMatch(evt.DestIp, @"^192\.168\.|^10\.|^127\.|^172\.")) 
                    {
                        OutboundNetEvents++;
                        string safePort = string.IsNullOrEmpty(evt.Port) || evt.Port == "0" ? $"IP_{evt.DestIp}" : evt.Port;
                        string key = (evt.PID == "4" || evt.PID == "0") ? 
                            $"PID_{evt.PID}_TID_{evt.TID}_IP_{evt.DestIp}_Port_{safePort}" : 
                            $"PID_{evt.PID}_TID_{evt.TID}_Port_{safePort}";

                        if (!ConnectionHistory.ContainsKey(key)) {
                            ConnectionHistory[key] = new Queue<DateTime>();
                            FlowMeta[key] = new FlowMetadata { Domain = !string.IsNullOrEmpty(evt.Query) ? evt.Query : evt.DestIp, Image = evt.Image };
                        }

                        bool isNewPing = true;
                        if (LastPingTime.TryGetValue(key, out DateTime lastPing) && (now - lastPing).TotalMilliseconds < 100) {
                            isNewPing = false;
                        }

                        if (isNewPing) {
                            ConnectionHistory[key].Enqueue(now);
                            LastPingTime[key] = now;
                            FlowMeta[key].DstIps.Enqueue(evt.DestIp);
                            int size = int.TryParse(evt.Size, out int parsed) ? parsed : 0;
                            FlowMeta[key].PacketSizes.Enqueue(size);

                            // Track Asymmetry
                            if (evt.EventName.Contains("Send")) FlowMeta[key].TotalBytesOut += size;
                            else if (evt.EventName.Contains("Recv")) FlowMeta[key].TotalBytesIn += size;

                            while (ConnectionHistory[key].Count > 100) ConnectionHistory[key].Dequeue();
                            while (FlowMeta[key].DstIps.Count > ConnectionHistory[key].Count) FlowMeta[key].DstIps.Dequeue();
                            while (FlowMeta[key].PacketSizes.Count > ConnectionHistory[key].Count) FlowMeta[key].PacketSizes.Dequeue();
                        }
                    }
                } // End Dequeue

                // --- 15 SECOND: ML HANDOFF & ALERT FLUSH ---
                if ((now - lastMLRunTime).TotalSeconds >= BatchAnalysisIntervalSeconds) {
                    ExecuteMlHandoff(now);
                    FlushCycleAlerts();
                    lastMLRunTime = now;
                }

                if ((now - lastCleanupTime).TotalSeconds >= 60) {
                    var staleKeys = LastPingTime.Where(kvp => (now - kvp.Value).TotalHours > 12).Select(kvp => kvp.Key).ToList();
                    foreach (var key in staleKeys) {
                        ConnectionHistory.TryRemove(key, out _); FlowMeta.TryRemove(key, out _);
                        LoggedFlows.TryRemove(key, out _); LastPingTime.TryRemove(key, out _);
                    }
                    lastCleanupTime = now;
                }

                if ((now - lastLightGC).TotalSeconds >= 60) {
                    GC.Collect(1, GCCollectionMode.Optimized);
                    lastLightGC = now;
                }

                // --- 30 MINUTE / HOURLY: DEEP GC & DISK GROOMING ---
                if ((now - lastUebaCleanup).TotalMinutes >= 30 || UebaLearningCache.Count > 30000) {
                    UebaLearningCache.Clear();
                    LateralTrack.Clear();
                    EgressTrack.Clear();
                    ProcessCache.Clear();

                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                    lastUebaCleanup = now;
                    WriteDiag("Deep Memory protection executed. Caches flushed and GC forced.", "INFO");
                }

                if (now.Minute == 0 && now.Second < 5) {
                    foreach (var file in Directory.GetFiles(LogDir, "*.jsonl")) {
                        if (File.GetLastWriteTime(file) < now.AddDays(-3)) {
                            try { File.Delete(file); WriteDiag($"Disk Protection: Groomed stale log {Path.GetFileName(file)}", "INFO"); } catch {}
                        }
                    }
                }

                // --- HEALTH CHECK & AUTO RECOVERY ---
                if ((now - LastEventReceived).TotalMinutes > 3 && !RealTimeC2Sensor.IsSessionHealthy()) {
                    if (!SensorBlinded) {
                        SensorBlinded = true;
                        WriteDiag("SENSOR BLINDED: ETW thread unresponsive. Initiating auto-recovery.", "ERROR");
                        
                        try {
                            RealTimeC2Sensor.StopSession();
                            
                            // OS-LEVEL FAILSAFE: Force terminate the trace via logman
                            Process.Start(new ProcessStartInfo("logman", "stop \"C2RealTimeSession\" -ets") { CreateNoWindow = true, UseShellExecute = false })?.WaitForExit();
                            Thread.Sleep(2000);
                            
                            RealTimeC2Sensor.StartSession();
                            LastEventReceived = now;
                            SensorBlinded = false;
                            WriteDiag("SENSOR RECOVERED: ETW SESSION RESTORED", "INFO");
                        } catch (Exception ex) {
                            WriteDiag($"Auto-Recovery failed: {ex.Message}. Retrying next cycle.", "ERROR");
                        }
                    }
                }

                Thread.Sleep(50);
            }
        }

        // ====================== NATIVE FFI ML HANDOFF ======================
        static void ExecuteMlHandoff(DateTime now)
        {
            var payloadList = new List<object>();

            foreach (var kvp in ConnectionHistory) {
                string key = kvp.Key;
                var historyQueue = kvp.Value;
                int count = historyQueue.Count;

                if (count >= MinSamplesForML) {

                    if (!LoggedFlows.TryGetValue(key, out int loggedCount) || loggedCount != count) {
                        LoggedFlows[key] = count;
                        var arr = historyQueue.ToArray();
                        var meta = FlowMeta[key];
                        var ipArr = meta.DstIps.ToArray();
                        var sizeArr = meta.PacketSizes.ToArray();

                        var intervals = new List<double>();
                        var alignedIps = new List<string>();
                        var alignedSizes = new List<int>();

                        for (int i = 1; i < arr.Length; i++) {
                            intervals.Add(Math.Round((arr[i] - arr[i - 1]).TotalSeconds, 2));
                            if (i < ipArr.Length) alignedIps.Add(ipArr[i]);
                            if (i < sizeArr.Length) alignedSizes.Add(sizeArr[i]);
                        }

                        double duration = (arr[arr.Length - 1] - arr[0]).TotalSeconds;
                        double sparsity = count > 0 ? duration / count : 0.0;
                        double asymmetry = meta.TotalBytesIn > 0 ? (double)meta.TotalBytesOut / meta.TotalBytesIn : meta.TotalBytesOut;

                        payloadList.Add(new { 
                            key = key, 
                            intervals = intervals, 
                            domain = meta.Domain, 
                            dst_ips = alignedIps, 
                            packet_sizes = alignedSizes,
                            asymmetry_ratio = asymmetry,
                            sparsity_index = sparsity,
                            ttls = (int[])null,
                            asns = (int[])null,
                            payload_entropies = (double[])null
                        });
                    }
                }
            }

            if (payloadList.Count > 0) {
                GlobalMlSent++;
                string jsonPayload = JsonSerializer.Serialize(payloadList);
                string response = RealTimeC2Sensor.EvaluateBatch(jsonPayload);

                if (!string.IsNullOrEmpty(response) && response != "{}") {
                    try {
                        using JsonDocument doc = JsonDocument.Parse(response);
                        var root = doc.RootElement;
                        if (root.TryGetProperty("daemon_error", out JsonElement err)) {
                            WriteDiag($"RUST ML ENGINE ERROR: {err.GetString()}", "ERROR");
                        } else if (root.TryGetProperty("alerts", out JsonElement alerts)) {
                            foreach (var alert in alerts.EnumerateArray()) {
                                GlobalMlAlerts++;
                                string alertKey = alert.GetProperty("key").GetString();
                                string reason = alert.GetProperty("alert_reason").GetString();
                                int confidence = alert.GetProperty("confidence").GetInt32();

                                string resolvedImage = FlowMeta.ContainsKey(alertKey) ? FlowMeta[alertKey].Image : "Unknown";
                                string dest = "Unknown";
                                var match = Regex.Match(alertKey, @"IP_([0-9\.]+)");
                                if (match.Success) dest = match.Groups[1].Value;

                                SubmitAlert("ML_Beacon", dest, resolvedImage, reason, confidence, "T1071");
                            }
                        }
                    } catch { WriteDiag("Failed to parse Rust JSON response.", "ERROR"); }
                }
            }
        }

        // ====================== ACTIVE DEFENSE & LOGGING ======================
        static void SubmitAlert(string type, string dest, string image, string flags, int confidence, string attck = "N/A", string rawJson = null, int learningHit = 0)
        {
            string dedupKey = $"{type}_{dest}_{flags}_{image}";
            if (CycleAlerts.ContainsKey(dedupKey)) { CycleAlerts[dedupKey].Count++; return; }

            string eventId = Guid.NewGuid().ToString();

            if (rawJson != null && type == "ThreatIntel_Match") {
                string injectStr = $"\"EventID\":\"{eventId}\", \"ComputerName\":\"{ComputerName}\", \"HostIP\":\"{HostIP}\", \"SensorUser\":\"{SensorUser}\", \"LearningHit\":{learningHit}, ";
                UebaBatch.Add(rawJson.Insert(1, injectStr));
            }

            var alert = new AlertEvent {
                EventID = eventId, EventType = type, Destination = dest, Image = image,
                SuspiciousFlags = flags, ATTCKMappings = attck, Confidence = confidence, HostIP = HostIP, SensorUser = SensorUser,
                Action = (ArmedMode && confidence >= ConfidenceThreshold) ? "Mitigated" : "Logged"
            };

            CycleAlerts[dedupKey] = alert;
        }

        static void FlushCycleAlerts()
        {
            if (CycleAlerts.Count == 0) return;

            foreach (var alert in CycleAlerts.Values) {
                DataBatch.Add(alert);
                if (alert.Action == "Mitigated" || alert.Confidence >= 90) {
                    if (alert.Destination != "Local_Privilege_Escalation" && alert.EventType != "ThreatIntel_Match") {
                        InvokeActiveDefense(alert.Image, alert.Destination, alert.Confidence, alert.SuspiciousFlags);
                    }
                }
                // HUD Integration point: Send to UI thread here
            }
            CycleAlerts.Clear();

            // Log Rotation & Writing
            lock (FileLock) {
                RotateLog(AlertLogPath);
                File.AppendAllLines(AlertLogPath, DataBatch.Select(x => JsonSerializer.Serialize(x)));
                DataBatch.Clear();

                if (UebaBatch.Count > 0) {
                    RotateLog(UebaLogPath);
                    File.AppendAllLines(UebaLogPath, UebaBatch);
                    UebaBatch.Clear();
                }
            }
        }

        static void RotateLog(string path) {
            if (File.Exists(path) && new FileInfo(path).Length > 50 * 1024 * 1024) {
                File.Move(path, path.Replace(".jsonl", $"_{DateTime.Now:yyyyMMdd_HHmm}.jsonl"));
            }
        }

        static void InvokeActiveDefense(string procName, string destIp, int confidence, string reason)
        {
            if (!ArmedMode || confidence < ConfidenceThreshold) return;

            if (!string.IsNullOrEmpty(procName) && procName != "Unknown" && procName != "System") {
                try {
                    string cleanProc = Path.GetFileNameWithoutExtension(procName);
                    foreach (var p in Process.GetProcessesByName(cleanProc)) p.Kill();
                    TotalMitigations++;
                } catch { }
            }

            if (Regex.IsMatch(destIp, @"^\d+\.\d+\.\d+\.\d+$")) {
                string ruleName = $"C2_Defend_Block_{destIp}";
                try {
                    var psi = new ProcessStartInfo("netsh", $"advfirewall firewall add rule name=\"{ruleName}\" dir=out action=block remoteip={destIp} protocol=any") { CreateNoWindow = true, UseShellExecute = false };
                    Process.Start(psi)?.WaitForExit();
                    TotalMitigations++;
                } catch { }
            }
        }

        // ====================== INITIALIZATION SUBSYSTEMS ======================
        static async Task SyncJA3Signatures()
        {
            WriteDiag("Fetching latest JA3 Fingerprints from abuse.ch SSLBL...", "STARTUP");
            bool success = false;
            if (!File.Exists(Ja3CachePath) || (DateTime.Now - File.GetLastWriteTime(Ja3CachePath)).TotalHours >= 24) {
                try {
                    using var client = new HttpClient();
                    string csv = await client.GetStringAsync("https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv");
                    var hashes = new List<string>();
                    foreach (var line in csv.Split('\n')) {
                        var match = Regex.Match(line, @"^([a-fA-F0-9]{32}),");
                        if (match.Success) hashes.Add(match.Groups[1].Value.ToLower());
                    }
                    if (hashes.Count > 0) {
                        File.WriteAllText(Ja3CachePath, JsonSerializer.Serialize(hashes));
                        success = true;
                    }
                } catch { WriteDiag("Failed to pull JA3 from abuse.ch. Relying on local cache/defaults.", "WARN"); }
            } else { success = true; }

            if (success && File.Exists(Ja3CachePath)) {
                try {
                    var cached = JsonSerializer.Deserialize<List<string>>(File.ReadAllText(Ja3CachePath));
                    foreach (var h in cached) MaliciousJA3Cache.Add(h);
                } catch { }
            }

            if (MaliciousJA3Cache.Count == 0) {
                string[] defaults = { "a0e9f5d64349fb13191bc781f81f42e1", "b32309a26951912be7dba376398abc3b", "eb88d0b3e1961a0562f006e5ce2a0b87" };
                foreach (var d in defaults) MaliciousJA3Cache.Add(d);
            }
        }

        static void InitializeEnvironment()
        {
            if (!Directory.Exists(BaseDir)) Directory.CreateDirectory(BaseDir);
            
            // Complete Directory Anti-Tamper Lockdown
            try {
                var dirInfo = new DirectoryInfo(BaseDir);
                var dirSecurity = dirInfo.GetAccessControl();
                
                // Block inheritance and wipe existing rules
                dirSecurity.SetAccessRuleProtection(true, false);

                var inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
                var propagate = PropagationFlags.None;

                // 1. SYSTEM
                dirSecurity.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, inherit, propagate, AccessControlType.Allow));
                // 2. Administrators
                dirSecurity.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, inherit, propagate, AccessControlType.Allow));
                // 3. Current Executing User
                dirSecurity.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User, FileSystemRights.FullControl, inherit, propagate, AccessControlType.Allow));

                dirInfo.SetAccessControl(dirSecurity);
            } catch (Exception ex) {
                Console.WriteLine($"[!] CRITICAL WARNING: Directory ACL lockdown failed. {ex.Message}");
            }

            if (!Directory.Exists(DataDir)) Directory.CreateDirectory(DataDir);
            if (!Directory.Exists(LogDir)) Directory.CreateDirectory(LogDir);

            if (File.Exists(DiagLogPath)) File.Delete(DiagLogPath);
            DiagWriter = new StreamWriter(new FileStream(DiagLogPath, FileMode.Append, FileAccess.Write, FileShare.Read)) { AutoFlush = true };

            try {
                if (!File.Exists(TamperLogPath)) File.Create(TamperLogPath).Dispose();
                TamperWriter = new StreamWriter(new FileStream(TamperLogPath, FileMode.Append, FileAccess.Write, FileShare.Read)) { AutoFlush = true };
            } catch { WriteDiag("Tamper Guard Log completely locked. Operating without disk ledger.", "WARN"); }
        }

        static void GetHostIP() {
            try {
                var interfaces = NetworkInterface.GetAllNetworkInterfaces();
                foreach (var ni in interfaces) {
                    if (ni.OperationalStatus == OperationalStatus.Up && ni.NetworkInterfaceType != NetworkInterfaceType.Loopback) {
                        var props = ni.GetIPProperties();
                        if (props.GatewayAddresses.Count > 0) {
                            foreach (var ip in props.UnicastAddresses) {
                                if (ip.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) {
                                    HostIP = ip.Address.ToString(); return;
                                }
                            }
                        }
                    }
                }
            } catch { }
        }

        public static void WriteDiag(string message, string level = "INFO") {
            string logLine = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] [{level}] {message}";
            lock (FileLock) { try { DiagWriter.WriteLine(logLine); } catch { } }
            if (level == "STARTUP" || level == "CRITICAL" || level == "ERROR") Console.WriteLine(logLine);
        }

        static void ShutdownSequence() {
            WriteDiag("Teardown Sequence Initiated.", "INFO");
            Console.WriteLine("\n[*] Gracefully halting ETW constraints and flushing unmanaged memory...");
            RealTimeC2Sensor.StopSession();
            DiagWriter?.Dispose();
            TamperWriter?.Dispose();
            Environment.Exit(0);
        }

    static Dictionary<string, string[]> LoadConfig(string path)
        {
            var config = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
            if (!File.Exists(path))
            {
                WriteDiag($"CRITICAL: Config file missing at {path}. Using empty arrays.", "ERROR");
                return config;
            }

            foreach (var line in File.ReadAllLines(path))
            {
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith(";") || line.StartsWith("#") || line.StartsWith("[")) continue;
                
                var parts = line.Split('=', 2);
                if (parts.Length == 2)
                {
                    config[parts[0].Trim()] = parts[1].Split(',')
                                                      .Select(s => s.Trim())
                                                      .Where(s => !string.IsNullOrEmpty(s))
                                                      .ToArray();
                }
            }
            return config;
        }
    }
    // ====================== UTILITY CLASSES ======================
    public static class MathHelpers {
        private static readonly HashSet<char> Vowels = new("aeiou".ToCharArray());
        public static double GetEntropy(string input) {
            if (string.IsNullOrEmpty(input)) return 0.0;
            var counts = new Dictionary<char, int>();
            foreach (char c in input) { if (!counts.ContainsKey(c)) counts[c] = 0; counts[c]++; }
            double entropy = 0.0;
            foreach (int count in counts.Values) {
                double p = (double)count / input.Length;
                entropy -= p * Math.Log(p, 2);
            }
            return entropy;
        }
        public static bool IsAnomalousDomain(string domain) {
            if (string.IsNullOrEmpty(domain)) return false;
            string dLow = domain.ToLowerInvariant();
            if (dLow.Contains("otel") || dLow.Contains("telemetry") || dLow.Contains("api") || dLow.Contains("prod-")) return false;
            if (domain.Length > 45) return true;
            int digits = domain.Count(char.IsDigit);
            if ((double)digits / domain.Length > 0.45) return true;
            int vowels = dLow.Count(c => Vowels.Contains(c));
            if ((double)vowels / domain.Length < 0.10) return true;
            return GetEntropy(domain) > 4.5;
        }
        // Zero-Allocation FNV-1a 64-bit Hash for Domains
        public static ulong HashDomain(string domain) {
            if (string.IsNullOrEmpty(domain)) return 0;
            ulong hash = 14695981039346656037;
            for (int i = 0; i < domain.Length; i++) {
                hash ^= char.ToLowerInvariant(domain[i]);
                hash *= 1099511628211;
            }
            return hash;
        }
        // Fast IP to 32-bit Integer
        public static uint IpToUint(string ipAddress) {
            if (System.Net.IPAddress.TryParse(ipAddress, out var address)) {
                byte[] bytes = address.GetAddressBytes();
                if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
                return BitConverter.ToUInt32(bytes, 0);
            }
            return 0;
        }
    }
}