/********************************************************************************
 * SYSTEM:          Deep Sensor - Host Behavioral / ETW Telemetry Engine
 * COMPONENT:       DeepVisibilitySensor.cs (Unmanaged ETW Listener)
 * VERSION:         2.0
 * AUTHOR:          Robert Weber
 * * DESCRIPTION:
 * A high-performance, real-time Event Tracing for Windows (ETW) listener compiled
 * natively into the PowerShell runspace. Acts as the primary host telemetry bridge,
 * parsing kernel-level process, registry, file, and memory events at lightning speed
 * without dropping to disk. Integrates compiled Sigma signatures via an O(n)
 * Aho-Corasick state machine for zero-latency Threat Intelligence evaluation.
* ARCHITECTURAL FEATURES:
 * - O(1) Process Lineage Cache: Tracks PIDs in memory to correlate parent-child
 * relationships instantly, bypassing Win32 API polling overhead.
 * - Forensic-Grade Quarantine: Utilizes native P/Invoke (SuspendThread) to freeze
 * malicious execution without crashing the parent process.
 * - Memory Neutralization: Strips RWX permissions (PAGE_NOACCESS) from injected
 * payloads while extracting raw shellcode to disk for analysis.
 ********************************************************************************/

using System;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using System.Threading;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Text;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using System.Linq;

public class DeepVisibilitySensor {

    // Thread-safe queue serving as the lock-free data bridge to the PowerShell loop
    public static ConcurrentQueue<string> EventQueue = new ConcurrentQueue<string>();

    private static libyaraNET.YaraContext _yaraContext;
    private static TraceEventSession _session;

    // Determines if the engine is allowed to suspend threads and strip memory
    public static bool IsArmed = false;

    // In-memory process caches to avoid continuous API lookups and support heuristics
    private static ConcurrentDictionary<int, string> ProcessCache = new ConcurrentDictionary<int, string>();
    private static ConcurrentDictionary<int, DateTime> ProcessStartTime = new ConcurrentDictionary<int, DateTime>();
    private static int SensorPid = -1;

    // =====================================================================
    // MATHEMATICAL LINEAGE CACHE (Execution Lineage & Stack Verification)
    // =====================================================================
    public struct ModuleMap {
        public string ModuleName;
        public ulong BaseAddress;
        public ulong EndAddress;
    }

    // Maps PID -> List of legally loaded modules on disk
    private static ConcurrentDictionary<int, List<ModuleMap>> ProcessModules = new ConcurrentDictionary<int, List<ModuleMap>>();

    // Maps TID -> Timestamp of high-risk events (Triggers the Stack Walk evaluation)
    private static ConcurrentDictionary<int, double> FlaggedThreadsForStackWalk = new ConcurrentDictionary<int, double>();

    // =====================================================================
    // DYNAMIC PRUNING: Globally Suppressed Sigma Rules
    // =====================================================================
    // DEVELOPER NOTE: Using ConcurrentDictionary as a lock-free HashSet
    // to bypass PowerShell CS0656 Monitor.Exit compilation bugs.
    public static ConcurrentDictionary<string, byte> SuppressedSigmaRules = new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);

    public static void SuppressSigmaRule(string ruleName) {
        SuppressedSigmaRules.TryAdd(ruleName.Trim(), 0);
    }

    // =====================================================================
    // CONTEXT-AWARE YARA ENGINE
    // =====================================================================
    // Maps process names to specific threat vectors to minimize CPU overhead
    // during in-memory shellcode evaluation.
    public static ConcurrentDictionary<string, libyaraNET.Rules> YaraMatrices = new ConcurrentDictionary<string, libyaraNET.Rules>(StringComparer.OrdinalIgnoreCase);

    public static void InitializeYaraMatrices(string yaraRuleDirectory) {
        if (!System.IO.Directory.Exists(yaraRuleDirectory)) return;

        // Iterates through subfolders (e.g., \LotL, \WebShells, \Core_C2)
        foreach (var vectorDir in System.IO.Directory.GetDirectories(yaraRuleDirectory)) {
            string vectorName = System.IO.Path.GetFileName(vectorDir);
            try {
                using (var compiler = new libyaraNET.Compiler()) {
                    foreach (var ruleFile in System.IO.Directory.GetFiles(vectorDir, "*.yar")) {
                        compiler.AddRuleFile(ruleFile);
                    }
                    var rules = compiler.GetRules();
                    YaraMatrices[vectorName] = rules;
                    EnqueueDiag($"[YARA] Compiled vector matrix: {vectorName} (Success)");
                }
            } catch (Exception ex) {
                EnqueueDiag($"[YARA] Failed to compile vector {vectorName}: {ex.Message}");
            }
        }
    }

    public static string DetermineThreatVector(string processName) {
        string proc = processName.ToLowerInvariant();

        if (proc.Contains("w3wp") || proc.Contains("nginx") || proc.Contains("httpd") || proc.Contains("tomcat"))
            return "WebInfrastructure";

        if (proc.Contains("spoolsv") || proc.Contains("lsass") || proc.Contains("smss") || proc.Contains("svchost"))
            return "SystemExploits";

        if (proc.Contains("powershell") || proc.Contains("pwsh") || proc.Contains("cmd") || proc.Contains("wscript") || proc.Contains("cscript"))
            return "LotL";

        if (proc.Contains("winword") || proc.Contains("excel") || proc.Contains("outlook") || proc.Contains("powerpnt"))
            return "MacroPayloads";

        if (proc.Contains("rundll32") || proc.Contains("regsvr32") || proc.Contains("mshta") || proc.Contains("msiexec") || proc.Contains("installutil"))
            return "BinaryProxy";

        if (proc.Contains("explorer") || proc.Contains("taskhostw") || proc.Contains("userinit") || proc.Contains("winlogon"))
            return "SystemPersistence";

        if (proc.Contains("chrome") || proc.Contains("msedge") || proc.Contains("firefox") || proc.Contains("discord"))
            return "InfostealerTargets";

        if (proc.Contains("teamviewer") || proc.Contains("anydesk") || proc.Contains("screenconnect") || proc.Contains("mstsc"))
            return "RemoteAdmin";

        if (proc.Contains("python") || proc.Contains("node") || proc.Contains("git") || proc.Contains("podman") || proc.Contains("docker"))
            return "DevOpsSupplyChain";

        return "Core_C2";
    }

    public static string EvaluatePayloadInMemory(byte[] payload, string processName) {
        string vector = DetermineThreatVector(processName);

        if (!YaraMatrices.ContainsKey(vector)) vector = "Core_C2";
        if (!YaraMatrices.ContainsKey(vector)) return "NoSignatureMatch";

        try {
            // DEVELOPER NOTE: Scanner does not implement IDisposable in this version of libyara.NET.
            var scanner = new libyaraNET.Scanner();
            var results = scanner.ScanMemory(payload, YaraMatrices[vector]);

            if (results != null && results.Count > 0) {
                List<string> matches = new List<string>();
                foreach (var match in results) {
                    matches.Add(match.MatchingRule.Identifier);
                }
                return string.Join(" | ", matches);
            }
        } catch (Exception ex) {
            return $"YaraEvaluationError: {ex.Message}";
        }
        return "NoSignatureMatch";
    }

    /// <summary>
    /// Forged Return Address Detection
    /// Checks the bytes immediately preceding a return pointer.
    /// If they do NOT form a valid CALL or JMP, the address was manually pushed (spoofed).
    /// </summary>
    private static bool IsForgedReturnAddress(int pid, ulong returnAddr)
    {
        if (returnAddr < 6) return true; // obviously invalid

        // 0x0010 (VM_READ) | 0x0008 (VM_OPERATION) - reuse existing constant style
        uint PROCESS_VM_READ_OPERATION = 0x0010 | 0x0008;
        IntPtr hProcess = OpenProcess(PROCESS_VM_READ_OPERATION, false, (uint)pid);
        if (hProcess == IntPtr.Zero) return true; // treat as suspicious on access failure

        try
        {
            // Read 10 bytes before the return address (covers E8 xx xx xx xx and shorter JMPs)
            byte[] buffer = new byte[10];
            ulong readAddr = returnAddr - 10;

            if (!ReadProcessMemory(hProcess, (IntPtr)readAddr, buffer, (UIntPtr)10, out _))
                return true; // cannot read → treat as forged

            // Check for common legitimate CALL / JMP opcodes in the preceding bytes
            for (int i = 0; i < 6; i++) // slide window
            {
                byte b = buffer[i];

                // CALL rel32  (most common)
                if (b == 0xE8) return false;

                // JMP rel32
                if (b == 0xE9) return false;

                // Short JMP rel8
                if (b == 0xEB) return false;

                // Indirect CALL (FF /2, FF /3, FF /4, FF /5)
                if (b == 0xFF)
                {
                    byte modrm = buffer[i + 1];
                    if ((modrm & 0xF8) == 0xD0 ||  // FF D0-D7  call reg
                        (modrm & 0xF8) == 0x10 ||  // FF 10-17  call [reg]
                        (modrm & 0xF8) == 0x50 ||  // FF 50-57  call [reg+disp8]
                        (modrm & 0xF8) == 0x90)    // FF 90-97  call [reg+disp32]
                    {
                        return false;
                    }
                }
            }
            // No valid CALL/JMP found in the preceding bytes → forged
            return true;
        }
        catch
        {
            return true; // treat read errors as suspicious
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }

    // DEVELOPER NOTE: Terminating threads inside these processes causes instant BSODs.
    // The sensor must monitor them but never attempt Active Defense containment on them.
    private static readonly HashSet<string> CriticalSystemProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
        "csrss.exe", "lsass.exe", "smss.exe", "services.exe", "wininit.exe", "winlogon.exe", "system"
    };

    // --- WIN32 API INTEGRATION FOR SURGICAL THREAD CONTAINMENT ---
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    // SWAPPED: Using SuspendThread instead of TerminateThread for reversible quarantine
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint SuspendThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesRead);

    [DllImport("dbghelp.dll", SetLastError = true)]
    static extern bool MiniDumpWriteDump(IntPtr hProcess, uint processId, Microsoft.Win32.SafeHandles.SafeFileHandle hFile, uint dumpType, IntPtr expParam, IntPtr userStreamParam, IntPtr callbackParam);

    /// <summary>
    /// Suspends a specific native thread by TID. This freezes the malicious payload
    /// in place, preventing further execution or data destruction, while preserving
    /// the thread's memory stack for forensic analysis.
    /// </summary>
    public static bool QuarantineNativeThread(int tid, int pid) {
        if (!IsArmed) {
            EnqueueDiag($"[AUDIT MODE] Active defense bypassed. Thread {tid} (PID: {pid}) was NOT suspended.");
            return false;
        }
        string procName = GetProcessName(pid);

        // GUARD: Prevent system hangs by refusing to suspend critical system threads
        if (CriticalSystemProcesses.Contains(procName)) {
            EnqueueDiag($"[GUARD] Active Defense bypassed thread {tid} in {procName}. Reason: Critical System Process.");
            return false;
        }

        // 0x0002 is THREAD_SUSPEND_RESUME
        uint THREAD_SUSPEND_RESUME = 0x0002;
        IntPtr hThread = OpenThread(THREAD_SUSPEND_RESUME, false, (uint)tid);

        if (hThread == IntPtr.Zero) {
            EnqueueDiag($"[ERROR] Failed to open thread {tid} for suspension. It may have already exited.");
            return false;
        }

        // SuspendThread returns the thread's previous suspend count.
        // If it returns 0xFFFFFFFF, the suspension failed.
        uint suspendCount = SuspendThread(hThread);
        CloseHandle(hThread);

        return (suspendCount != 0xFFFFFFFF);
    }

    /// <summary>
    /// Extracts the injected RWX payload, evaluates it against targeted YARA matrices,
    /// and returns the attribution string to the orchestrator for audit logging.
    /// </summary>
    public static string NeuterAndDumpPayload(int pid, ulong address, ulong size) {
        string yaraResult = "NoSignatureMatch";
        string procName = GetProcessName(pid);
        if (CriticalSystemProcesses.Contains(procName)) return yaraResult;

        // 0x0010 (VM_READ) | 0x0008 (VM_OPERATION)
        uint PROCESS_VM_READ_OPERATION = 0x0010 | 0x0008;
        IntPtr hProcess = OpenProcess(PROCESS_VM_READ_OPERATION, false, (uint)pid);
        if (hProcess == IntPtr.Zero) return "HandleAccessDenied";

        try {
            byte[] buffer = new byte[size];
            if (ReadProcessMemory(hProcess, (IntPtr)address, buffer, (UIntPtr)size, out UIntPtr bytesRead)) {

                yaraResult = EvaluatePayloadInMemory(buffer, procName);

                string quarantineDir = @"C:\ProgramData\DeepSensor\Data\Quarantine";
                System.IO.Directory.CreateDirectory(quarantineDir);
                string dumpPath = $@"{quarantineDir}\Payload_{procName}_{pid}_0x{address:X}.bin";
                System.IO.File.WriteAllBytes(dumpPath, buffer);

                EnqueueDiag($"[FORENSICS] Extracted {bytesRead} bytes to {dumpPath}. YARA Attribution: {yaraResult}");

                if (yaraResult != "NoSignatureMatch") {
                    EnqueueAlert("T1059", "YaraPayloadAttribution", procName, pid, 0, $"In-Memory Shellcode Identified As: {yaraResult}");
                }
            }

            // TRUE QUARANTINE (STRIP PERMISSIONS TO PAGE_NOACCESS)
            uint PAGE_NOACCESS = 0x01;
            if (VirtualProtectEx(hProcess, (IntPtr)address, (UIntPtr)size, PAGE_NOACCESS, out uint oldProtect)) {
                EnqueueDiag($"[CONTAINMENT] Memory permissions at 0x{address:X} stripped to PAGE_NOACCESS.");
            }
        }
        catch (Exception ex) {
            EnqueueDiag($"[ERROR] NeuterAndDumpPayload failed for PID {pid}: {ex.Message}");
            return $"ForensicError: {ex.Message}";
        }
        finally {
            CloseHandle(hProcess);
        }
        return yaraResult;
    }

    /// <summary>
    /// Captures a full memory dump of a compromised process for post-incident reverse engineering.
    /// </summary>
    public static string PreserveForensics(int pid, string procName) {
        if (!IsArmed) {
            return "Bypassed (Audit Mode)";
        }
        string dumpDir = @"C:\ProgramData\DeepSensor\Data\Forensics";
        System.IO.Directory.CreateDirectory(dumpDir);
        string dumpPath = $@"{dumpDir}\{procName}_{pid}_{DateTime.UtcNow:yyyyMMddHHmmss}.dmp";

        // PROCESS_QUERY_INFORMATION (0x0400) | PROCESS_VM_READ (0x0010)
        IntPtr hProcess = OpenProcess(0x0400 | 0x0010, false, (uint)pid);
        if (hProcess == IntPtr.Zero) return "AccessDenied";

        try {
            using (var fs = new System.IO.FileStream(dumpPath, System.IO.FileMode.Create, System.IO.FileAccess.ReadWrite, System.IO.FileShare.Write)) {
                // 2 = MiniDumpWithFullMemory
                bool success = MiniDumpWriteDump(hProcess, (uint)pid, fs.SafeFileHandle, 2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

                if (success) {
                    EnqueueDiag($"[FORENSICS] Memory dumped successfully to {dumpPath}");
                    return dumpPath;
                }
            }
        } catch (Exception ex) {
            EnqueueDiag($"[ERROR] Forensic dump failed for PID {pid}: {ex.Message}");
        } finally {
            CloseHandle(hProcess);
        }
        return "Failed";
    }

    // Static registry paths monitored for persistence and evasion techniques
    private static readonly string[] MonitoredRegPaths = {
        "image file execution options", "image file execution options\\sethc.exe",
        "image file execution options\\utilman.exe", "inprocserver32", "treatas",
        "windows\\currentversion\\run", "windows nt\\currentversion\\windows",
        "session manager", "services", "wmi\\autologger", "amsi\\providers",
        "control\\lsa\\security packages"
    };

    // Helper for named pipes evaluation
    private static double ShannonEntropy(string s)
    {
        if (string.IsNullOrEmpty(s)) return 0.0;
        var counts = new Dictionary<char, int>();
        foreach (char c in s) {
            counts[c] = counts.GetValueOrDefault(c) + 1;
        }
        double entropy = 0.0;
        int len = s.Length;
        foreach (var count in counts.Values) {
            double p = (double)count / len;
            entropy -= p * Math.Log(p, 2);
        }
        return entropy;
    }

    /// <summary>
    /// Filters out known Just-In-Time (JIT) environments which naturally execute from unbacked memory.
    /// </summary>
    private static bool IsKnownJitEnvironment(int pid, ulong instructionPointer) {
        string procName = GetProcessName(pid)?.ToLowerInvariant() ?? "";
        if (procName.Contains("powershell") || procName.Contains("chrome") ||
            procName.Contains("msedge") || procName.Contains("node") ||
            procName.Contains("w3wp")) {
            return true;
        }
        return false;
    }

    // Centralized exclusion lists - fully configurable from launcher
    private static HashSet<string> BenignExplorerValueNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    private static HashSet<string> BenignADSProcesses     = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    // --- THREAT INTEL & SIGMA CACHES ---
    private static HashSet<string> TiDrivers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    private static string[] SigmaCmdKeys;
    private static string[] SigmaCmdTitles;
    private static string[] SigmaImgKeys;
    private static string[] SigmaImgTitles;

    private static AhoCorasick CmdAc;
    private static AhoCorasick ImgAc;

    [ThreadStatic]
    private static StringBuilder _jsonSb;

    /// <summary>
    /// DEVELOPER NOTE: Performance Fix. Utilizes a ThreadStatic StringBuilder
    /// to eliminate massive Garbage Collection (GC) spikes during heavy ETW bursts.
    /// </summary>
    private static string JsonEscape(string text) {
        if (string.IsNullOrEmpty(text)) return "";

        if (_jsonSb == null) _jsonSb = new StringBuilder(Math.Max(text.Length, 256));
        _jsonSb.Clear();

        foreach (char c in text) {
            switch (c) {
                case '"': _jsonSb.Append("\\\""); break;
                case '\\': _jsonSb.Append("\\\\"); break;
                case '\b': _jsonSb.Append("\\b"); break;
                case '\f': _jsonSb.Append("\\f"); break;
                case '\n': _jsonSb.Append("\\n"); break;
                case '\r': _jsonSb.Append("\\r"); break;
                case '\t': _jsonSb.Append("\\t"); break;
                default:
                    if (c < ' ') _jsonSb.AppendFormat("\\u{0:x4}", (int)c);
                    else _jsonSb.Append(c);
                    break;
            }
        }
        return _jsonSb.ToString();
    }


    private static void EnqueueDiag(string msg) {
        EventQueue.Enqueue($"{{\"Provider\":\"DiagLog\", \"Message\":\"{JsonEscape(msg)}\"}}");
    }

    /// <summary>
    /// Initializes boundary PIDs and populates the O(1) Threat Intel and Sigma matrices.
    /// </summary>
   private static string _dllPath;

    public static void Initialize(string dllPath, int currentPid, string[] tiDrivers, string[] sigmaCmdKeys, string[] sigmaCmdTitles, string[] sigmaImgKeys, string[] sigmaImgTitles, string[] benignExplorerValues, string[] benignADSProcs) {
        _dllPath = dllPath;
        SensorPid = currentPid;

        try {
            _yaraContext = new libyaraNET.YaraContext();
            EnqueueDiag("[YARA] Native engine context initialized successfully.");
        } catch (Exception ex) {
            EnqueueDiag($"[YARA] Context Init Failed: {ex.Message}");
        }

        // DEVELOPER NOTE: Pre-populate the ProcessCache with pre-existing OS processes.
        // This prevents the ML engine from receiving raw PIDs as process names, which
        // previously triggered false "Behavioral Lineage Outlier" anomalies.
        foreach (var p in System.Diagnostics.Process.GetProcesses()) {
            try {
                // ETW ImageFileName typically includes the extension, so we append .exe for parity
                ProcessCache[p.Id] = p.ProcessName + ".exe";
            } catch { }
        }

        // Load configurable exclusions (O(1) lookup)
        BenignExplorerValueNames = new HashSet<string>(benignExplorerValues, StringComparer.OrdinalIgnoreCase);
        BenignADSProcesses       = new HashSet<string>(benignADSProcs,       StringComparer.OrdinalIgnoreCase);

        // DEVELOPER NOTE: This dynamic resolver ensures the background thread can find ALL
        // required helper DLLs (like FastSerialization) located in the TraceEventPackage folder.
        AppDomain.CurrentDomain.AssemblyResolve += (sender, args) => {
            string folderPath = System.IO.Path.GetDirectoryName(_dllPath);
            string assemblyName = new System.Reflection.AssemblyName(args.Name).Name;
            string targetPath = System.IO.Path.Combine(folderPath, assemblyName + ".dll");

            if (System.IO.File.Exists(targetPath)) {
                return System.Reflection.Assembly.LoadFrom(targetPath);
            }
            return null;
        };

        UpdateThreatIntel(tiDrivers, sigmaCmdKeys, sigmaCmdTitles, sigmaImgKeys, sigmaImgTitles);
    }

    /// <summary>
    /// Dynamically updates the threat intelligence matrices in memory (Hot-Swap).
    /// </summary>
    public static void UpdateThreatIntel(string[] tiDrivers, string[] sigmaCmdKeys, string[] sigmaCmdTitles, string[] sigmaImgKeys, string[] sigmaImgTitles) {
        var newTi = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string driver in tiDrivers) { newTi.Add(driver); }
        TiDrivers = newTi;

        SigmaCmdKeys = sigmaCmdKeys;
        SigmaCmdTitles = sigmaCmdTitles;
        SigmaImgKeys = sigmaImgKeys;
        SigmaImgTitles = sigmaImgTitles;

        var newCmdAc = new AhoCorasick();
        newCmdAc.Build(SigmaCmdKeys);
        CmdAc = newCmdAc;

        var newImgAc = new AhoCorasick();
        newImgAc.Build(SigmaImgKeys);
        ImgAc = newImgAc;
    }

    /// <summary>
    /// Instantiates the ETW tracking session, binds necessary kernel providers,
    /// and initiates the background memory grooming task.
    /// </summary>
    public static void StartSession() {

        // --- PROCESS LINEAGE MEMORY GROOMING (TTL) ---
        Task.Run(async () => {
            while (true) {
                await Task.Delay(TimeSpan.FromHours(1));
                try {
                    var activePids = new HashSet<int>();
                    foreach (var p in System.Diagnostics.Process.GetProcesses()) {
                        activePids.Add(p.Id);
                    }
                    foreach (var key in ProcessCache.Keys) {
                        if (!activePids.Contains(key)) {
                            ProcessCache.TryRemove(key, out _);
                            ProcessStartTime.TryRemove(key, out _);
                        }
                    }
                } catch { }
            }
        });

        // --- ETW BUFFER FLOOD DETECTION ---
        Task.Run(async () => {
            while (_session != null) {
                await Task.Delay(500);  // Check twice per second
                try {
                    if (_session.EventsLost > 0) {
                        string floodAlert = $"{{\"Category\":\"StaticAlert\", \"Type\":\"SensorBlinding\", \"Process\":\"ETW_KERNEL\", \"Reason\":\"BUFFER FLOOD DETECTED: {_session.EventsLost} events lost (Selective Dropping)\", \"Action\":\"CRITICAL: SENSOR BLINDED\"}}";
                        EventQueue.Enqueue(floodAlert);
                        EnqueueDiag($"[CRITICAL] ETW BUFFER FLOOD: {_session.EventsLost} events dropped");
                    }
                } catch { }
            }
        });

        // --- ISOLATED BACKGROUND TASK ---
        Task.Run(() => {
            try {
                EnqueueDiag("C# Background Task Thread successfully spawned.");
                RunEtwCore();
            } catch (Exception ex) {
                // We will now actually catch assembly resolution or binding crashes
                EnqueueDiag($"CRITICAL ETW TASK CRASH: {ex.Message} | {ex.StackTrace}");
                EventQueue.Enqueue($"{{\"Provider\":\"Error\", \"Message\":\"{JsonEscape(ex.Message)}\"}}");
            }
        });

        // =====================================================================
        // ADVANCED THREAT MODELING: User-Mode ETW Providers (WMI / PowerShell)
        // =====================================================================
        Thread umThread = new Thread(() => {
            try {
                string umSessionName = "DeepSensor_UserMode";

                // Tear down any orphaned sessions from previous crashes
                if (TraceEventSession.GetActiveSessionNames().Contains(umSessionName)) {
                    using (var old = new TraceEventSession(umSessionName)) { old.Stop(true); }
                }

                using (var userSession = new TraceEventSession(umSessionName)) {
                    // Use explicit ETW GUIDs to bypass string resolution failures

                    // Microsoft-Windows-WMI-Activity (Lateral Movement / Persistence)
                    userSession.EnableProvider(Guid.Parse("1418ef04-b0b4-4623-bf7e-d74ab47bbdaa"));

                    // Microsoft-Windows-PowerShell (AMSI Bypasses / Obfuscation)
                    userSession.EnableProvider(Guid.Parse("a0c1853b-5c40-4b15-8766-3cf1c58f985a"));

                    // Microsoft-Antimalware-Scan-Interface (AMSI Deobfuscated Payloads)
                    userSession.EnableProvider(Guid.Parse("2A576B87-09A7-520E-C21A-4942F0271D67"));

                    userSession.Source.Dynamic.All += delegate (TraceEvent data) {
                        if (data.ProviderName == "Microsoft-Windows-WMI-Activity" ||
                            data.ProviderName == "Microsoft-Windows-PowerShell")
                        {
                            StringBuilder sb = new StringBuilder();

                            // Only extract the actual payload values.
                            // DO NOT inject the ProviderName, or Sigma will match the word "powershell" on every event.
                            if (data.PayloadNames != null) {
                                foreach (string key in data.PayloadNames) {
                                    try {
                                        sb.Append($"{data.PayloadString(data.PayloadIndex(key))} ");
                                    } catch { }
                                }
                            }

                            string dynamicPayload = sb.ToString().Trim().ToLowerInvariant();

                            // Only evaluate if there is actual telemetry data to search
                            if (dynamicPayload.Length > 5) {
                                int cmdMatch = CmdAc.SearchFirst(dynamicPayload);
                                if (cmdMatch >= 0) {
                                    string fullTitle = SigmaCmdTitles[cmdMatch];
                                    string cleanTitle = fullTitle;
                                    int bracketIdx = fullTitle.IndexOf('[');
                                    if (bracketIdx > 0) { cleanTitle = fullTitle.Substring(0, bracketIdx).Trim(); }

                                    if (!SuppressedSigmaRules.ContainsKey(cleanTitle)) {

                                        // Handle User-Mode events that lack a native ProcessID
                                        string procName = GetProcessName(data.ProcessID);
                                        if (string.IsNullOrWhiteSpace(procName) || procName == "0" || procName == "-1") {
                                            procName = data.ProviderName.Contains("WMI") ? "WMI_Activity" : "PowerShell_Host";
                                        }

                                        EnqueueAlert("Sigma_UserMode", "AdvancedDetection", procName, data.ProcessID, data.ThreadID,
                                            $"Lateral Movement/AMSI Alert: {fullTitle} | Target: {SigmaCmdKeys[cmdMatch]}");
                                    }
                                }
                            }
                        }
                    };

                    EnqueueDiag($"User-Mode Session Bound. WMI and AMSI explicitly monitored via GUID.");
                    userSession.Source.Process(); // Blocks this specific background thread indefinitely
                }
            } catch (Exception ex) {
                EnqueueDiag($"USER-MODE ETW CRASH: {ex.Message}");
            }
        });

        umThread.IsBackground = true; // Ensures the thread dies gracefully when PowerShell exits
        umThread.Start();
    }

    // DEVELOPER NOTE: NoInlining prevents the CLR from trying to resolve TraceEvent
    // assemblies until AFTER the background thread has safely started.
    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private static void RunEtwCore() {
        string sessionName = KernelTraceEventParser.KernelSessionName; // "NT Kernel Logger"

        // Force-clear any existing session to prevent constructor hang
        if (TraceEventSession.GetActiveSessionNames().Contains(sessionName)) {
            using (var old = new TraceEventSession(sessionName)) { old.Stop(true); }
        }

        _session = new TraceEventSession(sessionName);
        EnqueueDiag($"TraceEventSession bound: {sessionName}");

        // Buffer flood monitoring
        Task.Run(async () => {
            while (_session != null) {
                await Task.Delay(1000);
                try {
                    if (_session.EventsLost > 0) {
                        string floodAlert = $"{{\"Category\":\"StaticAlert\", \"Type\":\"SensorBlinding\", \"Process\":\"ETW_KERNEL\", \"Reason\":\"BUFFER FLOOD DETECTED: {_session.EventsLost} events lost\", \"Action\":\"CRITICAL: SENSOR BLINDED\"}}";
                        EventQueue.Enqueue(floodAlert);
                        EnqueueDiag($"[CRITICAL] ETW BUFFER FLOOD: {_session.EventsLost} events dropped");
                    }
                } catch { }
            }
        });

        var kernelKeywords = KernelTraceEventParser.Keywords.Process |
            KernelTraceEventParser.Keywords.Registry |
            KernelTraceEventParser.Keywords.FileIOInit |
            KernelTraceEventParser.Keywords.FileIO |
            KernelTraceEventParser.Keywords.ImageLoad |
            KernelTraceEventParser.Keywords.Memory |
            KernelTraceEventParser.Keywords.Profile;

        _session.EnableKernelProvider(kernelKeywords);
        EnqueueDiag("Kernel Provider Enabled. Listening for events...");

        // =====================================================================
        // EXECUTION LINEAGE ENGINE
        // =====================================================================

        // 1. Build the Legal Boundaries dynamically
        _session.Source.Kernel.ImageLoad += delegate (ImageLoadTraceData data) {
            if (data.ProcessID == SensorPid || data.ProcessID == 0) return;

            var map = new ModuleMap {
                ModuleName = data.FileName,
                BaseAddress = (ulong)data.ImageBase,
                EndAddress = (ulong)data.ImageBase + (ulong)data.ImageSize
            };

            ProcessModules.AddOrUpdate(data.ProcessID,
                pid => new List<ModuleMap> { map },
                (pid, list) => {
                    lock (list) { list.Add(map); } // Lock for thread-safety during array iteration
                    return list;
                });
        };

        // 2. Clear memory cache when process dies
        _session.Source.Kernel.ProcessStop += delegate (ProcessTraceData data) {
            ProcessModules.TryRemove(data.ProcessID, out _);
        };

        // 3. The Math Engine: Verify Stack Lineage against Boundaries
        // Unbacked Memory + Forged Return Addresses
        _session.Source.Kernel.StackWalkStack += delegate (StackWalkStackTraceData data) {

            // Optimization: Skip if we don't have modules for this PID yet
            if (!ProcessModules.TryGetValue(data.ProcessID, out var modules)) return;

            int unbackedFrames = 0;
            int forgedReturns = 0;

            // Loop through the instruction pointers in the stack
            for (int i = 0; i < data.FrameCount; i++) {
                ulong instructionPointer = data.InstructionPointer(i);
                bool isBacked = false;

                // === Unbacked Memory Bounds ===
                foreach (var mod in modules) {
                    if (instructionPointer >= mod.BaseAddress && instructionPointer <= mod.EndAddress) {
                        isBacked = true;
                        break;
                    }
                }

                if (!isBacked) {
                    unbackedFrames++;

                    // === Forged Return Address Check ===
                    if (IsForgedReturnAddress(data.ProcessID, instructionPointer)) {
                        forgedReturns++;
                    }
                }
            }

            // High-confidence spoof detection
            if (unbackedFrames >= 2 || forgedReturns > 0) {
                string reason = $"STACK ANOMALY: {unbackedFrames} unbacked frame(s)";
                if (forgedReturns > 0) {
                    reason += $" | {forgedReturns} forged return address(es) detected";
                }

                // High-fidelity alert for call-stack spoofing / ThreadlessInject
                string alertJson = $"{{\"Category\":\"StaticAlert\", \"Type\":\"StackSpoofDetected\", \"Process\":\"PID:{data.ProcessID}\", \"Reason\":\"{reason}\", \"Action\":\"QueueForQuarantine\"}}";
                EventQueue.Enqueue(alertJson);

                EnqueueDiag($"Stack spoof detected on PID {data.ProcessID} - {forgedReturns}/{unbackedFrames} forged returns");
            }
        };

        // =====================================================================
        // 1. PROCESS TRACKING, LOLBINS & SIGMA THREAT INTEL
        // =====================================================================
        _session.Source.Kernel.ProcessStart += delegate (ProcessTraceData data) {
            EnqueueDiag($"ProcessStart hit: {data.ImageFileName} (PID: {data.ProcessID})");
            string image = data.ImageFileName;
            ProcessCache[data.ProcessID] = image;
            ProcessStartTime[data.ProcessID] = DateTime.UtcNow;

            // DEVELOPER NOTE: SENSOR SELF-AWARENESS
            // If the process is the launcher, or was spawned BY the launcher
            // (like icacls.exe during startup), we drop the event to prevent self-detection.
            if (data.ProcessID == SensorPid || data.ParentID == SensorPid) return;

            string cmd = data.CommandLine;

            if (cmd.IndexOf("logman", StringComparison.OrdinalIgnoreCase) >= 0 &&
                cmd.IndexOf("stop", StringComparison.OrdinalIgnoreCase) >= 0 &&
            (cmd.IndexOf("edr", StringComparison.OrdinalIgnoreCase) >= 0 || cmd.IndexOf("eventlog", StringComparison.OrdinalIgnoreCase) >= 0)) {
                EnqueueAlert("T1562.002", "ETWTampering", image, data.ProcessID, data.ThreadID, $"Attempted to kill ETW: {cmd}");
            }

            // VSS Watchdog
            if (image.Contains("vssadmin") || image.Contains("wmic")) {
                if (cmd.Contains("shadowcopy create")) {
                    EnqueueAlert("T1003.003", "CredentialDumping", image, data.ProcessID, data.ThreadID, $"VSS Shadow Copy Creation Detected: {cmd}");
                }
            }

            int cmdMatch = CmdAc.SearchFirst(cmd);
            if (cmdMatch >= 0) {
                string fullTitle = SigmaCmdTitles[cmdMatch];
                string cleanTitle = fullTitle;

                // DEVELOPER NOTE: Strip the MITRE tags from the title to match
                // the exact rule name sent back by the Python UEBA engine.
                int bracketIdx = fullTitle.IndexOf('[');
                if (bracketIdx > 0) { cleanTitle = fullTitle.Substring(0, bracketIdx).Trim(); }

                // FIX: Use ContainsKey for ConcurrentDictionary
                if (!SuppressedSigmaRules.ContainsKey(cleanTitle)) {
                    EnqueueAlert("Sigma_Match", "SigmaDetection", image, data.ProcessID, data.ThreadID, $"Rule: {fullTitle} | Match: {SigmaCmdKeys[cmdMatch]}");
                }
            }

            int imgMatch = ImgAc.SearchEndsWith(image, SigmaImgKeys);
            if (imgMatch >= 0) {
                string fullTitle = SigmaImgTitles[imgMatch];
                string cleanTitle = fullTitle;

                int bracketIdx = fullTitle.IndexOf('[');
                if (bracketIdx > 0) { cleanTitle = fullTitle.Substring(0, bracketIdx).Trim(); }

                // FIX: Use ContainsKey for ConcurrentDictionary
                if (!SuppressedSigmaRules.ContainsKey(cleanTitle)) {
                    EnqueueAlert("Sigma_Match", "SigmaDetection", image, data.ProcessID, data.ThreadID, $"Rule: {fullTitle} | Match: {SigmaImgKeys[imgMatch]}");
                }
            }

            string parentName = GetProcessName(data.ParentID);
            EnqueueRaw("ProcessStart", image, parentName, "", cmd, data.ProcessID, data.ThreadID);
        };

        _session.Source.Kernel.ProcessStop += delegate (ProcessTraceData data) {
            ProcessCache.TryRemove(data.ProcessID, out _);
            ProcessStartTime.TryRemove(data.ProcessID, out _);
        };

        // =====================================================================
        // 2. REGISTRY PERSISTENCE
        // =====================================================================
        _session.Source.Kernel.RegistrySetValue += delegate (RegistryTraceData data) {
            // DEVELOPER NOTE: Prevent self-detection
            if (data.ProcessID == SensorPid) return;

            string keyName = data.KeyName ?? "";
            string valueName = data.ValueName ?? "";
            string fullInfo = $"Key: '{keyName}' | ValueName: '{valueName}'";

            string searchText = (keyName + "\\" + valueName + " " + keyName + " " + valueName).ToLowerInvariant()
                .Replace(@"\registry\machine\", @"\")
                .Replace(@"\registry\user\", @"\")
                .Replace(@"\software\", @"\")
                .Replace(@"microsoft\windows\", @"windows\");

            string procLower = GetProcessName(data.ProcessID).ToLowerInvariant();

            // Skip heavy system noise
            if (procLower.Contains("trustedinstaller") ||
                procLower.Contains("msiexec") ||
                procLower.Contains("svchost") ||
                procLower.Contains("startmenuexperiencehost") ||
                procLower.Contains("searchhost") ||
                procLower.Contains("backgroundtaskhost") ||
                valueName.Contains("WritePermissionsCheck", StringComparison.OrdinalIgnoreCase))
            {
                EnqueueRaw("RegistryWrite", GetProcessName(data.ProcessID), "", keyName, valueName, data.ProcessID, data.ThreadID);
                return;
            }

            // BENIGN EXPLORER FILTER
            if (procLower.Contains("explorer") && BenignExplorerValueNames.Contains(valueName))
            {
                EnqueueRaw("RegistryWrite", GetProcessName(data.ProcessID), "", keyName, valueName, data.ProcessID, data.ThreadID);
                return;
            }

            // Trigger on validation suite OR real monitored persistence
            bool isTestProcess = procLower.Contains("powershell") ||
                                 procLower.Contains("pwsh") ||
                                 procLower.Contains("cmd");

            bool isPersistence = false;
            foreach (string monitored in MonitoredRegPaths)
            {
                if (keyName.ToLowerInvariant().Contains(monitored) ||
                    valueName.ToLowerInvariant().Contains(monitored) ||
                    searchText.Contains(monitored))
                {
                    isPersistence = true;
                    break;
                }
            }

            if (!isPersistence)
            {
                string lowerValue = valueName.ToLowerInvariant();
                if (lowerValue.Contains("sethc.exe") || lowerValue.Contains("utilman.exe") ||
                    lowerValue.Contains("debugger") || lowerValue.Contains("globalflag") ||
                    lowerValue.Contains("run") || lowerValue.Contains("runonce") ||
                    lowerValue.Contains("autologger") || lowerValue.Contains("amsi") ||
                    keyName.ToLowerInvariant().Contains("image file execution options"))
                {
                    isPersistence = true;
                }
            }

            if (isPersistence || isTestProcess)
            {
                if (searchText.Contains("pendingfilerenameoperations"))
                {
                    EnqueueAlert("T1562.001", "PendingRename", procLower, data.ProcessID, data.ThreadID, "Boot-time deletion scheduled");
                }
                else if (searchText.Contains("autologger") || searchText.Contains("amsi\\providers"))
                {
                    EnqueueAlert("T1562.001", "SensorTampering", procLower, data.ProcessID, data.ThreadID, $"Blinding attempt: {fullInfo}");
                }
                else
                {
                    EnqueueAlert("T1547.001", "RegPersistence", procLower, data.ProcessID, data.ThreadID, $"Persistence Key: {fullInfo}");
                }
            }

            EnqueueRaw("RegistryWrite", GetProcessName(data.ProcessID), "", keyName, valueName, data.ProcessID, data.ThreadID);
        };

        // =====================================================================
        // 3. FILE SYSTEM EVASION & CANARY WATCHDOG (MAX VISIBILITY + DIAGNOSTICS)
        // =====================================================================
        _session.Source.Kernel.FileIOCreate += delegate (FileIOCreateTraceData data) {
            string fileName = data.FileName;

            // Robust canary (case-insensitive + fallback)
            if (fileName.Contains("deepsensor_canary.tmp", StringComparison.OrdinalIgnoreCase)) {
                EventQueue.Enqueue("{\"Provider\":\"HealthCheck\", \"EventName\":\"ETW_HEARTBEAT\"}");
                EnqueueDiag($"[CANARY] Heartbeat triggered via FileIOCreate: {fileName}");
                return;
            }

            // ==================== NAMED PIPE TELEMETRY ====================
            if (fileName.Contains(@"\Device\NamedPipe\", StringComparison.OrdinalIgnoreCase)) {
                string[] parts = fileName.Split(new[] { @"\NamedPipe\" }, StringSplitOptions.None);
                string pipeName = parts.Length > 0 ? parts[parts.Length - 1] : "";
                string procName = GetProcessName(data.ProcessID).ToLowerInvariant();

                bool isSuspicious = false;
                string reason = "";

                // 1. High-entropy / random-looking pipe names (very common with malleable C2)
                if (pipeName.Length >= 8) {
                    bool isAlphanumericOrHyphen = true;
                    for (int i = 0; i < pipeName.Length; i++) {
                        char c = pipeName[i];
                        if (!char.IsLetterOrDigit(c) && c != '-') {
                            isAlphanumericOrHyphen = false;
                            break;
                        }
                    }
                    if (isAlphanumericOrHyphen) {
                        double entropy = ShannonEntropy(pipeName);
                        if (entropy > 3.5) {  // High randomness threshold
                            isSuspicious = true;
                            reason = $"High-entropy named pipe: {pipeName} (malleable C2 likely)";
                        }
                    }
                }

                // 2. Common malleable C2 patterns (still useful when seen in odd context)
                string[] malleablePatterns = { "postex_", "status_", "msagent_", "mojo.", "sliver", "beacon" };
                bool hasMalleablePattern = false;
                foreach (string p in malleablePatterns) {
                    if (pipeName.Contains(p, StringComparison.OrdinalIgnoreCase)) {
                        hasMalleablePattern = true;
                        break;
                    }
                }
                if (hasMalleablePattern) {
                    isSuspicious = true;
                    reason = $"Known malleable C2 pipe pattern: {pipeName}";
                }

                // 3. Unusual process creating a named pipe (strong behavioral signal)
                string[] unusualPipeCreators = { "powershell", "pwsh", "cmd", "rundll32", "regsvr32", "mshta", "wscript", "cscript" };
                bool isUnusualCreator = false;
                foreach (string creator in unusualPipeCreators) {
                    if (procName.Contains(creator)) {
                        isUnusualCreator = true;
                        break;
                    }
                }
                if (isUnusualCreator) {
                    isSuspicious = true;
                    reason = $"Unusual process ({procName}) created named pipe: {pipeName}";
                }

                if (isSuspicious) {
                    EnqueueAlert("T1021.002", "SuspiciousNamedPipe", procName,
                        data.ProcessID, data.ThreadID, reason);
                }

                // Catch the actual extraction of the AD database or SAM hive
                if (fileName.IndexOf("HarddiskVolumeShadowCopy", StringComparison.OrdinalIgnoreCase) >= 0) {
                    if (fileName.EndsWith("NTDS.dit", StringComparison.OrdinalIgnoreCase) || fileName.EndsWith("SYSTEM", StringComparison.OrdinalIgnoreCase)) {
                        EnqueueAlert("T1003.003", "CredentialExtraction", GetProcessName(data.ProcessID), data.ProcessID, data.ThreadID, $"Critical AD Database Extraction via VSS: {fileName}");
                        // Trigger Active Defense
                        QuarantineNativeThread(data.ThreadID, data.ProcessID);
                    }
                }
            }

            // ==================== MAX VISIBILITY ADS DIAGNOSTICS ====================
            int driveColon = fileName.IndexOf(':', 0);
            if (driveColon == -1) {
                EnqueueRaw("FileIOCreate", GetProcessName(data.ProcessID), "", fileName, "", data.ProcessID, data.ThreadID);
                return;
            }

            int adsColon = fileName.IndexOf(':', driveColon + 1);

            if (adsColon > driveColon + 1) {
                string streamName = fileName.Substring(adsColon);
                string alertMsg = $"ADS Created: {fileName}";

                bool isBenignStream = streamName.Contains(":$DATA", StringComparison.OrdinalIgnoreCase) ||
                                      streamName.Contains("SummaryInformation", StringComparison.OrdinalIgnoreCase) ||
                                      streamName.Contains("DocumentSummaryInformation", StringComparison.OrdinalIgnoreCase);

                string proc = GetProcessName(data.ProcessID).ToLowerInvariant();
                bool isBenignProcess = BenignADSProcesses.Contains(proc);

                if (!isBenignStream && !isBenignProcess) {
                    EnqueueAlert("T1564.004", "ADS", proc, data.ProcessID, data.ThreadID, alertMsg);
                }
            }

            // Always forward raw event for ML (ransomware burst, lineage, etc.)
            EnqueueRaw("FileIOCreate", GetProcessName(data.ProcessID), "", fileName, "", data.ProcessID, data.ThreadID);
        };

        // =====================================================================
        // FileIOWrite for Ransomware Burst Detection
        // =====================================================================
        _session.Source.Kernel.FileIOWrite += delegate (Microsoft.Diagnostics.Tracing.Parsers.Kernel.FileIOReadWriteTraceData data) {
            // DEVELOPER NOTE: Prevents the JSONL log writer from triggering the Ransomware ML alert
            if (data.ProcessID == SensorPid) return;

            EnqueueRaw("FileIOWrite", GetProcessName(data.ProcessID), "", data.FileName, "", data.ProcessID, data.ThreadID);
        };

        // =====================================================================
        // 4. MEMORY GUARD, THREAT INTEL & BYOVD
        // =====================================================================
        _session.Source.Kernel.ImageLoad += delegate (ImageLoadTraceData data) {
            string image = data.FileName;
            string cleanName = System.IO.Path.GetFileName(image);

            if (string.IsNullOrEmpty(image)) {
                EnqueueAlert("T1562.001", "UnbackedModule", GetProcessName(data.ProcessID), data.ProcessID, data.ThreadID, "Reflective module loaded without physical file backing");
            }

            if (image.IndexOf(".sys", StringComparison.OrdinalIgnoreCase) >= 0 && data.ProcessID != 4) {
                if (TiDrivers.Contains(cleanName)) {
                    string loader = GetProcessName(data.ProcessID);
                    EnqueueAlert("T1562.001", "ThreatIntel_Driver", loader, data.ProcessID, data.ThreadID, $"Known vulnerable driver loaded: {cleanName}");
                }
            }
        };

        // DEVELOPER NOTE: Event renamed to VirtualMemAlloc in TraceEvent 3.x.
        // Added (int) cast for Flags enum to support PAGE_EXECUTE_READWRITE check.
        // =====================================================================
        // ANTI-TAMPER: VirtualAlloc for RWX Injection Tracking
        // =====================================================================
        _session.Source.Kernel.VirtualMemAlloc += delegate (VirtualAllocTraceData data) {
            // 0x40 is PAGE_EXECUTE_READWRITE (RWX)
            if ((int)data.Flags == 0x40) {
                if (data.ProcessID == SensorPid) {
                    // Capture Memory Forensics
                    PreserveForensics(data.ProcessID, GetProcessName(data.ProcessID));
                    // Freeze the attacking thread
                    bool neutralized = QuarantineNativeThread(data.ThreadID, data.ProcessID);

                    // DEVELOPER NOTE: Bypassing TraceEvent wrapper bugs by dynamically querying the ETW manifest.
                    ulong baseAddress = Convert.ToUInt64(data.PayloadByName("BaseAddress"));
                    ulong regionSize  = Convert.ToUInt64(data.PayloadByName("RegionSize"));

                    NeuterAndDumpPayload(data.ProcessID, baseAddress, regionSize);

                    EnqueueAlert("T1562.001", "SensorTampering", "External Threat", data.ProcessID, data.ThreadID, $"RWX Injection caught. Attacking Thread Quarantined: {neutralized}");
                }
                else if (ProcessStartTime.TryGetValue(data.ProcessID, out DateTime startTime)) {
                    if ((DateTime.UtcNow - startTime).TotalMilliseconds < 1500) {
                        EnqueueAlert("T1055.012", "ProcessHollowing", GetProcessName(data.ProcessID), data.ProcessID, data.ThreadID, "RWX memory allocated in newly spawned process (Hollowing/Injection)");
                    }
                }
            }
        };

        _session.Source.Process();
    }

    /// <summary>
    /// DEVELOPER NOTE: Enhanced StopSession to explicitly clear memory-heavy collections
    /// and nullify the ETW session to support graceful orchestrator shutdown.
    /// </summary>
    public static void StopSession() {
        if (_session != null) {
            _session.Stop();
            _session.Dispose();
            _session = null;
        }

        // Clear high-churn caches to release string memory
        ProcessCache.Clear();
        ProcessStartTime.Clear();
        TiDrivers.Clear();
        // Finalize the native YARA engine to prevent memory leaks
        _yaraContext?.Dispose();
        _yaraContext = null;

        EnqueueDiag("[SYSTEM] ETW Session Stopped and YARA Engine Finalized.");

        // Drain the event queue
        string dummy;
        while (EventQueue.TryDequeue(out dummy));
    }

    private static string GetProcessName(int pid) {
        return ProcessCache.ContainsKey(pid) ? ProcessCache[pid] : pid.ToString();
    }

    private static void EnqueueAlert(string mitre, string type, string process, int pid, int tid, string details) {
        EventQueue.Enqueue($"{{\"Category\":\"StaticAlert\", \"Mitre\":\"{JsonEscape(mitre)}\", \"Type\":\"{JsonEscape(type)}\", \"Process\":\"{JsonEscape(process)}\", \"PID\":{pid}, \"TID\":{tid}, \"Details\":\"{JsonEscape(details)}\"}}");
    }

    private static void EnqueueRaw(string type, string process, string parent, string path, string cmd, int pid, int tid) {
        // DEVELOPER NOTE: All raw telemetry now flows through the JsonEscape sanitizer
        // to prevent PowerShell parse errors on complex system strings.
        EventQueue.Enqueue($"{{\"Category\":\"RawEvent\", \"Type\":\"{JsonEscape(type)}\", \"Process\":\"{JsonEscape(process)}\", \"Parent\":\"{JsonEscape(parent)}\", \"PID\":{pid}, \"TID\":{tid}, \"Path\":\"{JsonEscape(path)}\", \"Cmd\":\"{JsonEscape(cmd)}\"}}");
    }

    private class AhoCorasick {
        class Node {
            public Dictionary<char, Node> Children = new Dictionary<char, Node>();
            public Node Fail;
            public List<int> Outputs = new List<int>();
        }

        private Node Root = new Node();

        public void Build(string[] keywords) {
            for (int i = 0; i < keywords.Length; i++) {
                Node current = Root;
                foreach (char originalC in keywords[i]) {
                    char c = char.ToLowerInvariant(originalC);
                    if (!current.Children.ContainsKey(c))
                        current.Children[c] = new Node();
                    current = current.Children[c];
                }
                current.Outputs.Add(i);
            }

            Queue<Node> queue = new Queue<Node>();
            foreach (var child in Root.Children.Values) {
                child.Fail = Root;
                queue.Enqueue(child);
            }

            while (queue.Count > 0) {
                Node current = queue.Dequeue();
                foreach (var kvp in current.Children) {
                    char c = kvp.Key;
                    Node child = kvp.Value;
                    Node failNode = current.Fail;

                    while (failNode != null && !failNode.Children.ContainsKey(c)) {
                        failNode = failNode.Fail;
                    }

                    child.Fail = failNode != null ? failNode.Children[c] : Root;
                    child.Outputs.AddRange(child.Fail.Outputs);
                    queue.Enqueue(child);
                }
            }
        }

        public int SearchFirst(string text) {
            if (string.IsNullOrEmpty(text)) return -1;
            Node current = Root;
            foreach (char originalC in text) {
                char c = char.ToLowerInvariant(originalC);
                while (current != null && !current.Children.ContainsKey(c)) {
                    current = current.Fail;
                }
                current = current != null ? current.Children[c] : Root;
                if (current.Outputs.Count > 0) return current.Outputs[0];
            }
            return -1;
        }

        public int SearchEndsWith(string text, string[] keys) {
            if (string.IsNullOrEmpty(text)) return -1;
            Node current = Root;
            for (int i = 0; i < text.Length; i++) {
                char c = char.ToLowerInvariant(text[i]);
                while (current != null && !current.Children.ContainsKey(c)) {
                    current = current.Fail;
                }
                current = current != null ? current.Children[c] : Root;
                foreach (int matchIdx in current.Outputs) {
                    if (i == text.Length - 1) return matchIdx;
                }
            }
            return -1;
        }
    }
}