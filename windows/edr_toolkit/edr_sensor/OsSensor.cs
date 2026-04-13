/********************************************************************************
 * SYSTEM:          Deep Sensor - Host Behavioral / ETW Telemetry Engine
 * COMPONENT:       DeepVisibilitySensor.cs (Unmanaged ETW Listener)
 * VERSION:         2.1
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
 * - Native FFI Memory Map: Bypasses all IPC pipelines by directly loading the
 * Rust ML engine (DeepSensor_ML_v2.1.dll) into memory for zero-latency
 * telemetry ingestion.
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

    // =====================================================================
    // NATIVE RUST ML ENGINE FFI INTEGRATION
    // =====================================================================
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool SetDllDirectory(string lpPathName);

    [DllImport("DeepSensor_ML_v2.1.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private static extern IntPtr init_engine();

    [DllImport("DeepSensor_ML_v2.1.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private static extern IntPtr evaluate_telemetry(IntPtr engine, string jsonPayload);

    [DllImport("DeepSensor_ML_v2.1.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern void free_string(IntPtr ptr);

    [DllImport("DeepSensor_ML_v2.1.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern void teardown_engine(IntPtr engine);

    private static BlockingCollection<string> _mlWorkQueue = new BlockingCollection<string>(new ConcurrentQueue<string>());
    private static CancellationTokenSource _mlCancelSource = new CancellationTokenSource();
    private static IntPtr _mlEnginePtr = IntPtr.Zero;

    private static Task _mlConsumerTask;

    // Dashboard Telemetry Counters
    public static long TotalEventsParsed = 0;
    public static long TotalAlertsGenerated = 0;
    public static long TotalMlEvals = 0;

    // =====================================================================

    public static ConcurrentQueue<string> EventQueue = new ConcurrentQueue<string>();
    private static libyaraNET.YaraContext _yaraContext;
    private static TraceEventSession _session;
    public static bool IsArmed = false;

    private static ConcurrentDictionary<int, string> ProcessCache = new ConcurrentDictionary<int, string>();
    private static ConcurrentDictionary<int, DateTime> ProcessStartTime = new ConcurrentDictionary<int, DateTime>();
    private static int SensorPid = -1;

    public struct ModuleMap {
        public string ModuleName;
        public ulong BaseAddress;
        public ulong EndAddress;
    }

    // Dictionary to drop known benign Parent -> Child behaviors instantly at the C# boundary
    public static ConcurrentDictionary<string, byte> BenignLineages = new ConcurrentDictionary<string, byte>(
        new Dictionary<string, byte>(StringComparer.OrdinalIgnoreCase) {
            // Windows Initialization & Core Services
            { "wininit.exe|services.exe", 0 },
            { "wininit.exe|lsass.exe", 0 },
            { "wininit.exe|lsm.exe", 0 },

            // Service Control Manager Spawns
            { "services.exe|svchost.exe", 0 },
            { "services.exe|spoolsv.exe", 0 },
            { "services.exe|msmpeng.exe", 0 },         // Windows Defender
            { "services.exe|searchindexer.exe", 0 },
            { "services.exe|officeclicktorun.exe", 0 }, // Office Updates
            { "services.exe|winmgmt.exe", 0 },

            // Standard Service Host (svchost) Spawns
            { "svchost.exe|taskhostw.exe", 0 },
            { "svchost.exe|wmiprvse.exe", 0 },         // WMI Provider Host
            { "svchost.exe|dllhost.exe", 0 },          // COM Surrogate
            { "svchost.exe|sppsvc.exe", 0 },           // Software Protection
            { "svchost.exe|searchprotocolhost.exe", 0 },
            { "svchost.exe|searchfilterhost.exe", 0 },
            { "svchost.exe|audiodg.exe", 0 },          // Windows Audio Device Graph
            { "svchost.exe|smartscreen.exe", 0 },

            // Background / Ambient Noise
            { "explorer.exe|onedrive.exe", 0 },
            { "taskeng.exe|taskhostw.exe", 0 }
        },
        StringComparer.OrdinalIgnoreCase
    );

    private static ConcurrentDictionary<int, List<ModuleMap>> ProcessModules = new ConcurrentDictionary<int, List<ModuleMap>>();
    public static ConcurrentDictionary<string, byte> SuppressedSigmaRules = new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);

    public static void SuppressSigmaRule(string ruleName) {
        SuppressedSigmaRules.TryAdd(ruleName.Trim(), 0);
    }

    public static ConcurrentDictionary<string, byte> SuppressedProcessRules = new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);

    public static void SuppressProcessRule(string process, string ruleName) {
        string key = $"{process.Trim()}|{ruleName.Trim()}";
        SuppressedProcessRules.TryAdd(key, 0);
    }

    public static ConcurrentDictionary<string, libyaraNET.Rules> YaraMatrices = new ConcurrentDictionary<string, libyaraNET.Rules>(StringComparer.OrdinalIgnoreCase);

    public static void InitializeYaraMatrices(string yaraRuleDirectory) {
        if (!System.IO.Directory.Exists(yaraRuleDirectory)) return;

        foreach (var vectorDir in System.IO.Directory.GetDirectories(yaraRuleDirectory)) {
            string vectorName = System.IO.Path.GetFileName(vectorDir);
            try {
                using (var compiler = new libyaraNET.Compiler()) {
                    foreach (var ruleFile in System.IO.Directory.GetFiles(vectorDir, "*.yar")) {
                        compiler.AddRuleFile(ruleFile);
                    }
                    var rules = compiler.GetRules();
                    YaraMatrices[vectorName] = rules;
                    EnqueueDiag($"[YARA] Compiled vector matrix: {vectorName}");
                }
            } catch (Exception ex) {
                EnqueueDiag($"[YARA] Failed to compile vector {vectorName}: {ex.Message}");
            }
        }
    }

    public static string DetermineThreatVector(string processName) {
        string proc = processName.ToLowerInvariant();
        if (proc.Contains("w3wp") || proc.Contains("nginx") || proc.Contains("httpd")) return "WebInfrastructure";
        if (proc.Contains("spoolsv") || proc.Contains("lsass") || proc.Contains("smss")) return "SystemExploits";
        if (proc.Contains("powershell") || proc.Contains("cmd") || proc.Contains("wscript")) return "LotL";
        if (proc.Contains("winword") || proc.Contains("excel")) return "MacroPayloads";
        if (proc.Contains("rundll32") || proc.Contains("regsvr32")) return "BinaryProxy";
        if (proc.Contains("explorer") || proc.Contains("winlogon")) return "SystemPersistence";
        return "Core_C2";
    }

    public static string EvaluatePayloadInMemory(byte[] payload, string processName) {
        string vector = DetermineThreatVector(processName);
        if (!YaraMatrices.ContainsKey(vector)) vector = "Core_C2";
        if (!YaraMatrices.ContainsKey(vector)) return "NoSignatureMatch";

        try {
            var scanner = new libyaraNET.Scanner();
            var results = scanner.ScanMemory(payload, YaraMatrices[vector]);
            if (results != null && results.Count > 0) {
                List<string> matches = new List<string>();
                foreach (var match in results) { matches.Add(match.MatchingRule.Identifier); }
                return string.Join(" | ", matches);
            }
        } catch (Exception ex) {
            return $"YaraEvaluationError: {ex.Message}";
        }
        return "NoSignatureMatch";
    }

    private static bool IsForgedReturnAddress(int pid, ulong returnAddr) {
        if (returnAddr < 6) return true;

        uint PROCESS_VM_READ_OPERATION = 0x0010 | 0x0008;
        IntPtr hProcess = OpenProcess(PROCESS_VM_READ_OPERATION, false, (uint)pid);
        if (hProcess == IntPtr.Zero) return true;

        try {
            byte[] buffer = new byte[10];
            ulong readAddr = returnAddr - 10;
            if (!ReadProcessMemory(hProcess, (IntPtr)readAddr, buffer, (UIntPtr)10, out _)) return true;

            for (int i = 0; i < 6; i++) {
                byte b = buffer[i];
                if (b == 0xE8 || b == 0xE9 || b == 0xEB) return false;
                if (b == 0xFF) {
                    byte modrm = buffer[i + 1];
                    if ((modrm & 0xF8) == 0xD0 || (modrm & 0xF8) == 0x10 ||
                        (modrm & 0xF8) == 0x50 || (modrm & 0xF8) == 0x90) return false;
                }
            }
            return true;
        } catch {
            return true;
        } finally {
            CloseHandle(hProcess);
        }
    }

    private static readonly HashSet<string> CriticalSystemProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
        "csrss.exe", "lsass.exe", "smss.exe", "services.exe", "wininit.exe", "winlogon.exe", "system"
    };

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

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

    public static bool QuarantineNativeThread(int tid, int pid) {
        if (!IsArmed) return false;
        string procName = GetProcessName(pid);
        if (CriticalSystemProcesses.Contains(procName)) return false;

        uint THREAD_SUSPEND_RESUME = 0x0002;
        IntPtr hThread = OpenThread(THREAD_SUSPEND_RESUME, false, (uint)tid);
        if (hThread == IntPtr.Zero) return false;

        uint suspendCount = SuspendThread(hThread);
        CloseHandle(hThread);
        return (suspendCount != 0xFFFFFFFF);
    }

    public static string NeuterAndDumpPayload(int pid, ulong address, ulong size) {
        string yaraResult = "NoSignatureMatch";
        string procName = GetProcessName(pid);
        if (CriticalSystemProcesses.Contains(procName)) return yaraResult;

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

                if (yaraResult != "NoSignatureMatch") {
                    EnqueueAlert("T1059", "YaraPayloadAttribution", procName, "Unknown", pid, 0, 0, "", $"In-Memory Shellcode Identified As: {yaraResult}");
                }
            }

            uint PAGE_NOACCESS = 0x01;
            VirtualProtectEx(hProcess, (IntPtr)address, (UIntPtr)size, PAGE_NOACCESS, out uint oldProtect);
        } catch {
            return "ForensicError";
        } finally {
            CloseHandle(hProcess);
        }
        return yaraResult;
    }

    public static string PreserveForensics(int pid, string procName) {
        if (!IsArmed) return "Bypassed";
        string dumpDir = @"C:\ProgramData\DeepSensor\Data\Forensics";
        System.IO.Directory.CreateDirectory(dumpDir);
        string dumpPath = $@"{dumpDir}\{procName}_{pid}_{DateTime.UtcNow:yyyyMMddHHmmss}.dmp";

        IntPtr hProcess = OpenProcess(0x0400 | 0x0010, false, (uint)pid);
        if (hProcess == IntPtr.Zero) return "AccessDenied";

        try {
            using (var fs = new System.IO.FileStream(dumpPath, System.IO.FileMode.Create, System.IO.FileAccess.ReadWrite, System.IO.FileShare.Write)) {
                if (MiniDumpWriteDump(hProcess, (uint)pid, fs.SafeFileHandle, 2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero)) {
                    return dumpPath;
                }
            }
        } catch { } finally { CloseHandle(hProcess); }
        return "Failed";
    }

    private static readonly string[] MonitoredRegPaths = {
        "image file execution options", "inprocserver32", "treatas",
        "windows\\currentversion\\run", "session manager", "services",
        "wmi\\autologger", "amsi\\providers", "control\\lsa\\security packages"
    };

    private static double ShannonEntropy(string s) {
        if (string.IsNullOrEmpty(s)) return 0.0;
        var counts = new Dictionary<char, int>();
        foreach (char c in s) { counts[c] = counts.GetValueOrDefault(c) + 1; }
        double entropy = 0.0;
        int len = s.Length;
        foreach (var count in counts.Values) {
            double p = (double)count / len;
            entropy -= p * Math.Log(p, 2);
        }
        return entropy;
    }

    private static HashSet<string> BenignExplorerValueNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    private static HashSet<string> BenignADSProcesses     = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    private static HashSet<string> TiDrivers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    private static string[] SigmaCmdKeys;
    private static string[] SigmaCmdTitles;
    private static string[] SigmaImgKeys;
    private static string[] SigmaImgTitles;

    private static AhoCorasick CmdAc;
    private static AhoCorasick ImgAc;

    [ThreadStatic]
    private static StringBuilder _jsonSb;

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

    // Enables dynamic loading of the Native Rust DLL by PowerShell
    public static void SetLibraryPath(string path) {
        SetDllDirectory(path);
    }

    private static string _dllPath;

    public static void Initialize(string dllPath, int currentPid, string[] tiDrivers, string[] sigmaCmdKeys, string[] sigmaCmdTitles, string[] sigmaImgKeys, string[] sigmaImgTitles, string[] benignExplorerValues, string[] benignADSProcs) {
        _dllPath = dllPath;
        SensorPid = currentPid;

        try {
            _yaraContext = new libyaraNET.YaraContext();
            EnqueueDiag("[YARA] Native context initialized successfully.");
        } catch (Exception ex) { EnqueueDiag($"[YARA] Context Init Failed: {ex.Message}"); }

        // --- NATIVE RUST ENGINE FFI IMPORT ---
        try {
            _mlEnginePtr = init_engine();
            if (_mlEnginePtr != IntPtr.Zero) {
                // Success: Engine is mapped and database is ready
                EnqueueDiag("[ML ENGINE] Native DLL successfully mapped at memory address: 0x" + _mlEnginePtr.ToString("X"));
                EnqueueDiag("[ML ENGINE] UEBA Database initialized at C:\\ProgramData\\DeepSensor\\Data\\DeepSensor_UEBA.db");
            } else {
                // Failure: Pointer is null. Likely causes: DB locked or missing DLL.
                EnqueueDiag("[ML ENGINE ERROR] init_engine returned NULL. Database may be locked or path inaccessible.");
            }
        } catch (Exception ex) {
            // Failure: Critical FFI crash (e.g., mismatched architecture or missing entry point)
            EnqueueDiag($"[ML ENGINE ERROR] FFI Import Failed: {ex.Message}");
        }

        foreach (var p in System.Diagnostics.Process.GetProcesses()) {
            try { ProcessCache[p.Id] = p.ProcessName + ".exe"; } catch { }
        }

        BenignExplorerValueNames = new HashSet<string>(benignExplorerValues, StringComparer.OrdinalIgnoreCase);
        BenignADSProcesses       = new HashSet<string>(benignADSProcs,       StringComparer.OrdinalIgnoreCase);

        AppDomain.CurrentDomain.AssemblyResolve += (sender, args) => {
            string folderPath = System.IO.Path.GetDirectoryName(_dllPath);
            string assemblyName = new System.Reflection.AssemblyName(args.Name).Name;
            string targetPath = System.IO.Path.Combine(folderPath, assemblyName + ".dll");
            if (System.IO.File.Exists(targetPath)) return System.Reflection.Assembly.LoadFrom(targetPath);
            return null;
        };

        UpdateThreatIntel(tiDrivers, sigmaCmdKeys, sigmaCmdTitles, sigmaImgKeys, sigmaImgTitles);

        // Start the dedicated ML consumer thread with Micro-Batching
        _mlConsumerTask = Task.Factory.StartNew(() => {
            try {
                while (!_mlWorkQueue.IsCompleted) {
                    var batch = new List<string>();

                    // Block indefinitely until at least ONE event arrives
                    if (_mlWorkQueue.TryTake(out string firstEvent, Timeout.Infinite, _mlCancelSource.Token)) {
                        batch.Add(firstEvent);

                        // Quickly drain up to 999 more events if they are waiting (10ms timeout)
                        while (batch.Count < 1000 && _mlWorkQueue.TryTake(out string nextEvent, 10)) {
                            batch.Add(nextEvent);
                        }

                        if (_mlEnginePtr == IntPtr.Zero) continue;

                        // Wrap the batch in a JSON array format for Rust
                        string jsonArray = "[" + string.Join(",", batch) + "]";
                        Interlocked.Add(ref TotalMlEvals, batch.Count);

                        IntPtr resultPtr = evaluate_telemetry(_mlEnginePtr, jsonArray);
                        if (resultPtr != IntPtr.Zero) {
                            string alertJson = Marshal.PtrToStringAnsi(resultPtr);
                            free_string(resultPtr);
                            if (!string.IsNullOrEmpty(alertJson)) {
                                EventQueue.Enqueue($"[ML_ALERTS]{alertJson}");
                            }
                        }
                    }
                }
            } catch (OperationCanceledException) {
                // Normal shutdown via CancellationToken
            } catch (Exception ex) {
                EnqueueDiag($"[ML CONSUMER FATAL] {ex.Message}");
            }
        }, _mlCancelSource.Token, TaskCreationOptions.LongRunning, TaskScheduler.Default);
    }

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

    public static void StartSession() {
        Task.Run(async () => {
            while (true) {
                await Task.Delay(TimeSpan.FromHours(1));
                try {
                    var activePids = new HashSet<int>();
                    foreach (var p in System.Diagnostics.Process.GetProcesses()) { activePids.Add(p.Id); }
                    foreach (var key in ProcessCache.Keys) {
                        if (!activePids.Contains(key)) {
                            ProcessCache.TryRemove(key, out _);
                            ProcessStartTime.TryRemove(key, out _);
                        }
                    }
                } catch { }
            }
        });

        Task.Run(() => {
            try { RunEtwCore(); }
            catch (Exception ex) { EventQueue.Enqueue($"{{\"Provider\":\"Error\", \"Message\":\"{JsonEscape(ex.Message)}\"}}"); }
        });

        Thread umThread = new Thread(() => {
            try {
                string umSessionName = "DeepSensor_UserMode";
                if (TraceEventSession.GetActiveSessionNames().Contains(umSessionName)) {
                    using (var old = new TraceEventSession(umSessionName)) { old.Stop(true); }
                }

                using (var userSession = new TraceEventSession(umSessionName)) {
                    userSession.EnableProvider(Guid.Parse("1418ef04-b0b4-4623-bf7e-d74ab47bbdaa")); // WMI
                    userSession.EnableProvider(Guid.Parse("a0c1853b-5c40-4b15-8766-3cf1c58f985a")); // PowerShell

                    userSession.Source.Dynamic.All += delegate (TraceEvent data) {
                        if (data.ProviderName == "Microsoft-Windows-WMI-Activity" || data.ProviderName == "Microsoft-Windows-PowerShell") {
                            StringBuilder sb = new StringBuilder();
                            if (data.PayloadNames != null) {
                                foreach (string key in data.PayloadNames) {
                                    try { sb.Append($"{data.PayloadString(data.PayloadIndex(key))} "); } catch { }
                                }
                            }

                            string dynamicPayload = sb.ToString().Trim().ToLowerInvariant();
                            if (dynamicPayload.Length > 5) {
                                int cmdMatch = CmdAc.SearchFirst(dynamicPayload);
                                if (cmdMatch >= 0) {
                                    string fullTitle = SigmaCmdTitles[cmdMatch];
                                    string cleanTitle = fullTitle;
                                    int bracketIdx = fullTitle.IndexOf('[');
                                    if (bracketIdx > 0) { cleanTitle = fullTitle.Substring(0, bracketIdx).Trim(); }

                                    string procName = GetProcessName(data.ProcessID);
                                    if (string.IsNullOrWhiteSpace(procName) || procName == "0" || procName == "-1") {
                                        procName = data.ProviderName.Contains("WMI") ? "WMI_Activity" : "PowerShell_Host";
                                    }

                                    string cacheKey = $"{procName}|{cleanTitle}";
                                    // Check both Global Suppression and Process-Specific Suppression
                                    if (!SuppressedSigmaRules.ContainsKey(cleanTitle) && !SuppressedProcessRules.ContainsKey(cacheKey)) {
                                        EnqueueAlert("Sigma_UserMode", "AdvancedDetection", procName, "Unknown", data.ProcessID, 0, data.ThreadID, dynamicPayload, $"Rule: {fullTitle}");
                                    }
                                }
                            }
                        }
                    };
                    userSession.Source.Process();
                }
            } catch (Exception ex) { EnqueueDiag($"USER-MODE ETW CRASH: {ex.Message}"); }
        });
        umThread.IsBackground = true;
        umThread.Start();
    }

    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoInlining)]
    private static void RunEtwCore() {
        string sessionName = KernelTraceEventParser.KernelSessionName;
        if (TraceEventSession.GetActiveSessionNames().Contains(sessionName)) {
            using (var old = new TraceEventSession(sessionName)) { old.Stop(true); }
        }

        _session = new TraceEventSession(sessionName);
        EnqueueDiag($"TraceEventSession bound: {sessionName}");

        var kernelKeywords = KernelTraceEventParser.Keywords.Process | KernelTraceEventParser.Keywords.Registry |
            KernelTraceEventParser.Keywords.FileIOInit | KernelTraceEventParser.Keywords.FileIO |
            KernelTraceEventParser.Keywords.ImageLoad | KernelTraceEventParser.Keywords.Memory;

        _session.EnableKernelProvider(kernelKeywords);

        _session.Source.Kernel.ImageLoad += delegate (ImageLoadTraceData data) {
            if (data.ProcessID == SensorPid || data.ProcessID == 0) return;
            var map = new ModuleMap { ModuleName = data.FileName, BaseAddress = (ulong)data.ImageBase, EndAddress = (ulong)data.ImageBase + (ulong)data.ImageSize };
            ProcessModules.AddOrUpdate(data.ProcessID, pid => new List<ModuleMap> { map }, (pid, list) => { lock (list) { list.Add(map); } return list; });

            if (data.FileName.IndexOf(".sys", StringComparison.OrdinalIgnoreCase) >= 0 && data.ProcessID != 4) {
                if (TiDrivers.Contains(System.IO.Path.GetFileName(data.FileName))) {
                    EnqueueAlert("T1562.001", "ThreatIntel_Driver", GetProcessName(data.ProcessID), "Unknown", data.ProcessID, 0, data.ThreadID, "", $"Known vulnerable driver loaded: {data.FileName}");
                }
            }
        };

        _session.Source.Kernel.StackWalkStack += delegate (StackWalkStackTraceData data) {
            if (!ProcessModules.TryGetValue(data.ProcessID, out var modules)) return;
            int unbackedFrames = 0, forgedReturns = 0;

            for (int i = 0; i < data.FrameCount; i++) {
                ulong instructionPointer = data.InstructionPointer(i);
                bool isBacked = false;
                foreach (var mod in modules) {
                    if (instructionPointer >= mod.BaseAddress && instructionPointer <= mod.EndAddress) { isBacked = true; break; }
                }
                if (!isBacked) {
                    unbackedFrames++;
                    if (IsForgedReturnAddress(data.ProcessID, instructionPointer)) forgedReturns++;
                }
            }

            if (unbackedFrames >= 2 || forgedReturns > 0) {
                EventQueue.Enqueue($"{{\"Category\":\"StaticAlert\", \"Type\":\"StackSpoofDetected\", \"Process\":\"PID:{data.ProcessID}\", \"Reason\":\"{unbackedFrames} unbacked frames | {forgedReturns} forged returns\", \"Action\":\"QueueForQuarantine\"}}");
            }
        };

        _session.Source.Kernel.ProcessStart += delegate (ProcessTraceData data) {
            try {
                string image = data.ImageFileName;
                ProcessCache[data.ProcessID] = image;
                ProcessStartTime[data.ProcessID] = DateTime.UtcNow;

                if (data.ProcessID == SensorPid || data.ParentID == SensorPid) return;

                string cmd = data.CommandLine;
                if (cmd.IndexOf("logman", StringComparison.OrdinalIgnoreCase) >= 0 && cmd.IndexOf("stop", StringComparison.OrdinalIgnoreCase) >= 0) {
                    EnqueueAlert("T1562.002", "ETWTampering", image, GetProcessName(data.ParentID), data.ProcessID, data.ParentID, data.ThreadID, cmd, $"Attempted to terminate ETW: {cmd}");
                }

                int cmdMatch = CmdAc.SearchFirst(cmd);
                if (cmdMatch >= 0) {
                    string fullTitle = SigmaCmdTitles[cmdMatch];
                    int bracketIdx = fullTitle.IndexOf('[');
                    string cleanTitle = bracketIdx > 0 ? fullTitle.Substring(0, bracketIdx).Trim() : fullTitle;

                    string cacheKey = $"{image}|{cleanTitle}";
                    if (!SuppressedSigmaRules.ContainsKey(cleanTitle) && !SuppressedProcessRules.ContainsKey(cacheKey)) {
                        EnqueueAlert("Sigma_Match", "SigmaDetection", image, GetProcessName(data.ParentID), data.ProcessID, data.ParentID, data.ThreadID, cmd, $"Rule: {fullTitle}");
                    }
                }

                EnqueueRaw("ProcessStart", image, GetProcessName(data.ParentID), "", cmd, data.ProcessID, data.ThreadID);
                } catch (Exception ex) {
                EnqueueDiag($"[ETW ERROR] ProcessStart handler failed: {ex.Message}");
            }
        };

        _session.Source.Kernel.ProcessStop += delegate (ProcessTraceData data) {
            ProcessCache.TryRemove(data.ProcessID, out _);
            ProcessStartTime.TryRemove(data.ProcessID, out _);
            ProcessModules.TryRemove(data.ProcessID, out _);
        };

        _session.Source.Kernel.RegistrySetValue += delegate (RegistryTraceData data) {
            if (data.ProcessID == SensorPid) return;

            string keyName = data.KeyName ?? "", valueName = data.ValueName ?? "";
            string procLower = GetProcessName(data.ProcessID).ToLowerInvariant();

            if (procLower.Contains("trustedinstaller") || procLower.Contains("svchost")) {
                EnqueueRaw("RegistryWrite", GetProcessName(data.ProcessID), "", keyName, valueName, data.ProcessID, data.ThreadID); return;
            }
            if (procLower.Contains("explorer") && BenignExplorerValueNames.Contains(valueName)) {
                EnqueueRaw("RegistryWrite", GetProcessName(data.ProcessID), "", keyName, valueName, data.ProcessID, data.ThreadID); return;
            }

            string searchText = (keyName + "\\" + valueName).ToLowerInvariant();
            bool isPersistence = false;
            foreach (string monitored in MonitoredRegPaths) {
                if (searchText.Contains(monitored)) { isPersistence = true; break; }
            }

            if (isPersistence) {
                EnqueueAlert("T1547.001", "RegPersistence", procLower, "Unknown", data.ProcessID, 0, data.ThreadID, "", $"Persistence Key: {keyName}");
            }

            EnqueueRaw("RegistryWrite", GetProcessName(data.ProcessID), "", keyName, valueName, data.ProcessID, data.ThreadID);
        };

        _session.Source.Kernel.FileIOCreate += delegate (FileIOCreateTraceData data) {
            if (data.FileName.Contains("deepsensor_canary.tmp", StringComparison.OrdinalIgnoreCase)) {
                EventQueue.Enqueue("{\"Provider\":\"HealthCheck\", \"EventName\":\"ETW_HEARTBEAT\"}"); return;
            }

            if (data.FileName.Contains(@"\Device\NamedPipe\", StringComparison.OrdinalIgnoreCase)) {
                string[] pipeParts = data.FileName.Split(new[] { @"\NamedPipe\" }, StringSplitOptions.None);
                string pipeName = pipeParts.Length > 0 ? pipeParts[pipeParts.Length - 1] : "";

                if (ShannonEntropy(pipeName) > 3.5 || pipeName.Contains("mojo.")) {
                    EnqueueAlert("T1021.002", "SuspiciousNamedPipe", GetProcessName(data.ProcessID), "Unknown", data.ProcessID, 0, data.ThreadID, "", $"Pipe: {pipeName}");
                }
            }

            EnqueueRaw("FileIOCreate", GetProcessName(data.ProcessID), "", data.FileName, "", data.ProcessID, data.ThreadID);
        };

        _session.Source.Kernel.FileIOWrite += delegate (FileIOReadWriteTraceData data) {
            if (data.ProcessID == SensorPid) return;
            EnqueueRaw("FileIOWrite", GetProcessName(data.ProcessID), "", data.FileName, "", data.ProcessID, data.ThreadID);
        };

        _session.Source.Kernel.VirtualMemAlloc += delegate (VirtualAllocTraceData data) {
            if ((int)data.Flags == 0x40) { // PAGE_EXECUTE_READWRITE
                if (data.ProcessID == SensorPid) {
                    bool neutralized = QuarantineNativeThread(data.ThreadID, data.ProcessID);
                    ulong baseAddr = Convert.ToUInt64(data.PayloadByName("BaseAddress"));
                    ulong regSize  = Convert.ToUInt64(data.PayloadByName("RegionSize"));
                    NeuterAndDumpPayload(data.ProcessID, baseAddr, regSize);
                    EnqueueAlert("T1562.001", "SensorTampering", "External Threat", "Unknown", data.ProcessID, 0, data.ThreadID, "", $"RWX Injection caught. Attacking Thread Quarantined: {neutralized}");
                }
            }
        };

        _session.Source.Process();
    }

    public static void StopSession() {
        // 1. Stop the ETW session first to prevent new events from entering the queue
        if (_session != null) {
            _session.Stop();
            _session.Dispose();
            _session = null;
        }

        // 2. Signal the ML queue that no more items will be added and cancel the token
        _mlWorkQueue.CompleteAdding();
        _mlCancelSource.Cancel();

        // 3. Wait for the background thread to finish its last calculation (max 2 seconds)
        if (_mlConsumerTask != null) {
            _mlConsumerTask.Wait(2000);
        }

        // 4. Now that the thread is dead, safely destroy the Rust engine
        if (_mlEnginePtr != IntPtr.Zero) {
            teardown_engine(_mlEnginePtr);
            _mlEnginePtr = IntPtr.Zero;
            EnqueueDiag("[ML ENGINE] Native Rust DLL safely unloaded and DB flushed.");
        }

        ProcessCache.Clear();
        ProcessStartTime.Clear();
        TiDrivers.Clear();
        if (_yaraContext != null) { _yaraContext.Dispose(); _yaraContext = null; }
    }

    private static string GetProcessName(int pid) {
        return ProcessCache.ContainsKey(pid) ? ProcessCache[pid] : pid.ToString();
    }

    // EnqueueAlert with Fingerprinting
    public static void EnqueueAlert(string category, string eventType, string process, string parentProcess, int pid, int parentPid, int tid, string cmdline, string details) {
        if (_mlEnginePtr == IntPtr.Zero) return;

        // 1. PRE-ALERT GATEKEEPER: Drop known benign lineages instantly
        string lineageKey = $"{parentProcess}|{process}";
        if (BenignLineages.ContainsKey(lineageKey)) return;

        // 2. FINGERPRINTING: Validate known noisy but benign command structures
        string lowerCmd = cmdline.ToLowerInvariant();

        if (process.Equals("pwsh.exe", StringComparison.OrdinalIgnoreCase)) {
            // Drop VS Code Editor Services Telemetry
            if (lowerCmd.Contains("visual studio code host") && lowerCmd.Contains("ms-vscode.powershell")) return;
        }

        if (process.Equals("microsoft.visualstudio.code.servicecontroller.exe", StringComparison.OrdinalIgnoreCase) ||
            process.Equals("microsoft.visualstudio.code.servicehost.exe", StringComparison.OrdinalIgnoreCase)) {
            // Drop VS Code .NET / C# Dev Kit Telemetry
            if (lowerCmd.Contains("/telemetrysession:") || lowerCmd.Contains("dotnet.projectsystem")) return;
        }

        if (process.Equals("vssadmin.exe", StringComparison.OrdinalIgnoreCase)) {
            // Example: Drop authorized backup service volume shadow copies (Add your specific backup cmdline here)
            if (lowerCmd.Contains("list shadows") && parentProcess.Equals("wbengine.exe", StringComparison.OrdinalIgnoreCase)) return;
        }

        // 3. ENRICHED FFI JSON BUILDER
        string jsonEvent = $@"{{
            ""Category"":""{category}"",
            ""Type"":""{eventType}"",
            ""Process"":""{JsonEscape(process)}"",
            ""Parent"":""{JsonEscape(parentProcess)}"",
            ""PID"":{pid},
            ""ParentPID"":{parentPid},
            ""TID"":{tid},
            ""Cmd"":""{JsonEscape(cmdline)}"",
            ""Details"":""{JsonEscape(details)}""
        }}".Replace("\r", "").Replace("\n", "");

        if (!_mlWorkQueue.IsAddingCompleted) {
            _mlWorkQueue.Add(jsonEvent);
        }
    }

    private static void EnqueueRaw(string type, string process, string parent, string path, string cmd, int pid, int tid) {
        Interlocked.Increment(ref TotalEventsParsed);
        if (_mlEnginePtr == IntPtr.Zero) return;

        string jsonEvent = $"{{\"Category\":\"RawEvent\", \"Type\":\"{JsonEscape(type)}\", \"Process\":\"{JsonEscape(process)}\", \"Parent\":\"{JsonEscape(parent)}\", \"PID\":{pid}, \"TID\":{tid}, \"Path\":\"{JsonEscape(path)}\", \"Cmd\":\"{JsonEscape(cmd)}\"}}";

        if (!_mlWorkQueue.IsAddingCompleted && _mlEnginePtr != IntPtr.Zero) {
            bool added = _mlWorkQueue.TryAdd(jsonEvent);
            if (!added) EnqueueDiag("[DROPPED] ML queue full - raw event dropped (high load)");
        }
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
                    if (!current.Children.ContainsKey(c)) current.Children[c] = new Node();
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
                    while (failNode != null && !failNode.Children.ContainsKey(c)) failNode = failNode.Fail;
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
                while (current != null && !current.Children.ContainsKey(c)) current = current.Fail;
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
                while (current != null && !current.Children.ContainsKey(c)) current = current.Fail;
                current = current != null ? current.Children[c] : Root;
                foreach (int matchIdx in current.Outputs) if (i == text.Length - 1) return matchIdx;
            }
            return -1;
        }
    }
}