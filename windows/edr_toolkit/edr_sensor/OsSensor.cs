/********************************************************************************
 * SYSTEM:          Deep Sensor - Host Behavioral / ETW Telemetry Engine
 * COMPONENT:       DeepVisibilitySensor.cs (Unmanaged ETW Listener)
 * VERSION:         2.1
 * AUTHOR:          Robert Weber
 * * DESCRIPTION:
 * A high-performance, real-time Event Tracing for Windows (ETW) listener compiled
 * natively into the PowerShell runspace.
 ********************************************************************************/

using System;
using System.IO;
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
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetDllDirectory(string lpPathName);

    [DllImport("DeepSensor_ML_v2.1.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private static extern IntPtr init_engine();

    [DllImport("DeepSensor_ML_v2.1.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    private static extern IntPtr evaluate_telemetry(IntPtr engine, string jsonPayload);

    [DllImport("DeepSensor_ML_v2.1.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern void free_string(IntPtr ptr);

    [DllImport("DeepSensor_ML_v2.1.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern void teardown_engine(IntPtr engine);

    private static BlockingCollection<string> _mlWorkQueue = new BlockingCollection<string>(new ConcurrentQueue<string>(), 50000);
    private static CancellationTokenSource _mlCancelSource = new CancellationTokenSource();
    private static IntPtr _mlEnginePtr = IntPtr.Zero;

    private static Task _mlConsumerTask;

    // Dashboard Telemetry Counters
    public static long TotalEventsParsed = 0;
    public static long TotalAlertsGenerated = 0;
    public static long TotalMlEvals = 0;

    public class SigmaRule {
        public string id;
        public string category;
        public string anchor_string;
    }

    public static void SafeEnqueueEvent(string jsonPayload) {
        if (EventQueue == null) return;
        EventQueue.Enqueue(jsonPayload);
    }

    // NATIVE POWERSHELL ROUTING WRAPPER
    public static void InjectUebaTelemetry(string jsonEvent) {
        if (_mlEnginePtr == IntPtr.Zero || _mlWorkQueue == null) return;
        try {
            if (!_mlWorkQueue.IsAddingCompleted) {
                _mlWorkQueue.Add(jsonEvent);
            }
        } catch (InvalidOperationException) { /* Prevents Orchestrator Fatal Crashes */ }
    }

    public static ConcurrentQueue<string> EventQueue = new ConcurrentQueue<string>();
    private static libyaraNET.YaraContext _yaraContext;
    private static TraceEventSession _session;
    public static bool IsArmed = false;

    private static ConcurrentDictionary<int, string> ProcessCache = new ConcurrentDictionary<int, string>();
    private static ConcurrentDictionary<int, DateTime> ProcessStartTime = new ConcurrentDictionary<int, DateTime>();
    private static ConcurrentDictionary<int, string> ProcessUserCache = new ConcurrentDictionary<int, string>();
    private static int SensorPid = -1;
    public static string HostComputerName = "";
    public static string HostIP = "";
    public static string HostOS = "";
    public static string SensorUser = "";

    public struct ModuleMap : IComparable<ModuleMap> {
        public string ModuleName;
        public ulong BaseAddress;
        public ulong EndAddress;

        public int CompareTo(ModuleMap other) {
            return BaseAddress.CompareTo(other.BaseAddress);
        }
    }

    // Dictionary to drop known benign Parent -> Child behaviors instantly at the C# boundary
    public static ConcurrentDictionary<string, byte> BenignLineages = new ConcurrentDictionary<string, byte>(
        new Dictionary<string, byte>(StringComparer.OrdinalIgnoreCase) {
            // Windows Initialization & Core Services
            { "wininit.exe|services.exe", 0 }, { "wininit.exe|lsass.exe", 0 }, { "wininit.exe|lsm.exe", 0 },

            // Service Control Manager Spawns
            { "services.exe|svchost.exe", 0 }, { "services.exe|spoolsv.exe", 0 }, { "services.exe|msmpeng.exe", 0 },
            { "services.exe|searchindexer.exe", 0 }, { "services.exe|officeclicktorun.exe", 0 }, { "services.exe|winmgmt.exe", 0 },

            // Standard Service Host (svchost) Spawns
            { "svchost.exe|taskhostw.exe", 0 }, { "svchost.exe|wmiprvse.exe", 0 }, { "svchost.exe|dllhost.exe", 0 },
            { "svchost.exe|sppsvc.exe", 0 }, { "svchost.exe|searchprotocolhost.exe", 0 }, { "svchost.exe|searchfilterhost.exe", 0 },
            { "svchost.exe|audiodg.exe", 0 }, { "svchost.exe|smartscreen.exe", 0 },

            // Background / Ambient Noise
            { "explorer.exe|onedrive.exe", 0 }, { "taskeng.exe|taskhostw.exe", 0 }
        },
        StringComparer.OrdinalIgnoreCase
    );

    // Uses Immutable Arrays for lock-free, O(1) read operations during StackWalks
    private static ConcurrentDictionary<int, ModuleMap[]> ProcessModules = new ConcurrentDictionary<int, ModuleMap[]>();
    public static ConcurrentDictionary<string, byte> SuppressedSigmaRules = new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);

    public static void SuppressSigmaRule(string ruleName) { SuppressedSigmaRules.TryAdd(ruleName.Trim(), 0); }

    public static ConcurrentDictionary<string, byte> SuppressedProcessRules = new ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);

    public static void SuppressProcessRule(string process, string ruleName) {
        string key = $"{process.Trim()}|{ruleName.Trim()}";
        SuppressedProcessRules.TryAdd(key, 0);
    }

    // CONFIG-DRIVEN SUPPRESSION HELPERS (called from launcher)
    public static void AddBenignLineage(string lineageKey) {
        if (!string.IsNullOrWhiteSpace(lineageKey)) {
            BenignLineages.TryAdd(lineageKey.Trim(), 0);
        }
    }

    public static void SuppressRulesFromConfig(string[] rules) {
        if (rules == null) return;
        foreach (string rule in rules) {
            if (!string.IsNullOrWhiteSpace(rule)) {
                SuppressSigmaRule(rule.Trim());
            }
        }
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
                    YaraMatrices[vectorName] = compiler.GetRules();
                    EnqueueDiag($"[YARA] Compiled vector matrix: {vectorName}");
                }
            } catch (Exception ex) {
                EnqueueDiag($"[YARA] Failed to compile vector {vectorName}: {ex.Message}");
            }
        }
    }

    public static bool IsYaraRuleValid(string filePath) {
        try {
            using (var compiler = new libyaraNET.Compiler()) {
                compiler.AddRuleFile(filePath);
                return true;
            }
        } catch { return false; }
    }

    public static string DetermineThreatVector(string processName) {
        // Zero-allocation substring checks instead of processName.ToLowerInvariant().Contains()
        if (processName.IndexOf("w3wp", StringComparison.OrdinalIgnoreCase) >= 0 || processName.IndexOf("nginx", StringComparison.OrdinalIgnoreCase) >= 0 || processName.IndexOf("httpd", StringComparison.OrdinalIgnoreCase) >= 0) return "WebInfrastructure";
        if (processName.IndexOf("spoolsv", StringComparison.OrdinalIgnoreCase) >= 0 || processName.IndexOf("lsass", StringComparison.OrdinalIgnoreCase) >= 0 || processName.IndexOf("smss", StringComparison.OrdinalIgnoreCase) >= 0) return "SystemExploits";
        if (processName.IndexOf("powershell", StringComparison.OrdinalIgnoreCase) >= 0 || processName.IndexOf("cmd", StringComparison.OrdinalIgnoreCase) >= 0 || processName.IndexOf("wscript", StringComparison.OrdinalIgnoreCase) >= 0) return "LotL";
        if (processName.IndexOf("winword", StringComparison.OrdinalIgnoreCase) >= 0 || processName.IndexOf("excel", StringComparison.OrdinalIgnoreCase) >= 0) return "MacroPayloads";
        if (processName.IndexOf("rundll32", StringComparison.OrdinalIgnoreCase) >= 0 || processName.IndexOf("regsvr32", StringComparison.OrdinalIgnoreCase) >= 0) return "BinaryProxy";
        if (processName.IndexOf("explorer", StringComparison.OrdinalIgnoreCase) >= 0 || processName.IndexOf("winlogon", StringComparison.OrdinalIgnoreCase) >= 0) return "SystemPersistence";
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
        } catch (Exception ex) { return $"YaraEvaluationError: {ex.Message}"; }
        return "NoSignatureMatch";
    }

    private static bool IsForgedReturnAddress(int pid, ulong returnAddr) {
        if (returnAddr < 10) return true;
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
        } catch { return true; } finally { CloseHandle(hProcess); }
    }

    // EXHAUSTIVE ANTI-BSOD LIST: Touching these will cause system instability or immediate bugchecks
    private static readonly HashSet<string> CriticalSystemProcesses = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
        "csrss.exe", "lsass.exe", "smss.exe", "services.exe", "wininit.exe", "winlogon.exe", "system",
        "svchost.exe", "dwm.exe", "explorer.exe", "lsaiso.exe", "fontdrvhost.exe", "spoolsv.exe", "taskhostw.exe"
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

        // Prevent malware from crashing the EDR via massive RWX heap sprays (Cap at 50MB)
        if (size > 52428800) return "AllocationExceedsScanLimit";

        uint PROCESS_VM_READ_OPERATION = 0x0010 | 0x0008;
        IntPtr hProcess = OpenProcess(PROCESS_VM_READ_OPERATION, false, (uint)pid);
        if (hProcess == IntPtr.Zero) return "HandleAccessDenied";

        try {
            byte[] buffer = new byte[size];
            if (ReadProcessMemory(hProcess, (IntPtr)address, buffer, (UIntPtr)size, out UIntPtr bytesRead)) {
                yaraResult = EvaluatePayloadInMemory(buffer, procName);

                // Only write to disk if it actually matches a YARA rule to save I/O overhead
                if (yaraResult != "NoSignatureMatch") {
                    string quarantineDir = @"C:\ProgramData\DeepSensor\Data\Quarantine";
                    System.IO.Directory.CreateDirectory(quarantineDir);
                    string dumpPath = $@"{quarantineDir}\Payload_{procName}_{pid}_0x{address:X}.bin";
                    System.IO.File.WriteAllBytes(dumpPath, buffer);
                }
            }

            uint PAGE_NOACCESS = 0x01;
            VirtualProtectEx(hProcess, (IntPtr)address, (UIntPtr)size, PAGE_NOACCESS, out uint oldProtect);
        } catch { return "ForensicError"; } finally { CloseHandle(hProcess); }
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

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint ResumeThread(IntPtr hThread);

    // ROLLBACK MECHANISM
    public static bool ResumeNativeThread(int tid) {
        uint THREAD_SUSPEND_RESUME = 0x0002;
        IntPtr hThread = OpenThread(THREAD_SUSPEND_RESUME, false, (uint)tid);
        if (hThread == IntPtr.Zero) return false;
        uint resumeCount = ResumeThread(hThread);
        CloseHandle(hThread);

        // If resumeCount is > 0, it successfully decremented the suspension count
        return (resumeCount != 0xFFFFFFFF);
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
    private static HashSet<string> BenignADSProcesses       = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    private static HashSet<string> TiDrivers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    // =====================================================================
    // ZERO-ALLOCATION FLAT ARRAYS (Replaces Aho-Corasick)
    // =====================================================================
    public class RuleMatrix {
        public SigmaRule[] ProcRules = Array.Empty<SigmaRule>();
        public SigmaRule[] ImgRules  = Array.Empty<SigmaRule>();
        public SigmaRule[] FileRules = Array.Empty<SigmaRule>();
        public SigmaRule[] RegRules  = Array.Empty<SigmaRule>();
    }

    private static RuleMatrix _activeMatrix = new RuleMatrix();

    public static void UpdateSigmaRules(string b64Rules) {
        try {
            var matrix = new RuleMatrix();
            if (string.IsNullOrEmpty(b64Rules)) return;

            byte[] data = Convert.FromBase64String(b64Rules);
            string payload = System.Text.Encoding.UTF8.GetString(data);

            if (string.IsNullOrEmpty(payload)) return;

            string[] rules = payload.Split(new string[] { "[NEXT]" }, StringSplitOptions.RemoveEmptyEntries);

            var procList = new List<SigmaRule>();
            var imgList = new List<SigmaRule>();
            var fileList = new List<SigmaRule>();
            var regList = new List<SigmaRule>();

            foreach (string r in rules) {
                string[] parts = r.Split('|');
                if (parts.Length < 3) continue;

                string category = parts[0];
                string id = parts[1];
                string anchor = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(parts[2]));

                var rule = new SigmaRule { id = id, category = category, anchor_string = anchor.ToLowerInvariant() };

                switch (category.ToLowerInvariant()) {
                    case "process_creation": procList.Add(rule); break;
                    case "image_load": imgList.Add(rule); break;
                    case "file_event": fileList.Add(rule); break;
                    case "registry_event":
                    case "registry_set": regList.Add(rule); break;
                }
            }

            // Lock into highly-optimized flat arrays
            matrix.ProcRules = procList.ToArray();
            matrix.ImgRules = imgList.ToArray();
            matrix.FileRules = fileList.ToArray();
            matrix.RegRules = regList.ToArray();

            Interlocked.Exchange(ref _activeMatrix, matrix);
            EnqueueDiag("[OS SENSOR] Flat Rule Matrix Compiled: " + (matrix.ProcRules.Length + matrix.ImgRules.Length + matrix.FileRules.Length + matrix.RegRules.Length) + " zero-allocation signatures.");
        }
        catch (Exception ex) {
            EnqueueDiag($"[OS SENSOR] Rule Compilation Failed - {ex.Message}");
        }
    }

    [ThreadStatic]
    private static StringBuilder _jsonSb;

    private static string JsonEscape(string text) {
        if (string.IsNullOrEmpty(text)) return "";
        if (_jsonSb == null) _jsonSb = new StringBuilder(text.Length * 2);
        _jsonSb.Clear();

        foreach (char c in text) {
            switch (c) {
                case '"':  _jsonSb.Append("\\\""); break;
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

    private static string BuildEnrichedJson(
        string category, string eventType, string process, string parentProcess,
        int pid, int parentPid, int tid, string cmdline, string details,
        string path = "", string extraType = "")
    {
        string procLower = process.ToLowerInvariant();
        string parentLower = parentProcess.ToLowerInvariant();
        string eventUser = GetEventUser(pid);

        string lineageKey = $"{parentProcess}|{process}";
        if (BenignLineages.ContainsKey(lineageKey)) return null;

        if (BenignADSProcesses.Contains(procLower) || BenignADSProcesses.Contains(parentLower)) return null;

        if ((procLower == "pwsh.exe" || procLower == "powershell.exe") &&
            (parentLower.Contains("code") || parentLower.Contains("devenv") || parentLower.Contains("msedge") || parentLower.Contains("explorer"))) return null;

        if (procLower.Contains("visualstudio.code") &&
            (cmdline.IndexOf("/telemetrysession:", StringComparison.OrdinalIgnoreCase) >= 0 ||
            cmdline.IndexOf("dotnet.projectsystem", StringComparison.OrdinalIgnoreCase) >= 0)) return null;

        if (procLower == "vssadmin.exe" && cmdline.IndexOf("list shadows", StringComparison.OrdinalIgnoreCase) >= 0 &&
            parentLower == "wbengine.exe") return null;

        string json = $@"{{
            ""Category"":""{category}"",
            ""Type"":""{eventType}"",
            ""Process"":""{JsonEscape(process)}"",
            ""Parent"":""{JsonEscape(parentProcess)}"",
            ""PID"":{pid},
            ""ParentPID"":{parentPid},
            ""TID"":{tid},
            ""Cmd"":""{JsonEscape(cmdline)}"",
            ""Details"":""{JsonEscape(details)}"",
            ""Path"":""{JsonEscape(path)}"",
            ""ComputerName"":""{JsonEscape(HostComputerName)}"",
            ""IP"":""{JsonEscape(HostIP)}"",
            ""OS"":""{JsonEscape(HostOS)}"",
            ""SensorUser"":""{JsonEscape(SensorUser)}"",
            ""EventUser"":""{JsonEscape(eventUser)}"",
            ""Destination"":"""",
            ""Port"":0
        }}".Replace("\r", "").Replace("\n", "");

        return json;
    }

    // Enables dynamic loading of the Native Rust DLL by PowerShell
    public static void SetLibraryPath(string path) { SetDllDirectory(path); }

    private static string _dllPath;

    public static void Initialize(string dllPath, int currentPid, string[] tiDrivers, string[] benignExplorerValues, string[] benignADSProcs) {
        _dllPath = dllPath;
        SensorPid = currentPid;
        HostComputerName = Environment.MachineName;
        HostIP           = "0.0.0.0";           // fallback instead of "unknown"
        HostOS           = "Windows";
        SensorUser       = Environment.UserDomainName + "\\" + Environment.UserName;

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

        Task.Run(async () => {
            while (true) {
                try {
                    await Task.Delay(300_000);

                    var cutoff = DateTime.UtcNow.AddHours(-24);
                    var keysToRemove = new List<int>();

                    foreach (var kvp in ProcessStartTime.ToArray()) {
                        if (kvp.Value < cutoff || ProcessStartTime.Count > 10000)
                            keysToRemove.Add(kvp.Key);
                    }

                    foreach (var pid in keysToRemove) {
                        ProcessCache.TryRemove(pid, out _);
                        ProcessStartTime.TryRemove(pid, out _);
                        ProcessModules.TryRemove(pid, out _);
                    }
                }
                catch { /* Never crash the sensor */ }
            }
        });

        AppDomain.CurrentDomain.AssemblyResolve += (sender, args) => {
            string folderPath = System.IO.Path.GetDirectoryName(_dllPath);
            string assemblyName = new System.Reflection.AssemblyName(args.Name).Name;
            string targetPath = System.IO.Path.Combine(folderPath, assemblyName + ".dll");
            if (System.IO.File.Exists(targetPath)) return System.Reflection.Assembly.LoadFrom(targetPath);
            return null;
        };

        UpdateThreatIntel(tiDrivers);

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

    public static void UpdateThreatIntel(string[] tiDrivers) {
        var newTi = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string driver in tiDrivers) { newTi.Add(driver); }
        TiDrivers = newTi;
    }

    public static void StartSession() {
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

                            string dynamicPayload = sb.ToString().Trim();
                            if (dynamicPayload.Length > 5) {
                                var matrix = _activeMatrix;
                                SigmaRule matchedRule = null;

                                // Zero-Allocation SIMD String Array Search
                                for (int i = 0; i < matrix.ProcRules.Length; i++) {
                                    if (dynamicPayload.IndexOf(matrix.ProcRules[i].anchor_string, StringComparison.OrdinalIgnoreCase) >= 0) {
                                        matchedRule = matrix.ProcRules[i];
                                        break;
                                    }
                                }

                                if (matchedRule != null) {
                                    string procName = GetProcessName(data.ProcessID);
                                    if (string.IsNullOrWhiteSpace(procName) || procName == "0" || procName == "-1") {
                                        procName = data.ProviderName.Contains("WMI") ? "WMI_Activity" : "PowerShell_Host";
                                    }

                                    string cacheRuleName = matchedRule.id;
                                    int bracketIdx = cacheRuleName.IndexOf('[');
                                    if (bracketIdx >= 0) cacheRuleName = cacheRuleName.Substring(0, bracketIdx).Trim();

                                    string cacheKey = $"{procName}|{cacheRuleName}";

                                    if (!SuppressedSigmaRules.ContainsKey(cacheRuleName) && !SuppressedProcessRules.ContainsKey(cacheKey)) {
                                        EnqueueAlert("Sigma_UserMode", "AdvancedDetection", procName, "Unknown", data.ProcessID, 0, data.ThreadID, dynamicPayload, $"Rule: {matchedRule.id}");
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
        _lastEventsLost = 0;
        EnqueueDiag($"TraceEventSession bound: {sessionName}");

        var kernelKeywords = KernelTraceEventParser.Keywords.Process | KernelTraceEventParser.Keywords.Registry |
            KernelTraceEventParser.Keywords.FileIOInit | KernelTraceEventParser.Keywords.FileIO |
            KernelTraceEventParser.Keywords.ImageLoad | KernelTraceEventParser.Keywords.Memory;

        _session.EnableKernelProvider(kernelKeywords);

        _session.Source.Kernel.ImageLoad += delegate (ImageLoadTraceData data) {
            if (data.ProcessID == SensorPid || data.ProcessID == 0) return;
            var map = new ModuleMap { ModuleName = data.FileName, BaseAddress = (ulong)data.ImageBase, EndAddress = (ulong)data.ImageBase + (ulong)data.ImageSize };

            // Atomically replace with a sorted array for binary searching
            ProcessModules.AddOrUpdate(data.ProcessID,
                pid => new ModuleMap[] { map },
                (pid, arr) => {
                    var list = new List<ModuleMap>(arr);
                    int index = list.BinarySearch(map);
                    if (index < 0) list.Insert(~index, map);
                    return list.ToArray();
                });

            if (data.FileName.IndexOf(".sys", StringComparison.OrdinalIgnoreCase) >= 0 && data.ProcessID != 4) {
                if (TiDrivers.Contains(System.IO.Path.GetFileName(data.FileName))) {
                    EnqueueAlert("T1562.001", "ThreatIntel_Driver", GetProcessName(data.ProcessID), "Unknown", data.ProcessID, 0, data.ThreadID, "", $"Known vulnerable driver loaded: {data.FileName}");
                }
            }

            var matrix = _activeMatrix;
            SigmaRule matchedRule = null;

            // Zero-Allocation Search
            for (int i = 0; i < matrix.ImgRules.Length; i++) {
                if (data.FileName.IndexOf(matrix.ImgRules[i].anchor_string, StringComparison.OrdinalIgnoreCase) >= 0) {
                    matchedRule = matrix.ImgRules[i];
                    break;
                }
            }

            if (matchedRule != null) {
                string cacheRuleName = matchedRule.id;
                int bracketIdx = cacheRuleName.IndexOf('[');
                if (bracketIdx >= 0) cacheRuleName = cacheRuleName.Substring(0, bracketIdx).Trim();

                string cacheKey = $"{GetProcessName(data.ProcessID)}|{cacheRuleName}";

                if (!SuppressedSigmaRules.ContainsKey(cacheRuleName) && !SuppressedProcessRules.ContainsKey(cacheKey)) {
                    EnqueueAlert("Sigma_Match", "ImageLoadDetection", GetProcessName(data.ProcessID), "Unknown", data.ProcessID, 0, data.ThreadID, data.FileName, $"Rule: {matchedRule.id}");
                }
            }
        };

        _session.Source.Kernel.StackWalkStack += delegate (StackWalkStackTraceData data) {
            if (!ProcessModules.TryGetValue(data.ProcessID, out var modules)) return;
            int unbackedFrames = 0, forgedReturns = 0;

            for (int i = 0; i < data.FrameCount; i++) {
                ulong instructionPointer = data.InstructionPointer(i);
                bool isBacked = false;

                // O(log N) Binary Search across the lock-free array
                int left = 0, right = modules.Length - 1;
                while (left <= right) {
                    int mid = left + (right - left) / 2;
                    if (instructionPointer >= modules[mid].BaseAddress && instructionPointer <= modules[mid].EndAddress) {
                        isBacked = true;
                        break;
                    }
                    if (instructionPointer < modules[mid].BaseAddress) right = mid - 1;
                    else left = mid + 1;
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
                string image = data.ImageFileName ?? "";
                ProcessCache[data.ProcessID] = image;
                ProcessStartTime[data.ProcessID] = DateTime.UtcNow;

                if (data.ProcessID == SensorPid || data.ParentID == SensorPid) return;

                string cmd = data.CommandLine ?? "";
                if (cmd.IndexOf("logman", StringComparison.OrdinalIgnoreCase) >= 0 && cmd.IndexOf("stop", StringComparison.OrdinalIgnoreCase) >= 0) {
                    EnqueueAlert("T1562.002", "ETWTampering", image, GetProcessName(data.ParentID), data.ProcessID, data.ParentID, data.ThreadID, cmd, $"Attempted to terminate ETW: {cmd}");
                }

                var matrix = _activeMatrix;
                SigmaRule matchedRule = null;

                // Zero-Allocation Search
                for (int i = 0; i < matrix.ProcRules.Length; i++) {
                    if (cmd.IndexOf(matrix.ProcRules[i].anchor_string, StringComparison.OrdinalIgnoreCase) >= 0) {
                        matchedRule = matrix.ProcRules[i];
                        break;
                    }
                }

                if (matchedRule != null) {
                    string cacheRuleName = matchedRule.id;
                    int bracketIdx = cacheRuleName.IndexOf('[');
                    if (bracketIdx >= 0) cacheRuleName = cacheRuleName.Substring(0, bracketIdx).Trim();
                    string cacheKey = $"{image}|{cacheRuleName}";

                    if (!SuppressedSigmaRules.ContainsKey(cacheRuleName) && !SuppressedProcessRules.ContainsKey(cacheKey)) {
                        EnqueueAlert("Sigma_Match", "SigmaDetection", image, GetProcessName(data.ParentID), data.ProcessID, data.ParentID, data.ThreadID, cmd, $"Rule: {matchedRule.id}");
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

            // Zero-allocation procName extraction
            string procName = GetProcessName(data.ProcessID);

            if (procName.IndexOf("trustedinstaller", StringComparison.OrdinalIgnoreCase) >= 0 || procName.IndexOf("svchost", StringComparison.OrdinalIgnoreCase) >= 0) {
                EnqueueRaw("RegistryWrite", procName, "", keyName, valueName, data.ProcessID, data.ThreadID); return;
            }
            if (procName.IndexOf("explorer", StringComparison.OrdinalIgnoreCase) >= 0 && BenignExplorerValueNames.Contains(valueName)) {
                EnqueueRaw("RegistryWrite", procName, "", keyName, valueName, data.ProcessID, data.ThreadID); return;
            }

            string searchText = keyName + "\\" + valueName;
            bool isPersistence = false;
            foreach (string monitored in MonitoredRegPaths) {
                if (searchText.IndexOf(monitored, StringComparison.OrdinalIgnoreCase) >= 0) { isPersistence = true; break; }
            }

            if (isPersistence) {
                EnqueueAlert("T1547.001", "RegPersistence", procName, "Unknown", data.ProcessID, 0, data.ThreadID, "", $"Persistence Key: {keyName}");
            }

            var matrix = _activeMatrix;
            SigmaRule matchedRule = null;

            // Zero-Allocation Search
            for (int i = 0; i < matrix.RegRules.Length; i++) {
                if (searchText.IndexOf(matrix.RegRules[i].anchor_string, StringComparison.OrdinalIgnoreCase) >= 0) {
                    matchedRule = matrix.RegRules[i];
                    break;
                }
            }

            if (matchedRule != null) {
                string cacheRuleName = matchedRule.id;
                int bracketIdx = cacheRuleName.IndexOf('[');
                if (bracketIdx >= 0) cacheRuleName = cacheRuleName.Substring(0, bracketIdx).Trim();
                string cacheKey = $"{procName}|{cacheRuleName}";

                if (!SuppressedSigmaRules.ContainsKey(cacheRuleName) && !SuppressedProcessRules.ContainsKey(cacheKey)) {
                    EnqueueAlert("Sigma_Match", "RegistryDetection", procName, "Unknown", data.ProcessID, 0, data.ThreadID, searchText, $"Rule: {matchedRule.id}");
                }
            }

            EnqueueRaw("RegistryWrite", procName, "", keyName, valueName, data.ProcessID, data.ThreadID);
        };

        _session.Source.Kernel.FileIOCreate += delegate (FileIOCreateTraceData data) {
            string fileName = data.FileName ?? "";

            if (fileName.IndexOf("deepsensor_canary.tmp", StringComparison.OrdinalIgnoreCase) >= 0) {
                SafeEnqueueEvent("{\"Provider\":\"HealthCheck\", \"EventName\":\"ETW_HEARTBEAT\"}");
                return;
            }

            if (fileName.IndexOf(@"\Device\NamedPipe\", StringComparison.OrdinalIgnoreCase) >= 0) {
                string[] pipeParts = fileName.Split(new[] { @"\NamedPipe\" }, StringSplitOptions.None);
                string pipeName = pipeParts.Length > 0 ? pipeParts[pipeParts.Length - 1] : "";

                if (ShannonEntropy(pipeName) > 3.5 || pipeName.IndexOf("mojo.", StringComparison.OrdinalIgnoreCase) >= 0) {
                    EnqueueAlert("T1021.002", "SuspiciousNamedPipe", GetProcessName(data.ProcessID), "Unknown", data.ProcessID, 0, data.ThreadID, "", $"Pipe: {pipeName}");
                }
            }

            var matrix = _activeMatrix;
            SigmaRule matchedRule = null;

            // Zero-Allocation Search
            for (int i = 0; i < matrix.FileRules.Length; i++) {
                if (fileName.IndexOf(matrix.FileRules[i].anchor_string, StringComparison.OrdinalIgnoreCase) >= 0) {
                    matchedRule = matrix.FileRules[i];
                    break;
                }
            }

            if (matchedRule != null) {
                string cacheRuleName = matchedRule.id;
                int bracketIdx = cacheRuleName.IndexOf('[');
                if (bracketIdx >= 0) cacheRuleName = cacheRuleName.Substring(0, bracketIdx).Trim();
                string procName = GetProcessName(data.ProcessID);
                string cacheKey = $"{procName}|{cacheRuleName}";

                if (!SuppressedSigmaRules.ContainsKey(cacheRuleName) && !SuppressedProcessRules.ContainsKey(cacheKey)) {
                    EnqueueAlert("Sigma_Match", "FileDropDetection", procName, "Unknown", data.ProcessID, 0, data.ThreadID, fileName, $"Rule: {matchedRule.id}");
                }
            }

            EnqueueRaw("FileIOCreate", GetProcessName(data.ProcessID), "", fileName, "", data.ProcessID, data.ThreadID);
        };

        _session.Source.Kernel.FileIOWrite += delegate (FileIOReadWriteTraceData data) {
            if (data.ProcessID == SensorPid) return;
            EnqueueRaw("FileIOWrite", GetProcessName(data.ProcessID), "", data.FileName, "", data.ProcessID, data.ThreadID);
        };

        _session.Source.Kernel.VirtualMemAlloc += delegate (VirtualAllocTraceData data) {
            int flags = (int)data.Flags;
            // Catch BOTH 0x40 (PAGE_EXECUTE_READWRITE) and 0x20 (PAGE_EXECUTE_READ)
            // This captures the exact moment RW memory is transitioned to RX for execution
            if (flags == 0x40 || flags == 0x20) {

                // Do not scan our own memory allocations
                if (data.ProcessID != SensorPid && data.ProcessID != 0) {
                    ulong baseAddr = Convert.ToUInt64(data.PayloadByName("BaseAddress"));
                    ulong regSize  = Convert.ToUInt64(data.PayloadByName("RegionSize"));

                    // 1. Dump the specific RWX shellcode to disk
                    // 2. Scan it with the Context-Aware YARA matrices
                    // 3. Strip the memory of executable permissions (PAGE_NOACCESS)
                    string yaraResult = NeuterAndDumpPayload(data.ProcessID, baseAddr, regSize);

                    if (yaraResult != "NoSignatureMatch" && yaraResult != "HandleAccessDenied") {
                        // We got a YARA hit! Quarantine the thread that injected it.
                        bool neutralized = QuarantineNativeThread(data.ThreadID, data.ProcessID);
                        EnqueueAlert("T1055", "YaraPayloadAttribution", GetProcessName(data.ProcessID), "Unknown", data.ProcessID, 0, data.ThreadID, "", $"YARA Hit: {yaraResult} | Thread Frozen: {neutralized}");
                    }
                }
            }
        };

        // Telemetry Blinding - Background Watchdog for ETW Buffer Exhaustion
        Task.Run(async () => {
            while (IsSessionHealthy()) {
                await Task.Delay(2000); // Check every 2 seconds
                if (_session != null && _session.EventsLost > _lastEventsLost) {
                    int dropped = _session.EventsLost - _lastEventsLost;
                    _lastEventsLost = _session.EventsLost;

                    EventQueue.Enqueue($"{{\"Provider\":\"DiagLog\", \"Message\":\"SENSOR_BLINDING_DETECTED:{dropped}\"}}");
                }
            }
        });

        _session.Source.Process();
    }

    // Watchdog state
    private static int _lastEventsLost = 0;

    public static bool IsSessionHealthy() {
        if (_session == null) return false;
        try { return _session.Source != null; } catch { return false; }
    }

    public static void StopSession() {
        if (_session != null) {
            _session.Stop();
            _session.Dispose();
            _session = null;
        }

        string umSessionName = "DeepSensor_UserMode";
        if (TraceEventSession.GetActiveSessionNames().Contains(umSessionName)) {
            using (var old = new TraceEventSession(umSessionName)) { old.Stop(true); }
        }
    }

    public static void TeardownEngine() {
        _mlWorkQueue.CompleteAdding();
        _mlCancelSource.Cancel();

        if (_mlConsumerTask != null) { _mlConsumerTask.Wait(2000); }

        if (_mlEnginePtr != IntPtr.Zero) {
            teardown_engine(_mlEnginePtr);
            _mlEnginePtr = IntPtr.Zero;
            EnqueueDiag("[ML ENGINE] Native Rust DLL safely unloaded and DB flushed.");
        }

        foreach (var rules in YaraMatrices.Values) {
            try { rules.Dispose(); } catch {}
        }
        YaraMatrices.Clear();
        if (_yaraContext != null) { _yaraContext.Dispose(); _yaraContext = null; }
    }

    private static string GetProcessName(int pid) {
        return ProcessCache.ContainsKey(pid) ? ProcessCache[pid] : pid.ToString();
    }

    private static string GetEventUser(int pid) {
        if (ProcessUserCache.TryGetValue(pid, out string user)) return user;

        try
        {
            using (var p = System.Diagnostics.Process.GetProcessById(pid))
            {
                user = p.StartInfo.UserName ?? "UNKNOWN";
                // Better resolution for domain users / SYSTEM
                if (string.IsNullOrWhiteSpace(user) || user == "UNKNOWN")
                    user = "NT AUTHORITY\\SYSTEM"; // fallback for service/background
            }
        }
        catch
        {
            user = "UNKNOWN";
        }

        ProcessUserCache.TryAdd(pid, user);
        return user;
    }

    // EnqueueAlert with Fingerprinting + Full Config Exclusions
    public static void EnqueueAlert(string category, string eventType, string process, string parentProcess, int pid, int parentPid, int tid, string cmdline, string details) {
        Interlocked.Increment(ref TotalAlertsGenerated);
        if (_mlEnginePtr == IntPtr.Zero) return;

        string jsonEvent = BuildEnrichedJson(category, eventType, process, parentProcess, pid, parentPid, tid, cmdline, details);
        if (jsonEvent == null) return;   // dropped by exclusion

        try {
            if (!_mlWorkQueue.IsAddingCompleted) _mlWorkQueue.Add(jsonEvent);
        } catch (InvalidOperationException) { }
    }

    private static void EnqueueRaw(string type, string process, string parent, string path, string cmd, int pid, int tid) {
        Interlocked.Increment(ref TotalEventsParsed);
        if (_mlEnginePtr == IntPtr.Zero) return;

        string jsonEvent = BuildEnrichedJson("RawEvent", type, process, parent, pid, 0, tid, cmd, "", path, type);
        if (jsonEvent == null) return;

        try {
            if (!_mlWorkQueue.IsAddingCompleted) _mlWorkQueue.Add(jsonEvent);
        } catch (InvalidOperationException) { }
    }
}