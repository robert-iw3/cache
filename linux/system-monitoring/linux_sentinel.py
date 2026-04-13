import argparse
import json
import logging
import os
import shutil
import subprocess
import time
import hashlib
import signal
import sys
import re
import threading
import concurrent.futures
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from socketserver import ThreadingMixIn
from datetime import datetime, timedelta

# Configuration
VERSION = "2.3"
BASE_DIR = Path(__file__).parent.resolve()
CONFIG_FILE = BASE_DIR / "sentinel.conf"
LOG_DIR = Path("/var/log/linux-sentinel") if os.geteuid() == 0 else Path.home() / ".linux-sentinel/logs"
BACKUP_DIR = Path("/var/backups/linux-sentinel") if os.geteuid() == 0 else Path.home() / ".linux-sentinel/backups"
BASELINE_DIR = LOG_DIR / "baseline"
ALERTS_DIR = LOG_DIR / "alerts"
QUARANTINE_DIR = LOG_DIR / "quarantine"
JSON_OUTPUT_FILE = LOG_DIR / "latest_scan.json"
THREAT_INTEL_DIR = LOG_DIR / "threat_intel"
YARA_RULES_DIR = LOG_DIR / "yara_rules"
HONEYPOT_LOG = LOG_DIR / "honeypot.log"
EBPF_LOG = LOG_DIR / "ebpf_events.log"
LOCK_FILE = Path(f"/tmp/linux-sentinel-{os.getlogin()}.lock")
PID_FILE = Path(f"/tmp/linux-sentinel-{os.getlogin()}.pid")
HONEYPOT_PORTS = [2222, 8080, 23, 21, 3389]
API_PORT = int(os.environ.get("DASHBOARD_PORT", 8080))
THREAT_INTEL_UPDATE_HOURS = 6
MAX_FIND_DEPTH = 2
SCAN_TIMEOUT = 180
PARALLEL_JOBS = 2

# Alert levels
CRITICAL = 1
HIGH = 2
MEDIUM = 3
LOW = 4

# Environment flags
IS_CONTAINER = False
IS_VM = False
IS_DEBIAN = False
IS_FEDORA = False
IS_NIXOS = False
HAS_JQ = shutil.which("jq") is not None
HAS_INOTIFY = shutil.which("inotifywait") is not None
HAS_YARA = shutil.which("yara") is not None
HAS_BCC = shutil.which("bpftrace") is not None or Path("/usr/share/bcc/tools").exists()
HAS_NETCAT = shutil.which("nc") is not None or shutil.which("netcat") is not None
NETCAT_BIN = "nc" if shutil.which("nc") else "netcat"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "sentinel.log"),
        logging.StreamHandler()
    ],
    datefmt="%Y-%m-%dT%H:%M:%SZ"
)
logger = logging.getLogger(__name__)

def validate_path(path: Path) -> Path:
    """Validate and resolve a file path."""
    path = path.resolve()
    if ".." in str(path):
        logger.error(f"Invalid path: {path}")
        exit(1)
    return path

def acquire_lock():
    """Acquire an exclusive lock with stale lock detection."""
    if LOCK_FILE.exists():
        try:
            with open(PID_FILE, "r") as f:
                lock_pid = f.read().strip()
            if lock_pid and os.path.exists(f"/proc/{lock_pid}"):
                logger.error(f"Another instance is running (PID: {lock_pid})")
                exit(1)
            else:
                LOCK_FILE.unlink(missing_ok=True)
                PID_FILE.unlink(missing_ok=True)
        except Exception:
            LOCK_FILE.unlink(missing_ok=True)
            PID_FILE.unlink(missing_ok=True)

    try:
        with open(LOCK_FILE, "x"):
            os.write(PID_FILE, str(os.getpid()))
    except FileExistsError:
        logger.error("Failed to acquire lock. Another instance may be running.")
        exit(1)

def cleanup():
    """Clean up resources on exit."""
    stop_honeypots()
    stop_ebpf_monitoring()
    stop_api_server()
    LOCK_FILE.unlink(missing_ok=True)
    PID_FILE.unlink(missing_ok=True)

def detect_environment():
    """Detect container, VM, and OS type."""
    global IS_CONTAINER, IS_VM, IS_DEBIAN, IS_FEDORA, IS_NIXOS
    # Container detection
    if Path("/.dockerenv").exists() or Path("/run/.containerenv").exists() or "docker" in Path("/proc/1/cgroup").read_text():
        IS_CONTAINER = True
    # VM detection
    if shutil.which("systemd-detect-virt") and subprocess.run(["systemd-detect-virt"], capture_output=True).returncode == 0:
        IS_VM = True
    elif shutil.which("dmidecode") and os.geteuid() == 0:
        try:
            vendor = subprocess.run(["dmidecode", "-s", "system-product-name"], capture_output=True, text=True).stdout.lower()
            if any(vm in vendor for vm in ["vmware", "virtualbox", "qemu", "kvm", "xen"]):
                IS_VM = True
        except subprocess.CalledProcessError:
            pass
    # OS detection
    os_release = Path("/etc/os-release").read_text().lower()
    IS_DEBIAN = "debian" in os_release
    IS_FEDORA = "fedora" in os_release
    IS_NIXOS = "nixos" in os_release

def init_json_output():
    """Initialize JSON output file."""
    json_data = {
        "version": VERSION,
        "scan_start": "",
        "scan_end": "",
        "hostname": "",
        "environment": {
            "is_container": IS_CONTAINER,
            "is_vm": IS_VM,
            "user": os.getlogin(),
            "has_jq": HAS_JQ,
            "has_inotify": HAS_INOTIFY,
            "has_yara": HAS_YARA,
            "has_bcc": HAS_BCC,
            "has_netcat": HAS_NETCAT
        },
        "summary": {
            "total_alerts": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        },
        "alerts": [],
        "performance": {
            "scan_duration": 0,
            "modules_run": []
        },
        "integrity": {
            "script_hash": "",
            "baseline_age": 0
        },
        "features": {
            "ebpf_monitoring": False,
            "honeypots": False,
            "yara_scanning": False,
            "api_server": False
        }
    }
    with open(JSON_OUTPUT_FILE, "w") as f:
        json.dump(json_data, f, indent=2)

def load_config():
    """Load configuration with defaults."""
    config = {
        "MONITOR_NETWORK": True,
        "MONITOR_PROCESSES": True,
        "MONITOR_FILES": True,
        "MONITOR_USERS": True,
        "MONITOR_ROOTKITS": True,
        "MONITOR_MEMORY": True,
        "ENABLE_ANTI_EVASION": True,
        "ENABLE_EBPF": True,
        "ENABLE_HONEYPOTS": True,
        "ENABLE_API_SERVER": True,
        "ENABLE_YARA": True,
        "SEND_EMAIL": False,
        "EMAIL_RECIPIENT": "",
        "WEBHOOK_URL": "",
        "SLACK_WEBHOOK_URL": "",
        "ABUSEIPDB_API_KEY": "",
        "VIRUSTOTAL_API_KEY": "",
        "SYSLOG_ENABLED": True,
        "PERFORMANCE_MODE": False,
        "ENABLE_THREAT_INTEL": True,
        "WHITELIST_PROCESSES": [
            "firefox", "chrome", "nmap", "masscan", "nuclei", "gobuster", "ffuf",
            "subfinder", "httpx", "amass", "burpsuite", "wireshark", "metasploit",
            "sqlmap", "nikto", "dirb", "wpscan", "john", "docker", "containerd",
            "systemd", "kthreadd", "bash", "zsh", "ssh", "python3", "yara"
        ],
        "WHITELIST_CONNECTIONS": [
            "127.0.0.1", "::1", "0.0.0.0", "8.8.8.8", "1.1.1.1", "208.67.222.222",
            "1.0.0.1", "9.9.9.9"
        ],
        "EXCLUDE_PATHS": [
            "/opt/metasploit-framework", "/usr/share/metasploit-framework",
            "/usr/share/wordlists", "/home/*/go/bin", "/tmp/nuclei-templates",
            "/var/lib/docker", "/var/lib/containerd", "/snap"
        ],
        "CRITICAL_PATHS": [
            "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config",
            "/etc/hosts"
        ]
    }
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r") as f:
                for line in f:
                    if line.strip() and not line.startswith("#"):
                        key, value = line.strip().split("=", 1)
                        key = key.strip()
                        value = value.strip().strip('"').strip("'")
                        if key in config:
                            if isinstance(config[key], bool):
                                config[key] = value.lower() == "true"
                            elif isinstance(config[key], list):
                                config[key] = [x.strip() for x in value.split(",")]
                            else:
                                config[key] = value
            logger.info(f"Configuration loaded from {CONFIG_FILE}")
        except Exception as e:
            logger.warning(f"Config file error: {e}, using defaults")
    return config

def log_alert(level: int, message: str):
    """Log an alert with specified severity."""
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    level_map = {CRITICAL: "CRITICAL", HIGH: "HIGH", MEDIUM: "MEDIUM", LOW: "LOW"}
    color_map = {CRITICAL: "\033[0;31m", HIGH: "\033[1;33m", MEDIUM: "\033[0;34m", LOW: "\033[0;32m"}
    print(f"{color_map.get(level, '')}[{level_map.get(level, 'UNKNOWN')}] {message}\033[0m")

    ALERTS_DIR.mkdir(parents=True, exist_ok=True)
    alert_file = ALERTS_DIR / f"{datetime.now().strftime('%Y%m%d')}.log"
    log_entry = f"[{timestamp}] [LEVEL:{level}] {message}"
    with open(alert_file, "a") as f:
        f.write(log_entry + "\n")
    with open(alert_file.with_suffix(".hash"), "a") as f:
        f.write(hashlib.sha256(log_entry.encode()).hexdigest() + "\n")

    with open(JSON_OUTPUT_FILE, "r") as f:
        json_data = json.load(f)
    json_data["alerts"].append({"level": level_map.get(level, "UNKNOWN").lower(), "message": message, "timestamp": timestamp})
    json_data["summary"]["total_alerts"] += 1
    json_data["summary"][level_map.get(level, "UNKNOWN").lower()] += 1
    with open(JSON_OUTPUT_FILE, "w") as f:
        json.dump(json_data, f, indent=2)

    if config["SYSLOG_ENABLED"] and shutil.which("logger"):
        subprocess.run(["logger", "-t", f"linux-sentinel[{os.getpid()}]", "-p", "security.alert", message], check=False)

    if level == CRITICAL:
        send_critical_alert(message)

def send_critical_alert(message: str):
    """Send critical alerts via multiple channels."""
    timestamp = datetime.now().isoformat()
    hostname = subprocess.run(["hostname"], capture_output=True, text=True).stdout.strip()

    if config["SEND_EMAIL"] and config["EMAIL_RECIPIENT"]:
        if shutil.which("mail"):
            subprocess.run(["mail", "-s", "Linux Sentinel Alert", config["EMAIL_RECIPIENT"]], input=f"CRITICAL SECURITY ALERT: {message}", text=True, check=False)
        elif shutil.which("sendmail"):
            subprocess.run(["sendmail", config["EMAIL_RECIPIENT"]], input=f"Subject: Linux Sentinel Critical Alert\n\nCRITICAL SECURITY ALERT: {message}", text=True, check=False)

    if config["WEBHOOK_URL"] and shutil.which("curl"):
        payload = {"alert": "CRITICAL", "message": message, "timestamp": timestamp, "hostname": hostname}
        subprocess.run(["curl", "-s", "--max-time", "10", "-X", "POST", config["WEBHOOK_URL"], "-H", "Content-Type: application/json", "-d", json.dumps(payload)], check=False)

    if config["SLACK_WEBHOOK_URL"] and shutil.which("curl"):
        payload = {
            "attachments": [{
                "color": "danger",
                "title": "🚨 Linux Sentinel v2.3 Critical Alert",
                "text": message,
                "fields": [
                    {"title": "Hostname", "value": hostname, "short": True},
                    {"title": "Timestamp", "value": timestamp, "short": True}
                ],
                "footer": "Linux Sentinel v2.3",
                "ts": int(time.time())
            }]
        }
        subprocess.run(["curl", "-s", "--max-time", "10", "-X", "POST", config["SLACK_WEBHOOK_URL"], "-H", "Content-Type: application/json", "-d", json.dumps(payload)], check=False)

    if os.environ.get("DISPLAY"):
        if shutil.which("notify-send"):
            subprocess.run(["notify-send", "Linux Sentinel", f"CRITICAL: {message}", "--urgency=critical"], check=False)
        elif shutil.which("zenity"):
            subprocess.run(["zenity", "--error", "--text", f"Linux Sentinel CRITICAL: {message}"], check=False)

def init_yara_rules():
    """Initialize YARA rules for malware detection."""
    if not HAS_YARA:
        logger.info("YARA not available - skipping rule initialization")
        return

    YARA_RULES_DIR.mkdir(parents=True, exist_ok=True)

    malware_rule = YARA_RULES_DIR / "malware_detection.yar"
    with open(malware_rule, "w") as f:
        f.write("""
rule Suspicious_Base64_Payload {
    meta:
        description = "Detects suspicious base64 encoded payloads"
        severity = "high"
    strings:
        $b64_long = /[A-Za-z0-9+\\/]{100,}=/ fullword
        $eval = "eval"
        $exec = "exec"
        $decode = "base64"
    condition:
        $b64_long and ($eval or $exec or $decode)
}

rule Reverse_Shell_Patterns {
    meta:
        description = "Detects reverse shell command patterns"
        severity = "critical"
    strings:
        $nc_bind = /nc.*-l.*-p.*[0-9]+/
        $nc_connect = /nc.*[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+.*[0-9]+/
        $bash_tcp = "/dev/tcp/"
        $python_socket = "socket.socket(socket.AF_INET"
        $perl_socket = "IO::Socket::INET"
        $socat_reverse = /socat.*tcp.*exec/
        $mknod_backpipe = /mknod.*backpipe.*p/
    condition:
        any of them
}

rule Webshell_Indicators {
    meta:
        description = "Detects common webshell patterns"
        severity = "high"
    strings:
        $php_eval = /eval\\s*\\(\\s*\\$_((GET|POST|REQUEST)/
        $php_system = /system\\s*\\(\\s*\\$_((GET|POST|REQUEST)/
        $php_passthru = /passthru\\s*\\(\\s*\\$_((GET|POST|REQUEST)/
        $php_shell_exec = /shell_exec\\s*\\(\\s*\\$_((GET|POST|REQUEST)/
        $asp_eval = "eval(Request"
        $jsp_runtime = "Runtime.getRuntime().exec"
        $generic_backdoor = /\\$_((GET|POST)\\[.*\\]\\s*=.*/exec/
    condition:
        any of them
}

rule Crypto_Miner_Indicators {
    meta:
        description = "Detects cryptocurrency mining malware"
        severity = "high"
    strings:
        $stratum1 = "stratum+tcp://"
        $stratum2 = "stratum+ssl://"
        $xmrig = "xmrig"
        $cpuminer = "cpuminer"
        $pool1 = "pool.supportxmr.com"
        $pool2 = "xmr-usa-east1.nanopool.org"
        $wallet = /[49][A-Za-z0-9]{94}/
        $mining_algo = /cryptonight|scrypt|sha256|x11/
    condition:
        any of them
}

rule Process_Injection_Techniques {
    meta:
        description = "Detects process injection indicators"
        severity = "medium"
    strings:
        $ptrace = "ptrace"
        $proc_mem = "/proc/*/mem"
        $ld_preload = "LD_PRELOAD"
        $dlopen = "dlopen"
        $mmap_exec = "PROT_EXEC"
        $shellcode = { 31 c0 50 68 }
    condition:
        any of them
}

rule Persistence_Mechanisms {
    meta:
        description = "Detects persistence establishment attempts"
        severity = "medium"
    strings:
        $crontab = "crontab -e"
        $systemd_service = ".service"
        $bashrc = ".bashrc"
        $profile = ".profile"
        $ssh_keys = "authorized_keys"
        $startup = "/etc/init.d/"
        $rc_local = "/etc/rc.local"
    condition:
        any of them
}
""")

    apt_rule = YARA_RULES_DIR / "apt_indicators.yar"
    with open(apt_rule, "w") as f:
        f.write("""
rule APT_Lateral_Movement {
    meta:
        description = "Detects APT lateral movement tools"
        severity = "critical"
    strings:
        $psexec = "psexec"
        $wmic = "wmic process call create"
        $schtasks = "schtasks /create"
        $powershell_encoded = "powershell -enc"
        $mimikatz = "sekurlsa::logonpasswords"
        $bloodhound = "SharpHound"
        $cobalt_strike = "beacon"
    condition:
        any of them
}

rule Data_Exfiltration {
    meta:
        description = "Detects data exfiltration attempts"
        severity = "high"
    strings:
        $curl_upload = /curl.*-T.*http/
        $wget_post = /wget.*--post-file/
        $nc_file = /nc.*<.*\\/.*\\//
        $base64_pipe = /base64.*\\|.*curl/
        $tar_remote = /tar.*\\|.*nc/
        $scp_remote = /scp.*@/
    condition:
        any of them
}
""")
    logger.info("YARA rules initialized")

def start_ebpf_monitoring():
    """Start eBPF-based kernel monitoring."""
    if not HAS_BCC or os.geteuid() != 0:
        logger.info("eBPF monitoring requires root and BCC tools - skipping")
        return

    ebpf_script = LOG_DIR / "linux_sentinel_execsnoop.py"
    with open(ebpf_script, "w") as f:
        f.write("""
import sys
import time
from bcc import BPF

bpf_text = '''
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

struct data_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char filename[256];
};

BPF_PERF_OUTPUT(events);

int syscall__execve(struct pt_regs *ctx, const char __user *filename,
                    const char __user *const __user *argv,
                    const char __user *const __user *envp)
{
    struct data_t data = {};
    struct task_struct *task;

    data.pid = bpf_get_current_pid_tgid() >> 32;
    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
'''

def print_event(cpu, data, size):
    event = b['events'].event(data)
    suspicious_patterns = [
        b'nc', b'netcat', b'socat', b'/dev/tcp', b'python -c', b'perl -e',
        b'bash -i', b'sh -i', b'wget', b'curl', b'base64'
    ]

    filename = event.filename.decode('utf-8', 'replace')
    comm = event.comm.decode('utf-8', 'replace')

    for pattern in suspicious_patterns:
        if pattern in filename.encode() or pattern in comm.encode():
            with open('{EBPF_LOG}', 'a') as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} SUSPICIOUS_EXEC: PID={event.pid} PPID={event.ppid} COMM={comm} FILE={filename}\\n")
            break

b = BPF(text=bpf_text)
execve_fnname = b.get_syscall_fnname('execve')
b.attach_kprobe(event=execve_fnname, fn_name='syscall__execve')
b['events'].open_perf_buffer(print_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        sys.exit(0)
""".format(EBPF_LOG=EBPF_LOG))

    proc = subprocess.Popen(["python3", str(ebpf_script)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    with open(LOG_DIR / "ebpf_monitor.pid", "w") as f:
        f.write(str(proc.pid))
    logger.info("eBPF process monitoring started")

def stop_ebpf_monitoring():
    """Stop eBPF monitoring."""
    pid_file = LOG_DIR / "ebpf_monitor.pid"
    if pid_file.exists():
        with open(pid_file, "r") as f:
            pid = f.read().strip()
        if pid and os.path.exists(f"/proc/{pid}"):
            os.kill(int(pid), signal.SIGTERM)
        pid_file.unlink(missing_ok=True)
    (LOG_DIR / "linux_sentinel_execsnoop.py").unlink(missing_ok=True)

def start_honeypots():
    """Start honeypot listeners on specified ports."""
    if not HAS_NETCAT:
        logger.info("Netcat not available - honeypots disabled")
        return

    def honeypot_thread(port: int):
        while True:
            try:
                result = subprocess.run([NETCAT_BIN, "-l", "-p", str(port), "-s", "127.0.0.1"], timeout=30, capture_output=True, text=True)
                if result.stderr:
                    result = subprocess.run([NETCAT_BIN, "-l", "127.0.0.1", str(port)], timeout=30, capture_output=True, text=True)
                if result.stdout or result.stderr:
                    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                    with open(HONEYPOT_LOG, "a") as f:
                        f.write(f"[{timestamp}] HONEYPOT_HIT: Port {port} - {result.stdout or result.stderr}\n")
                    log_alert(HIGH, f"Honeypot triggered on port {port}")
            except subprocess.TimeoutExpired:
                continue
            except Exception as e:
                logger.error(f"Honeypot error on port {port}: {e}")
                break

    HONEYPOT_LOG.parent.mkdir(parents=True, exist_ok=True)
    HONEYPOT_LOG.touch()

    pid_file = LOG_DIR / "honeypot.pids"
    for port in HONEYPOT_PORTS:
        if subprocess.run(f"ss -tuln | grep -q ':{port} '", shell=True).returncode == 0:
            continue
        thread = threading.Thread(target=honeypot_thread, args=(port,), daemon=True)
        thread.start()
        with open(pid_file, "a") as f:
            f.write(f"{thread.ident}\n")
    logger.info(f"Honeypots started on ports: {', '.join(map(str, HONEYPOT_PORTS))}")

def stop_honeypots():
    """Stop honeypot listeners."""
    pid_file = LOG_DIR / "honeypot.pids"
    if pid_file.exists():
        with open(pid_file, "r") as f:
            for pid in f.read().splitlines():
                try:
                    os.kill(int(pid), signal.SIGTERM)
                except (ValueError, ProcessLookupError):
                    pass
        pid_file.unlink(missing_ok=True)

class LinuxSentinelHandler(BaseHTTPRequestHandler):
    """HTTP handler for the REST API."""
    def do_GET(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == "/api/status":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "version": VERSION,
                "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                "status": "active",
                "log_dir": str(LOG_DIR)
            }).encode())
        elif parsed_path.path == "/api/alerts":
            alerts = []
            alert_file = ALERTS_DIR / f"{datetime.now().strftime('%Y%m%d')}.log"
            if alert_file.exists():
                with open(alert_file, "r") as f:
                    for line in f.readlines()[-20:]:
                        if "[LEVEL:" in line:
                            parts = line.strip().split("] ", 2)
                            if len(parts) >= 3:
                                timestamp = parts[0][1:]
                                level = {"1": "critical", "2": "high", "3": "medium", "4": "low"}.get(parts[1].split(":")[1], "unknown")
                                alerts.append({"timestamp": timestamp, "level": level, "message": parts[2]})
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(alerts).encode())
        elif parsed_path.path == "/api/scan":
            with open(JSON_OUTPUT_FILE, "r") as f:
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(f.read().encode())
        elif parsed_path.path == "/api/honeypot":
            activity = []
            if HONEYPOT_LOG.exists():
                with open(HONEYPOT_LOG, "r") as f:
                    activity = f.readlines()[-10:]
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"events": activity}).encode())
        elif parsed_path.path == "/":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write("""
<!DOCTYPE html>
<html>
<head>
    <title>Linux Sentinel Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #1a1a1a; color: #fff; }
        .container { max-width: 1200px; margin: 0 auto; }
        .card { background: #2d2d2d; padding: 20px; margin: 10px 0; border-radius: 8px; }
        .alert-critical { border-left: 5px solid #ff4444; }
        .alert-high { border-left: 5px solid #ff8800; }
        .alert-medium { border-left: 5px solid #0088ff; }
        .alert-low { border-left: 5px solid #00ff88; }
        .status-good { color: #00ff88; }
        .status-warning { color: #ff8800; }
        .status-critical { color: #ff4444; }
        h1 { color: #00ff88; }
        .refresh { float: right; cursor: pointer; color: #0088ff; }
    </style>
    <script>
        function refreshData() {
            fetch('/api/status').then(r => r.json()).then(data => {
                document.getElementById('status').innerHTML = JSON.stringify(data, null, 2);
            });
            fetch('/api/alerts').then(r => r.json()).then(data => {
                let html = '';
                data.forEach(alert => {
                    let className = 'alert-' + alert.level;
                    html += `<div class="card ${className}"><strong>${alert.level.toUpperCase()}</strong>: ${alert.message}<br><small>${alert.timestamp}</small></div>`;
                });
                document.getElementById('alerts').innerHTML = html;
            });
        }
        setInterval(refreshData, 30000);
        window.onload = refreshData;
    </script>
</head>
<body>
    <div class="container">
        <h1>🛡️ Linux Sentinel v2.3 Dashboard <span class="refresh" onclick="refreshData()">🔄 Refresh</span></h1>
        <div class="card">
            <h2>System Status</h2>
            <pre id="status">Loading...</pre>
        </div>
        <div class="card">
            <h2>Recent Alerts</h2>
            <div id="alerts">Loading...</div>
        </div>
    </div>
</body>
</html>
""".encode())
        else:
            self.send_error(404, "Not Found")

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    pass

def start_api_server():
    """Start the REST API server."""
    if not shutil.which("python3"):
        logger.info("Python3 not available - API server disabled")
        return

    used_port = API_PORT
    for port in range(API_PORT, API_PORT + 5):
        try:
            server = ThreadingHTTPServer(("127.0.0.1", port), LinuxSentinelHandler)
            with open(LOG_DIR / "api_server.pid", "w") as f:
                f.write(str(os.getpid()))
            logger.info(f"API server started on http://127.0.0.1:{port}")
            threading.Thread(target=server.serve_forever, daemon=True).start()
            return
        except OSError:
            used_port = port + 1
    logger.info(f"No available ports found starting from {API_PORT} - API server disabled")

def stop_api_server():
    """Stop the API server."""
    pid_file = LOG_DIR / "api_server.pid"
    if pid_file.exists():
        with open(pid_file, "r") as f:
            pid = f.read().strip()
        if pid and os.path.exists(f"/proc/{pid}"):
            os.kill(int(pid), signal.SIGTERM)
        pid_file.unlink(missing_ok=True)

def detect_anti_evasion():
    """Detect anti-evasion techniques."""
    logger.info("Running anti-evasion detection...")

    if "LD_PRELOAD" in os.environ:
        log_alert(HIGH, f"LD_PRELOAD environment variable detected: {os.environ['LD_PRELOAD']}")

    for pid in [x for x in Path("/proc").glob("[0-9]*")][:20]:
        try:
            with open(f"/proc/{pid.name}/environ", "r") as f:
                environ = f.read().replace("\0", "\n")
            if "LD_PRELOAD=" in environ:
                proc_name = subprocess.run(["ps", "-p", pid.name, "-o", "comm="], capture_output=True, text=True).stdout.strip()
                preload = next((x.split("=", 1)[1] for x in environ.split("\n") if x.startswith("LD_PRELOAD=")), "")
                log_alert(HIGH, f"Process with LD_PRELOAD detected: {proc_name} (PID: {pid.name}, PRELOAD: {preload})")
        except (FileNotFoundError, PermissionError):
            continue

    proc_dirs = len(list(Path("/proc").glob("[0-9]*")))
    ps_count = len(subprocess.run(["ps", "aux", "--no-headers"], capture_output=True, text=True).stdout.splitlines())
    ps_ef_count = len(subprocess.run(["ps", "-ef", "--no-headers"], capture_output=True, text=True).stdout.splitlines())
    if abs(proc_dirs - ps_count) > 15 or abs(proc_dirs - ps_ef_count) > 15:
        log_alert(HIGH, f"Significant /proc inconsistency detected (proc_dirs: {proc_dirs}, ps: {ps_count}, ps_ef: {ps_ef_count})")

    if os.geteuid() == 0 and Path("/proc/kallsyms").exists():
        kallsyms = Path("/proc/kallsyms").read_text()
        if any(x in kallsyms for x in ["hijacked", "hook", "detour"]):
            log_alert(CRITICAL, "Suspicious kernel symbols detected")

    hiding_techniques = ["/usr/bin/...", "/usr/sbin/...", "/lib/.x", "/lib64/.x", "/tmp/.hidden", "/var/tmp/.X11-unix"]
    for path in hiding_techniques:
        if Path(path).exists():
            log_alert(CRITICAL, f"Rootkit hiding technique detected: {path}")

def monitor_network_advanced():
    """Advanced network monitoring."""
    if not config["MONITOR_NETWORK"]:
        return

    logger.info("Advanced network monitoring...")

    ss_ports = len(set(re.findall(r":(\d+) ", subprocess.run(["ss", "-Htulnp"], capture_output=True, text=True).stdout)))
    netstat_ports = len(set(re.findall(r":(\d+) ", subprocess.run(["netstat", "-tulnp"], capture_output=True, text=True).stdout)))
    lsof_ports = len(set(re.findall(r":(\d+) ", subprocess.run(["lsof", "-i", "-P", "-n"], capture_output=True, text=True).stdout)))

    if abs(ss_ports - netstat_ports) > 5 or abs(lsof_ports - ss_ports) > 5:
        log_alert(HIGH, f"Network tool output inconsistency detected (ss: {ss_ports}, netstat: {netstat_ports}, lsof: {lsof_ports})")

    if Path("/proc/net/raw").exists():
        raw_sockets = len([x for x in Path("/proc/net/raw").read_text().splitlines() if not x.startswith("sl")])
        if raw_sockets > 3:
            log_alert(MEDIUM, f"Multiple RAW sockets detected: {raw_sockets}")

    icmp_traffic = int(re.search(r"ICMP:.*?(\d+)", Path("/proc/net/snmp").read_text()).group(1)) if Path("/proc/net/snmp").exists() else 0
    if icmp_traffic > 1000:
        log_alert(MEDIUM, f"High ICMP traffic detected: {icmp_traffic} packets")

def monitor_files_with_yara():
    """File monitoring with YARA."""
    if not config["MONITOR_FILES"] or not HAS_YARA:
        return

    logger.info("File monitoring with YARA...")

    def scan_file(file: Path):
        if file.stat().st_size > 1048576:  # Skip files > 1MB
            return
        if HAS_YARA:
            for rule in YARA_RULES_DIR.glob("*.yar"):
                result = subprocess.run(["yara", "-s", str(rule), str(file)], capture_output=True, text=True)
                if result.stdout:
                    log_alert(CRITICAL, f"YARA detection: {result.stdout}")
                    quarantine_file_forensic(file)
                    return
        if file.is_file() and file.readable():
            content = file.read_text(errors="ignore")
            if re.search(r"(eval.*base64|exec.*\$|/dev/tcp|socket\.socket.*connect)", content):
                log_alert(HIGH, f"Suspicious script content: {file}")
                quarantine_file_forensic(file)

    locations = ["/tmp", "/var/tmp", "/dev/shm"]
    with concurrent.futures.ThreadPoolExecutor(max_workers=PARALLEL_JOBS) as executor:
        for loc in locations:
            loc_path = Path(loc)
            if loc_path.is_dir() and loc_path.readable():
                files = list(loc_path.glob("**/*"))[:100]  # Limit to 100 files per location
                executor.map(scan_file, files)

def quarantine_file_forensic(file: Path):
    """Quarantine a file with forensic analysis."""
    timestamp = int(time.time())
    quarantine_name = f"{file.name}_{timestamp}"
    forensic_dir = QUARANTINE_DIR / "forensics"
    forensic_dir.mkdir(parents=True, exist_ok=True)

    if file.is_file() and file.parent.writable():
        stat_info = subprocess.run(["stat", str(file)], capture_output=True, text=True).stdout
        (forensic_dir / f"{quarantine_name}.stat").write_text(stat_info)
        ls_info = subprocess.run(["ls", "-la", str(file)], capture_output=True, text=True).stdout
        (forensic_dir / f"{quarantine_name}.ls").write_text(ls_info)
        file_info = subprocess.run(["file", str(file)], capture_output=True, text=True).stdout
        (forensic_dir / f"{quarantine_name}.file").write_text(file_info)
        sha256 = hashlib.sha256(file.read_bytes()).hexdigest()
        (forensic_dir / f"{quarantine_name}.sha256").write_text(sha256)
        if HAS_YARA:
            yara_result = subprocess.run(["yara", "-s", "-r", str(YARA_RULES_DIR), str(file)], capture_output=True, text=True).stdout
            (forensic_dir / f"{quarantine_name}.yara").write_text(yara_result)
        if shutil.which("strings"):
            strings = subprocess.run(["strings", str(file)], capture_output=True, text=True).stdout.splitlines()[:100]
            (forensic_dir / f"{quarantine_name}.strings").write_text("\n".join(strings))

        shutil.move(file, QUARANTINE_DIR / quarantine_name)
        file.touch()
        os.chmod(file, 0o000)
        logger.info(f"File quarantined: {file} -> {QUARANTINE_DIR / quarantine_name}")

def update_threat_intelligence():
    """Update threat intelligence feeds."""
    if not config["ENABLE_THREAT_INTEL"]:
        return

    logger.info("Updating threat intelligence...")
    intel_file = THREAT_INTEL_DIR / "malicious_ips.txt"
    timestamp_file = THREAT_INTEL_DIR / ".last_update"

    update_needed = True
    if timestamp_file.exists():
        last_update = int(timestamp_file.read_text())
        if (datetime.now() - datetime.fromtimestamp(last_update)).total_seconds() < THREAT_INTEL_UPDATE_HOURS * 3600:
            update_needed = False

    if update_needed and shutil.which("curl"):
        try:
            temp_file = Path("/tmp") / f"linux_sentinel_threat_{int(time.time())}"
            subprocess.run(["curl", "-s", "--max-time", "30", "-o", str(temp_file), "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"], check=True)
            if temp_file.stat().st_size > 0 and len(temp_file.read_text().splitlines()) > 100:
                shutil.move(temp_file, intel_file)
                timestamp_file.write_text(str(int(time.time())))
                logger.info(f"Threat intelligence updated ({len(intel_file.read_text().splitlines())} entries)")
            else:
                temp_file.unlink()
                logger.info("Threat intelligence update failed - validation failed")
        except Exception as e:
            logger.info(f"Threat intelligence update failed: {e}")
            temp_file.unlink(missing_ok=True)

def create_baseline():
    """Create security baseline."""
    logger.info("Creating security baseline...")
    BASELINE_DIR.mkdir(parents=True, exist_ok=True)

    if shutil.which("ss"):
        (BASELINE_DIR / "network_baseline.txt").write_text(subprocess.run(["ss", "-tulnp", "--no-header"], capture_output=True, text=True).stdout)
    elif shutil.which("netstat"):
        (BASELINE_DIR / "network_baseline.txt").write_text(subprocess.run(["netstat", "-tulnp", "--numeric-hosts", "--numeric-ports"], capture_output=True, text=True).stdout)

    (BASELINE_DIR / "process_baseline.txt").write_text(subprocess.run(["ps", "-eo", "pid,ppid,user,comm,cmd", "--no-headers"], capture_output=True, text=True).stdout)

    if shutil.which("systemctl"):
        (BASELINE_DIR / "services_baseline.txt").write_text(subprocess.run(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--no-legend", "--plain"], capture_output=True, text=True).stdout)

    for path in config["CRITICAL_PATHS"]:
        path = Path(path)
        if path.exists() and path.is_file() and path.readable():
            (BASELINE_DIR / f"{path.name}_baseline.sha256").write_text(hashlib.sha256(path.read_bytes()).hexdigest())

    if Path("/etc/passwd").readable():
        (BASELINE_DIR / "users_baseline.txt").write_text("\n".join(sorted(Path("/etc/passwd").read_text().splitlines())))

    if shutil.which("last"):
        (BASELINE_DIR / "last_baseline.txt").write_text(subprocess.run(["last", "-n", "10", "--time-format=iso"], capture_output=True, text=True).stdout)

    pkg_hash = ""
    if IS_DEBIAN:
        pkg_hash = hashlib.sha256(subprocess.run(["dpkg", "-l"], capture_output=True, text=True).stdout.encode()).hexdigest()
    elif IS_FEDORA:
        pkg_hash = hashlib.sha256(subprocess.run(["rpm", "-qa", "--queryformat=%{NAME}-%{VERSION}-%{RELEASE}\n"], capture_output=True, text=True).stdout.encode()).hexdigest()
    elif IS_NIXOS:
        pkg_hash = hashlib.sha256(subprocess.run(["nix-store", "--query", "--requisites", "/run/current-system"], capture_output=True, text=True).stdout.encode()).hexdigest()
    if pkg_hash:
        (BASELINE_DIR / "packages_hash.txt").write_text(pkg_hash)

    (BASELINE_DIR / "suid_baseline.txt").write_text("\n".join(sorted(subprocess.run(["find", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "-maxdepth", "1", "-perm", "/4000", "-o", "-perm", "/2000"], capture_output=True, text=True).stdout.splitlines())))

    (BASELINE_DIR / ".initialized").touch()
    logger.info("Baseline created successfully")

def monitor_processes():
    """Monitor processes for suspicious activity."""
    if not config["MONITOR_PROCESSES"]:
        return

    logger.info("Process monitoring...")
    suspicious_procs = ["nc", "netcat", "socat", "ncat"]
    for proc in suspicious_procs:
        try:
            pids = subprocess.run(["pgrep", "-f", proc], capture_output=True, text=True).stdout.splitlines()[:3]
            for pid in pids:
                proc_info = subprocess.run(["ps", "-p", pid, "-o", "user,comm,args", "--no-headers"], capture_output=True, text=True).stdout
                if proc_info:
                    user, comm, args = proc_info.split(maxsplit=2)
                    if comm not in config["WHITELIST_PROCESSES"]:
                        log_alert(MEDIUM, f"Potentially suspicious process: {comm} (User: {user}, PID: {pid})")
        except subprocess.CalledProcessError:
            pass

def monitor_users():
    """Monitor user accounts."""
    if not config["MONITOR_USERS"]:
        return

    logger.info("User monitoring...")
    if Path("/etc/passwd").readable() and (BASELINE_DIR / "users_baseline.txt").exists():
        current_users = sorted(Path("/etc/passwd").read_text().splitlines())
        baseline_users = sorted((BASELINE_DIR / "users_baseline.txt").read_text().splitlines())
        new_users = [u for u in current_users if u not in baseline_users][:3]
        for user in new_users:
            if subprocess.run(["getent", "passwd", user.split(":")[0]], capture_output=True).returncode == 0:
                log_alert(HIGH, f"New user account detected: {user.split(':')[0]}")

def monitor_rootkits():
    """Detect rootkit indicators."""
    if not config["MONITOR_ROOTKITS"]:
        return

    logger.info("Rootkit detection...")
    rootkit_paths = ["/tmp/.ICE-unix/.X11-unix", "/dev/shm/.hidden", "/tmp/.hidden", "/usr/bin/...", "/usr/sbin/..."]
    for path in rootkit_paths:
        if Path(path).exists():
            log_alert(CRITICAL, f"Rootkit indicator found: {path}")

def monitor_memory():
    """Monitor memory usage."""
    if not config["MONITOR_MEMORY"]:
        return

    logger.info("Memory monitoring...")
    try:
        output = subprocess.run(["ps", "aux", "--sort=-%mem", "--no-headers"], capture_output=True, text=True).stdout.splitlines()[:3]
        for line in output:
            fields = line.split(maxsplit=10)
            mem_usage = float(fields[3])
            proc_name = Path(fields[10]).name
            pid = fields[1]
            if proc_name not in config["WHITELIST_PROCESSES"] and mem_usage > 80:
                log_alert(MEDIUM, f"High memory usage: {proc_name} (PID: {pid}, MEM: {mem_usage}%)")
    except Exception as e:
        logger.error(f"Memory monitoring error: {e}")

def validate_script_integrity():
    """Validate script integrity."""
    script_hash_file = LOG_DIR / ".script_hash"
    current_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

    if script_hash_file.exists():
        stored_hash = script_hash_file.read_text().strip()
        if current_hash != stored_hash:
            log_alert(CRITICAL, "Script integrity check failed - possible tampering detected")
            print(f"Expected: {stored_hash}\nCurrent: {current_hash}\n")
            choice = input("Continue anyway? (y/N): ").lower()
            if choice != "y":
                exit(1)

    script_hash_file.write_text(current_hash)

def main_enhanced(args):
    """Run enhanced security scan."""
    start_time = time.time()
    logger.info("Linux Sentinel v2.3 Enhanced - Starting advanced security scan...")

    with open(JSON_OUTPUT_FILE, "r") as f:
        json_data = json.load(f)
    json_data["scan_start"] = datetime.utcnow().isoformat()
    json_data["hostname"] = subprocess.run(["hostname"], capture_output=True, text=True).stdout.strip()
    json_data["environment"]["user"] = os.getlogin()
    json_data["environment"].update({
        "is_container": IS_CONTAINER,
        "is_vm": IS_VM,
        "has_jq": HAS_JQ,
        "has_inotify": HAS_INOTIFY,
        "has_yara": HAS_YARA,
        "has_bcc": HAS_BCC,
        "has_netcat": HAS_NETCAT
    })
    with open(JSON_OUTPUT_FILE, "w") as f:
        json.dump(json_data, f, indent=2)

    for dir in [LOG_DIR, BASELINE_DIR, ALERTS_DIR, QUARANTINE_DIR, BACKUP_DIR, THREAT_INTEL_DIR, YARA_RULES_DIR]:
        dir.mkdir(parents=True, exist_ok=True)

    detect_environment()
    init_json_output()
    init_yara_rules()
    update_threat_intelligence()

    if not (BASELINE_DIR / ".initialized").exists() or args.force_baseline:
        create_baseline()

    modules_run = []
    if config["ENABLE_ANTI_EVASION"]:
        detect_anti_evasion()
        modules_run.append("anti-evasion")

    if config["MONITOR_NETWORK"]:
        monitor_network_advanced()
        modules_run.append("network")

    if config["MONITOR_FILES"] and HAS_YARA:
        monitor_files_with_yara()
        modules_run.append("files-yara")

    if config["MONITOR_PROCESSES"]:
        monitor_processes()
        modules_run.append("processes")

    if config["MONITOR_USERS"]:
        monitor_users()
        modules_run.append("users")

    if config["MONITOR_ROOTKITS"]:
        monitor_rootkits()
        modules_run.append("rootkits")

    if config["MONITOR_MEMORY"]:
        monitor_memory()
        modules_run.append("memory")

    if config["ENABLE_EBPF"] and HAS_BCC and os.geteuid() == 0:
        start_ebpf_monitoring()
        json_data["features"]["ebpf_monitoring"] = True
        modules_run.append("ebpf")

    if config["ENABLE_HONEYPOTS"] and HAS_NETCAT and os.geteuid() == 0:
        start_honeypots()
        json_data["features"]["honeypots"] = True
        modules_run.append("honeypots")

    if config["ENABLE_API_SERVER"]:
        start_api_server()
        json_data["features"]["api_server"] = True
        modules_run.append("api")

    if config["ENABLE_YARA"] and HAS_YARA:
        json_data["features"]["yara_scanning"] = True

    end_time = time.time()
    duration = int(end_time - start_time)
    json_data["scan_end"] = datetime.utcnow().isoformat()
    json_data["performance"]["scan_duration"] = duration
    json_data["performance"]["modules_run"] = modules_run
    json_data["integrity"]["baseline_age"] = int((time.time() - (BASELINE_DIR / ".initialized").stat().st_mtime) / 86400) if (BASELINE_DIR / ".initialized").exists() else 0
    with open(JSON_OUTPUT_FILE, "w") as f:
        json.dump(json_data, f, indent=2)

    generate_enhanced_summary(duration, modules_run)

def generate_enhanced_summary(duration: int, modules_run: List[str]):
    """Generate a summary of the scan."""
    today = datetime.now().strftime("%Y%m%d")
    alert_file = ALERTS_DIR / f"{today}.log"

    alert_count = critical_count = high_count = medium_count = low_count = 0
    if alert_file.exists():
        with open(alert_file, "r") as f:
            lines = f.readlines()
            alert_count = len([l for l in lines if l.startswith("[")])
            critical_count = len([l for l in lines if "CRITICAL" in l])
            high_count = len([l for l in lines if "HIGH" in l])
            medium_count = len([l for l in lines if "MEDIUM" in l])
            low_count = len([l for l in lines if "LOW" in l])

    print(f"\033[0;36m=== GHOST SENTINEL v{VERSION} ADVANCED SECURITY SUMMARY ===\033[0m")
    print(f"\033[1;33mScan Duration: {duration}s\033[0m")
    print(f"\033[1;33mModules Run: {len(modules_run)} ({', '.join(modules_run)})\033[0m")
    print(f"\033[1;33mTotal Alerts: {alert_count}\033[0m")
    print(f"\033[0;31mCritical: {critical_count}\033[0m")
    print(f"\033[1;33mHigh: {high_count}\033[0m")
    print(f"\033[0;34mMedium: {medium_count}\033[0m")
    print(f"\033[0;32mLow: {low_count}\033[0m")
    print(f"\033[0;34mEnvironment: Container={IS_CONTAINER}, VM={IS_VM}\033[0m")
    print(f"\033[0;34mCapabilities: YARA={HAS_YARA}, eBPF={HAS_BCC}, jq={HAS_JQ}\033[0m")
    print(f"\033[0;36mLogs: {LOG_DIR}\033[0m")
    print(f"\033[0;36mJSON Output: {JSON_OUTPUT_FILE}\033[0m")

    active_features = []
    if (LOG_DIR / "ebpf_monitor.pid").exists():
        active_features.append("eBPF Monitoring")
    if (LOG_DIR / "honeypot.pids").exists():
        active_features.append("Honeypots")
    if (LOG_DIR / "api_server.pid").exists():
        active_features.append("API Server")
    if active_features:
        print(f"\033[0;35mActive Features: {', '.join(active_features)}\033[0m")

    if (LOG_DIR / "api_server.pid").exists():
        print(f"\033[0;36mDashboard: http://127.0.0.1:{API_PORT}\033[0m")

    if critical_count or high_count:
        print("\n\033[0;31mPriority Alerts:\033[0m")
        for line in lines[-5:]:
            if "[LEVEL:1]" in line or "[LEVEL:2]" in line:
                level = "CRITICAL" if "[LEVEL:1]" in line else "HIGH"
                msg = line.split("] ", 2)[2].strip()
                print(f"\033[{'0;31m' if level == 'CRITICAL' else '1;33m'}  {'🚨' if level == 'CRITICAL' else '⚠️'} {level}: {msg}\033[0m")
    else:
        print("\033[0;32m✓ No critical threats detected\033[0m")

    # Load json_data from the JSON output file
    if JSON_OUTPUT_FILE.exists():
        with open(JSON_OUTPUT_FILE, "r") as jf:
            json_data = json.load(jf)
        baseline_age = json_data["integrity"]["baseline_age"]
    else:
        baseline_age = 0
    print(f"\033[0;36mBaseline Age: {baseline_age} days\033[0m")
    if baseline_age > 30:
        print("\033[1;33m⚠️  Consider updating baseline (run with --force-baseline)\033[0m")

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description=f"Linux Sentinel v{VERSION} Security Monitor")
    parser.add_argument("mode", choices=["run", "install", "baseline", "config", "logs", "alerts", "json", "test", "enhanced", "update", "performance", "integrity", "reset-integrity", "fix-hostname", "systemd", "honeypot", "api", "cleanup", "status", "dashboard", "yara", "ebpf"], default="run", nargs="?")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--force-baseline", action="store_true", help="Force baseline creation")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    acquire_lock()
    signal.signal(signal.SIGINT, lambda s, f: cleanup())
    signal.signal(signal.SIGTERM, lambda s, f: cleanup())

    global config
    config = load_config()

    if args.mode == "install":
        cron_entry = f"0 * * * * {BASE_DIR}/linux_sentinel.py >/dev/null 2>&1"
        if shutil.which("crontab") and not subprocess.run(["crontab", "-l"], capture_output=True, text=True).stdout.strip().endswith(cron_entry):
            crontab = subprocess.run(["crontab", "-l"], capture_output=True, text=True).stdout + cron_entry
            subprocess.run(["crontab", "-"], input=crontab, text=True)
            logger.info("Installed to run hourly via cron")
        if os.geteuid() == 0 and shutil.which("systemctl"):
            service_file = Path("/etc/systemd/system/linux-sentinel.service")
            timer_file = Path("/etc/systemd/system/linux-sentinel.timer")
            service_file.write_text(f"""
[Unit]
Description=Linux Sentinel v{VERSION} Security Monitor
After=network.target

[Service]
Type=oneshot
ExecStart={BASE_DIR}/linux_sentinel.py enhanced
User=root
StandardOutput=journal
StandardError=journal
""")
            timer_file.write_text(f"""
[Unit]
Description=Run Linux Sentinel hourly
Requires=linux-sentinel.service

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
""")
            subprocess.run(["systemctl", "daemon-reload"])
            subprocess.run(["systemctl", "enable", "linux-sentinel.timer"])
            subprocess.run(["systemctl", "start", "linux-sentinel.timer"])
            logger.info("Systemd service and timer installed")
    elif args.mode == "baseline":
        detect_environment()
        init_json_output()
        init_yara_rules()
        create_baseline()
    elif args.mode == "config":
        subprocess.run([os.environ.get("EDITOR", "nano"), str(CONFIG_FILE)])
    elif args.mode == "logs":
        if (LOG_DIR / "sentinel.log").exists():
            subprocess.run(["tail", "-f", str(LOG_DIR / "sentinel.log")])
        else:
            print("No log file found. Run a scan first.")
    elif args.mode == "alerts":
        alert_file = ALERTS_DIR / f"{datetime.now().strftime('%Y%m%d')}.log"
        if alert_file.exists():
            print(alert_file.read_text())
        else:
            print("No alerts for today")
    elif args.mode == "json":
        if JSON_OUTPUT_FILE.exists():
            if HAS_JQ:
                subprocess.run(["jq", ".", str(JSON_OUTPUT_FILE)])
            else:
                print(JSON_OUTPUT_FILE.read_text())
        else:
            print("No JSON output available")
    elif args.mode == "test":
        detect_environment()
        init_json_output()
        init_yara_rules()
        log_alert(HIGH, "Test alert - Linux Sentinel v2.3 is working")
        print(f"\033[0;32m✓ Test completed successfully!\033[0m")
        print(f"\033[0;36mAdvanced Capabilities:\033[0m")
        print(f"  YARA: {HAS_YARA}\n  eBPF: {HAS_BCC}\n  jq: {HAS_JQ}\n  inotify: {HAS_INOTIFY}\n  netcat: {HAS_NETCAT}")
        print(f"\033[0;36mEnvironment: Container={IS_CONTAINER}, VM={IS_VM}\033[0m")
        print(f"\033[0;36mLogs: {LOG_DIR}\033[0m")
        print(f"\033[0;36mJSON: {JSON_OUTPUT_FILE}\033[0m")
    elif args.mode in ["enhanced", "v2", "v3", "performance"]:
        config["PERFORMANCE_MODE"] = args.mode == "performance"
        main_enhanced(args)
    elif args.mode == "update":
        update_url = "https://raw.githubusercontent.com/your-repo/linux-sentinel/main/linux_sentinel.py"
        if shutil.which("curl"):
            try:
                temp_file = Path("/tmp") / f"linux_sentinel_{int(time.time())}.py"
                subprocess.run(["curl", "-s", "--max-time", "30", "-o", str(temp_file), update_url], check=True)
                if temp_file.stat().st_size > 0 and "#!/usr/bin/env python3" in temp_file.read_text():
                    shutil.copy2(__file__, f"{__file__}.backup.{int(time.time())}")
                    shutil.move(temp_file, __file__)
                    os.chmod(__file__, 0o755)
                    logger.info("Update completed successfully")
                else:
                    temp_file.unlink()
                    logger.info("Update failed - invalid file")
            except Exception as e:
                logger.info(f"Update failed: {e}")
                temp_file.unlink(missing_ok=True)
        else:
            logger.info("curl not available - cannot update")
    elif args.mode == "integrity":
        validate_script_integrity()
        print("\033[0;32m✓ Script integrity check completed\033[0m")
    elif args.mode == "reset-integrity":
        script_hash_file = LOG_DIR / ".script_hash"
        current_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        script_hash_file.write_text(current_hash)
        print(f"\033[0;32m✓ Script integrity hash reset\033[0m")
        print(f"Current hash: {current_hash}")
    elif args.mode == "fix-hostname":
        hostname = subprocess.run(["hostname"], capture_output=True, text=True).stdout.strip()
        if not re.search(rf"\b{hostname}\b", Path("/etc/hosts").read_text()):
            with open("/etc/hosts", "a") as f:
                f.write(f"127.0.0.1 {hostname}\n")
            print("\033[0;32m✓ Hostname resolution fixed\033[0m")
        else:
            print("\033[0;32m✓ Hostname resolution already OK\033[0m")
    elif args.mode == "systemd":
        if os.geteuid() == 0:
            service_file = Path("/etc/systemd/system/linux-sentinel.service")
            timer_file = Path("/etc/systemd/system/linux-sentinel.timer")
            service_file.write_text(f"""
[Unit]
Description=Linux Sentinel v{VERSION} Security Monitor
After=network.target

[Service]
Type=oneshot
ExecStart={BASE_DIR}/linux_sentinel.py enhanced
User=root
StandardOutput=journal
StandardError=journal
""")
            timer_file.write_text(f"""
[Unit]
Description=Run Linux Sentinel hourly
Requires=linux-sentinel.service

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
""")
            subprocess.run(["systemctl", "daemon-reload"])
            subprocess.run(["systemctl", "enable", "linux-sentinel.timer"])
            subprocess.run(["systemctl", "start", "linux-sentinel.timer"])
            logger.info("Systemd service and timer installed")
        else:
            print("Systemd integration requires root privileges")
    elif args.mode == "honeypot":
        if os.geteuid() == 0:
            detect_environment()
            init_json_output()
            init_yara_rules()
            start_honeypots()
            print("Honeypots started. Press Ctrl+C to stop.")
            input()
            stop_honeypots()
        else:
            print("Honeypots require root privileges")
    elif args.mode == "api":
        detect_environment()
        init_json_output()
        init_yara_rules()
        start_api_server()
        print(f"API server started on http://127.0.0.1:{API_PORT}")
        print("Press Ctrl+C to stop.")
        input()
        stop_api_server()
    elif args.mode == "cleanup":
        stop_honeypots()
        stop_ebpf_monitoring()
        stop_api_server()
        subprocess.run(["pkill", "-f", "linux_sentinel"], check=False)
        for temp in Path("/tmp").glob("linux_sentinel_*"):
            temp.unlink()
        LOCK_FILE.unlink(missing_ok=True)
        PID_FILE.unlink(missing_ok=True)
        script_hash_file = LOG_DIR / ".script_hash"
        current_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        script_hash_file.write_text(current_hash)
        hostname = subprocess.run(["hostname"], capture_output=True, text=True).stdout.strip()
        if not re.search(rf"\b{hostname}\b", Path("/etc/hosts").read_text()):
            with open("/etc/hosts", "a") as f:
                f.write(f"127.0.0.1 {hostname}\n")
            print("✓ Fixed hostname resolution")
        print("\033[0;32m✓ Cleanup completed - all issues resolved\033[0m")
        print("You can now run: sudo python3 linux_sentinel.py test")
    elif args.mode == "status":
        print(f"Linux Sentinel v{VERSION} Status:")
        print("==========================")
        pid_file = LOG_DIR / "api_server.pid"
        if pid_file.exists() and os.path.exists(f"/proc/{pid_file.read_text().strip()}"):
            print(f"\033[0;32m✓ API Server running (PID: {pid_file.read_text().strip()}) - http://127.0.0.1:{API_PORT}\033[0m")
        else:
            print("\033[0;31m✗ API Server not running\033[0m")
        pid_file = LOG_DIR / "honeypot.pids"
        if pid_file.exists():
            count = len(pid_file.read_text().splitlines())
            print(f"\033[0;32m✓ Honeypots running: {count}\033[0m")
        else:
            print("\033[0;31m✗ Honeypots not running\033[0m")
        pid_file = LOG_DIR / "ebpf_monitor.pid"
        if pid_file.exists() and os.path.exists(f"/proc/{pid_file.read_text().strip()}"):
            print(f"\033[0;32m✓ eBPF Monitor running (PID: {pid_file.read_text().strip()})\033[0m")
        else:
            print("\033[0;31m✗ eBPF Monitor not running\033[0m")
        alert_file = ALERTS_DIR / f"{datetime.now().strftime('%Y%m%d')}.log"
        if alert_file.exists():
            count = len([l for l in alert_file.read_text().splitlines() if l.startswith("[")])
            print(f"\033[1;33mAlerts today: {count}\033[0m")
        else:
            print("\033[0;32mNo alerts today\033[0m")
    elif args.mode == "dashboard":
        detect_environment()
        init_json_output()
        init_yara_rules()
        start_api_server()
        print(f"\033[0;32m✓ Dashboard started at http://127.0.0.1:{API_PORT}\033[0m")
        print("Press Ctrl+C to stop...")
        input()
    elif args.mode == "yara":
        detect_environment()
        init_json_output()
        init_yara_rules()
        if HAS_YARA:
            monitor_files_with_yara()
        else:
            print("YARA not available - install yara package")
    elif args.mode == "ebpf":
        if HAS_BCC and os.geteuid() == 0:
            detect_environment()
            init_json_output()
            init_yara_rules()
            start_ebpf_monitoring()
            print("eBPF monitoring started. Press Ctrl+C to stop.")
            input()
            stop_ebpf_monitoring()
        else:
            print("eBPF monitoring requires root privileges and BCC tools")
    else:
        detect_environment()
        init_json_output()
        init_yara_rules()
        monitor_network_advanced()
        monitor_processes()
        monitor_files_with_yara()
        monitor_users()
        monitor_rootkits()
        monitor_memory()
        alert_file = ALERTS_DIR / f"{datetime.now().strftime('%Y%m%d')}.log"
        alert_count = len([l for l in alert_file.read_text().splitlines() if l.startswith("[")]) if alert_file.exists() else 0
        if alert_count:
            print(f"\033[1;33mSecurity Summary: {alert_count} alerts generated\033[0m")
            print(f"\033[1;33mCheck: {alert_file}\033[0m")
        else:
            print("\033[0;32mSecurity Summary: No threats detected\033[0m")

if __name__ == "__main__":
    main()