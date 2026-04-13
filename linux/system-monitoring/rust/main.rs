use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use config::{Config, File as ConfigFile};
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::mpsc;
use tokio::time;
use tracing::{error, info, warn, Level};
use tracing_subscriber::fmt::format::Json;
use rayon::prelude::*;
use libbpf_rs::Program;
use yara::{Compiler, Rules};
use seccomp::{allow_syscall, SeccompAction, SeccompFilter};

const VERSION: &str = "2.3";
const LOG_DIR: &str = "/var/log/linux-sentinel";
const BACKUP_DIR: &str = "/var/backups/linux-sentinel";
const API_PORT: u16 = 8080;
const HONEYPOT_PORTS: &[u16] = &[2222, 23, 21, 3389]; // Removed 8080 to avoid conflict with API

#[derive(Parser)]
#[clap(version = VERSION, about = "Linux Sentinel Security Monitoring Tool")]
struct Cli {
    #[clap(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    Enhanced,
    Test,
    Api,
    Honeypot,
    Cleanup,
    Status,
    Yara,
    Ebpf,
}

#[derive(Deserialize, Clone)]
struct SentinelConfig {
    monitor_network: bool,
    monitor_processes: bool,
    monitor_files: bool,
    monitor_users: bool,
    monitor_rootkits: bool,
    monitor_memory: bool,
    enable_anti_evasion: bool,
    enable_ebpf: bool,
    enable_honeypots: bool,
    enable_api_server: bool,
    enable_yara: bool,
    whitelist_processes: Vec<String>,
    critical_paths: Vec<String>,
}

impl SentinelConfig {
    fn validate(&self) -> Result<()> {
        for path in &self.critical_paths {
            if path.contains("..") || !path.starts_with('/') {
                return Err(anyhow::anyhow!("Invalid critical path: {}", path));
            }
        }
        Ok(())
    }
}

struct Sentinel {
    config: Arc<SentinelConfig>,
    yara_rules: Option<Arc<Rules>>,
}

impl Sentinel {
    fn new(config_path: &str) -> Result<Self> {
        let config_path = Path::new(config_path);
        if config_path.is_absolute() && !config_path.exists() {
            return Err(anyhow::anyhow!("Configuration file not found: {}", config_path.display()));
        }

        let config = Config::builder()
            .add_source(ConfigFile::with_name(config_path.to_str().context("Invalid config path")?))
            .build()
            .context("Failed to load configuration")?
            .try_deserialize::<SentinelConfig>()
            .context("Failed to deserialize configuration")?;

        config.validate().context("Configuration validation failed")?;

        let yara_rules = if config.enable_yara {
            let compiler = Compiler::new().context("Failed to create YARA compiler")?;
            let rules = compiler
                .add_rules_file("/opt/linux-sentinel/rules.yara")
                .context("Failed to load YARA rules")?
                .compile()
                .context("Failed to compile YARA rules")?;
            Some(Arc::new(rules))
        } else {
            None
        };

        // Apply seccomp filter
        let mut filter = SeccompFilter::new(SeccompAction::Errno(libc::EPERM))?;
        allow_syscall(&mut filter, libc::SYS_openat)?;
        allow_syscall(&mut filter, libc::SYS_read)?;
        allow_syscall(&mut filter, libc::SYS_write)?;
        allow_syscall(&mut filter, libc::SYS_close)?;
        allow_syscall(&mut filter, libc::SYS_fstat)?;
        allow_syscall(&mut filter, libc::SYS_getpid)?;
        allow_syscall(&mut filter, libc::SYS_socket)?;
        allow_syscall(&mut filter, libc::SYS_bind)?;
        allow_syscall(&mut filter, libc::SYS_listen)?;
        filter.apply().context("Failed to apply seccomp filter")?;

        Ok(Sentinel {
            config: Arc::new(config),
            yara_rules,
        })
    }

    async fn run_enhanced(&self) -> Result<()> {
        info!("Starting enhanced mode scan");
        let tasks = vec![
            tokio::spawn(self.clone().monitor_network()),
            tokio::spawn(self.clone().monitor_processes()),
            tokio::spawn(self.clone().monitor_files()),
            tokio::spawn(self.clone().monitor_users()),
            tokio::spawn(self.clone().monitor_rootkits()),
            tokio::spawn(self.clone().monitor_memory()),
        ];

        futures::future::try_join_all(tasks).await?;
        info!("Enhanced mode scan completed");
        Ok(())
    }

    async fn monitor_network(&self) -> Result<()> {
        if !self.config.monitor_network {
            info!("Network monitoring disabled");
            return Ok(());
        }
        info!("Monitoring network activity");
        let output = Command::new("ss")
            .arg("-tuln")
            .output()
            .context("Failed to execute ss")?;
        let log_path = Path::new(LOG_DIR).join("network.log");
        fs::write(&log_path, output.stdout)?;
        Ok(())
    }

    async fn monitor_processes(&self) -> Result<()> {
        if !self.config.monitor_processes {
            info!("Process monitoring disabled");
            return Ok(());
        }
        info!("Monitoring processes");
        let processes: Vec<_> = fs::read_dir("/proc")?
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let path = entry.path();
                if path.is_dir() && path.file_name()?.to_string().parse::<u32>().is_ok() {
                    Some(path)
                } else {
                    None
                }
            })
            .collect();

        processes.par_iter().for_each(|path| {
            if let Ok(status) = fs::read_to_string(path.join("status")) {
                if let Some(name) = status.lines().find(|line| line.starts_with("Name:")) {
                    let process_name = name.split_whitespace().nth(1).unwrap_or("");
                    if !self.config.whitelist_processes.contains(&process_name.to_string()) {
                        warn!("Suspicious process detected: {}", process_name);
                    }
                }
            }
        });
        Ok(())
    }

    async fn monitor_files(&self) -> Result<()> {
        if !self.config.monitor_files || !self.config.enable_yara || self.yara_rules.is_none() {
            info!("File monitoring or YARA disabled");
            return Ok(());
        }
        info!("Scanning critical files with YARA");
        let rules = self.yara_rules.as_ref().unwrap();
        for path in &self.config.critical_paths {
            let path = PathBuf::from(path);
            if path.exists() {
                let scanner = rules.scanner().context("Failed to create YARA scanner")?;
                let results = scanner.scan_file(&path).context("Failed to scan file with YARA")?;
                for result in results {
                    warn!("YARA rule match: {} on file {}", result.identifier, path.display());
                }
            }
        }
        Ok(())
    }

    async fn monitor_users(&self) -> Result<()> {
        if !self.config.monitor_users {
            info!("User monitoring disabled");
            return Ok(());
        }
        info!("Checking user accounts");
        let passwd = fs::read_to_string("/etc/passwd")?;
        for line in passwd.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() > 0 && parts[0] != "root" && parts[2].parse::<u32>().unwrap_or(9999) < 1000 {
                warn!("Low UID user detected: {}", parts[0]);
            }
        }
        Ok(())
    }

    async fn monitor_rootkits(&self) -> Result<()> {
        if !self.config.monitor_rootkits {
            info!("Rootkit monitoring disabled");
            return Ok(());
        }
        info!("Checking for rootkits");
        let suspicious_files = ["/bin/.hidden", "/usr/bin/.rootkit"];
        for file in suspicious_files {
            if Path::new(file).exists() {
                warn!("Potential rootkit file detected: {}", file);
            }
        }
        Ok(())
    }

    async fn monitor_memory(&self) -> Result<()> {
        if !self.config.monitor_memory {
            info!("Memory monitoring disabled");
            return Ok(());
        }
        info!("Checking memory usage");
        let meminfo = fs::read_to_string("/proc/meminfo")?;
        let total_mem = meminfo
            .lines()
            .find(|line| line.starts_with("MemTotal"))
            .and_then(|line| line.split_whitespace().nth(1).and_then(|s| s.parse::<u64>().ok()));
        if let Some(total) = total_mem {
            if total < 1_000_000 {
                warn!("Low system memory: {} kB", total);
            }
        }
        Ok(())
    }

    async fn run_honeypots(&self) -> Result<()> {
        if !self.config.enable_honeypots {
            info!("Honeypots disabled");
            return Ok(());
        }
        info!("Starting honeypot servers");
        let mut listeners = Vec::new();
        for &port in HONEYPOT_PORTS {
            let addr = format!("0.0.0.0:{}", port);
            let listener = TcpListener::bind(&addr)
                .await
                .context(format!("Failed to bind to port {}", port))?;
            listeners.push(listener);
            info!("Honeypot listening on port {}", port);
        }
        signal::ctrl_c().await?;
        Ok(())
    }

    async fn run_api(&self) -> Result<()> {
        if !self.config.enable_api_server {
            info!("API server disabled");
            return Ok(());
        }
        info!("Starting API server on port {}", API_PORT);
        let listener = TcpListener::bind(format!("0.0.0.0:{}", API_PORT)).await?;
        // Simplified API server (extend with actual endpoints as needed)
        loop {
            let (stream, _) = listener.accept().await?;
            tokio::spawn(async move {
                // Handle API requests (placeholder)
                let _ = stream;
            });
        }
    }

    async fn run_status(&self) -> Result<()> {
        info!("Checking status");
        let api_pid = Path::new(LOG_DIR).join("api_server.pid");
        if api_pid.exists() && fs::read_to_string(&api_pid).is_ok() {
            info!("API server running");
        } else {
            warn!("API server not running");
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_max_level(Level::INFO)
        .init();

    // Ensure directories exist
    fs::create_dir_all(LOG_DIR)?;
    fs::create_dir_all(BACKUP_DIR)?;

    let cli = Cli::parse();
    let sentinel = Sentinel::new("/opt/linux-sentinel/sentinel.conf")?;

    match cli.mode {
        Mode::Enhanced => sentinel.run_enhanced().await,
        Mode::Test => Ok(info!("Test mode: Configuration and environment validated")),
        Mode::Api => sentinel.run_api().await,
        Mode::Honeypot => sentinel.run_honeypots().await,
        Mode::Cleanup => Ok(info!("Cleanup not implemented")),
        Mode::Status => sentinel.run_status().await,
        Mode::Yara => sentinel.monitor_files().await,
        Mode::Ebpf => Ok(info!("eBPF monitoring not implemented")),
    }
}