# Windows EDR Hunting Toolkit

A high-performance PowerShell Endpoint Detection and Response (EDR) hunting script. This toolkit is designed to detect advanced evasion techniques, fileless malware, and stealthy persistence mechanisms across Windows environments.

## Features

* **Deep Fileless Hunting:** Detects WMI Event Subscriptions, advanced Registry hooks (IFEO, AppInit_DLLs), COM Hijacking, and malicious BITS jobs.
* **Memory & Process Evasion:** Identifies hidden processes (API vs. WMI discrepancies), reflective DLL injection, and unusual parent-child process relationships.
* **Defense Evasion Detection:** Spots ETW Autologger disabling, AMSI provider tampering, and `PendingFileRenameOperations` (MoveEDR-style evasion).
* **BYOVD (Bring Your Own Vulnerable Driver) Detection:** Scans loaded kernel drivers against a known-vulnerable list, with an option to pull live updates from `loldrivers.io`.
* **High-Speed File Analysis:** Utilizes PowerShell Runspace Thread Pools to rapidly scan directories for file cloaking (Standard I/O vs. Memory-Mapped I/O), high Shannon entropy (packed/encrypted payloads), timestomping, and NTFS Alternate Data Streams (ADS).
* **SIEM-Ready Output:** Automatically maps all findings to MITRE ATT&CK tactics and exports them as CSV, JSON, and styled HTML reports.

---

## Development & Building

This project uses a modular development structure to ensure maintainability and CI/CD readiness. **Do not edit the monolithic release script directly.** All development happens in the `dev/` directory:
* `dev/src/` - Contains the individual numbered modules.
* `dev/tests/` - Contains the Pester 5 test suite with mocked API calls.
* `dev/Build-Toolkit.ps1` - Compiles the modules into the final deployable payload.
* `dev/Run-Tests.ps1` - Executes the test suite to validate logic before compilation.

**To build a new release:**
1. Make your changes in the `dev/src/` modules.
2. Run `.\dev\Run-Tests.ps1` to ensure no logic regressions.
3. Run `.\dev\Build-Toolkit.ps1` to generate the monolithic `EDR_Toolkit_Deploy.ps1` in the `Release/` folder.

---

## Usage

Run the compiled release script from an **Elevated (Administrator)** PowerShell prompt.

**1. Full System Memory & Fileless Scan (Fastest)**
Runs all memory, registry, and fileless checks without crawling the hard drive.
```powershell
.\Release\EDR_Toolkit_Deploy.ps1 -ScanProcesses -ScanFileless -ScanTasks -ScanDrivers -ScanInjection -ScanRegistry -ScanETWAMSI -ScanPendingRename -ScanBITS -ScanCOM
```

**2. Deep Target Directory Scan (File Evasion)**
Recursively scans the `C:\` drive utilizing the heavily optimized multithreaded engine, while filtering for High/Critical alerts only.
```powershell
.\Release\EDR_Toolkit_Deploy.ps1 -TargetDirectory "C:\" -Recursive -ScanADS -QuickMode -SeverityFilter Critical,High
```

**3. Enterprise WinRM Deployment (Silent)**
Deploy over the network without console spam, outputting only JSON for SIEM ingestion.
```powershell
Invoke-Command -ComputerName SRV-WEB-01 -FilePath ".\Release\EDR_Toolkit_Deploy.ps1" -ArgumentList @("-ScanProcesses", "-ScanFileless", "-Quiet", "-OutputFormat", "JSON")
```

---

## Command-Line Parameters

### Hunt Modules
| Parameter | Description |
| :--- | :--- |
| `-ScanProcesses` | Hunts for hidden processes, unusual parents, and suspicious command lines (LOLBins). |
| `-ScanInjection` | Looks for reflective DLLs, foreign modules, and process hollowing indicators. |
| `-ScanFileless` | Checks classic WMI subscriptions and user/system Run keys. |
| `-ScanRegistry` | Expanded registry hunting (IFEO, AppInit_DLLs, suspicious Services). |
| `-ScanTasks` | Analyzes Scheduled Tasks for malicious triggers and actions. |
| `-ScanDrivers` | Checks loaded kernel drivers against known BYOVD hashes/names. |
| `-ScanBITS` | Finds suspicious or non-standard Background Intelligent Transfer Service jobs. |
| `-ScanCOM` | Hunts for COM hijacking via `CLSID InProcServer32` hooks. |
| `-ScanETWAMSI` | Detects disabled ETW Autologgers and tampered AMSI registry keys. |
| `-ScanPendingRename`| Checks for `PendingFileRenameOperations` often used by malware to delete EDR agents on reboot. |

### File Scanning Options
| Parameter | Description |
| :--- | :--- |
| `-TargetDirectory <Path>` | The root folder to begin file-based hunts (entropy, cloaking, timestomping). |
| `-Recursive` | Crawls all subdirectories within the `-TargetDirectory`. |
| `-ScanADS` | Specifically hunts for NTFS Alternate Data Streams (hidden files within files). |
| `-QuickMode` | **Highly Recommended.** Reduces the entropy sample size and skips massive files to vastly speed up disk scans. |

### Global & Filtering Options
| Parameter | Description |
| :--- | :--- |
| `-AutoUpdateDrivers` | Reaches out to the `loldrivers.io` API to fetch the latest vulnerable driver list. |
| `-ReportPath <Path>` | Directory where reports will be saved (Default: Current Directory). |
| `-ExcludePaths` | Array of strings. Skips specific folders during disk scans. Ex: `-ExcludePaths "C:\Docker", "C:\Apps"` |
| `-SeverityFilter` | Array of strings. Restricts output. Ex: `-SeverityFilter Critical,High` |
| `-OutputFormat` | Restricts the generated report files. Options: `All`, `JSON`, `CSV`, `HTML`. |
| `-Quiet` | Suppresses console chatter and progress bars. Ideal for automated tasks via Orchestrator or GPO. |
| `-TestMode` | Skips all scans and injects simulated findings to test SIEM ingestion and alert rules. |

---

## Outputs

Upon completion, the toolkit automatically generates a timestamped package (based on `-OutputFormat`) and prints a **Top 10 Findings Summary** to the console.
