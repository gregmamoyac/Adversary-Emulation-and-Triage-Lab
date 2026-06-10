# Lab Environment Setup Guide

This guide walks through standing up the isolated Windows VM lab needed to run the adversary emulation and triage exercises in this repo.

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│          Host Machine (your workstation)        │
│                                                 │
│  ┌───────────────────────────────────────────┐  │
│  │   Windows 10/11 VM  (isolated network)    │  │
│  │                                           │  │
│  │   Sysmon v15    ← endpoint telemetry      │  │
│  │   Winlogbeat    ← ships logs to SIEM      │  │
│  │   SQLite3 CLI   ← browser artifact parse  │  │
│  │   PECmd.exe     ← prefetch deep parse     │  │
│  │                                           │  │
│  └───────────────────────────────────────────┘  │
│           │ Winlogbeat / Log shipping            │
│  ┌────────▼───────────────────────────────────┐  │
│  │   Elastic SIEM / Splunk / WEF              │  │
│  └────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

---

## Step 1 — Create an Isolated Windows VM

Use any hypervisor (VMware, VirtualBox, Hyper-V).

**Critical: isolate the network.** Options:
- Host-only adapter (no internet — certutil technique won't make real network connection, but artifacts still generate)
- NAT adapter pointed to a local IIS/Apache server you control for the certutil download target
- Dedicated lab VLAN with internet access (most realistic, but ensure no production systems are reachable)

**Recommended VM spec:**
- Windows 10 or 11 (workstation SKU — prefetch is enabled by default)
- 4 GB RAM, 60 GB disk
- PowerShell 5.1 or higher
- .NET 4.7+

---

## Step 2 — Install and Configure Sysmon

Sysmon is free from Microsoft Sysinternals and provides the process creation, network connection, and file creation events this lab relies on.

```powershell
# Download Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
Expand-Archive "$env:TEMP\Sysmon.zip" -DestinationPath "$env:TEMP\Sysmon"

# Download SwiftOnSecurity config (community-maintained, high signal)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "$env:TEMP\sysmonconfig.xml"

# Install with config (run as Administrator)
& "$env:TEMP\Sysmon\Sysmon64.exe" -accepteula -i "$env:TEMP\sysmonconfig.xml"
```

Verify Sysmon is running:
```powershell
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

---

## Step 3 — Enable Windows Audit Policies

These policies populate the Security event log with EID 4698 (task created) and EID 4688 (process create).

```powershell
# Run as Administrator
# Enable process creation auditing (needed for EID 4688)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# Enable scheduled task auditing (needed for EID 4698)
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable

# Enable command line logging in process creation events
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

Enable PowerShell Script Block Logging:
```powershell
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item $regPath -Force | Out-Null
Set-ItemProperty $regPath -Name EnableScriptBlockLogging -Value 1
```

---

## Step 4 — Install SQLite3 CLI

Required for the browser history triage module to query Chrome/Edge/Firefox SQLite databases.

1. Download `sqlite-tools-win32` from https://www.sqlite.org/download.html
2. Extract `sqlite3.exe` to `C:\Windows\System32\` or any directory on your PATH
3. Verify: `sqlite3 --version`

---

## Step 5 — Install PECmd (Optional but Recommended)

Eric Zimmerman's PECmd provides deep prefetch parsing including loaded file lists and all 8 run times per executable.

1. Download from https://github.com/EricZimmerman/PECmd/releases
2. Place `PECmd.exe` on your PATH
3. The triage script auto-detects it and uses it if available

---

## Step 6 — Set Up a SIEM (Optional)

For full SIEM alert validation, set up one of these free options:

**Elastic SIEM (recommended):**
- Deploy Elastic Stack with the free tier
- Install Winlogbeat on the VM to ship Sysmon + Security logs
- Import the provided Sigma rules as Kibana detection rules

**Splunk Free:**
- Install Splunk Universal Forwarder on the VM
- Convert Sigma rules with `sigma convert -t splunk`

**Windows Event Forwarding (no third-party software):**
- Configure WEF subscription from a collector machine
- Forward Security, System, Sysmon/Operational channels

---

## Step 7 — Clone the Repo and Run

```powershell
git clone https://github.com/YOUR_USERNAME/blueteam-lab.git
cd blueteam-lab

# Set execution policy for the lab session
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

# Confirm Sysmon and audit policies are active, then:
.\adversary-emulation\run_emulation.bat    # Step 1: generate artifacts
# ... check SIEM alerts ...
.\run_triage.bat                           # Step 2: triage the endpoint
```

---

## Verification Checklist

Before running the emulation, confirm:

- [ ] VM is on an isolated network adapter
- [ ] Sysmon service is running (`Get-Service Sysmon64`)
- [ ] Security audit policies enabled (`auditpol /get /category:*`)
- [ ] PowerShell Script Block Logging enabled
- [ ] sqlite3.exe on PATH (`sqlite3 --version`)
- [ ] SIEM receiving events (check for any recent Sysmon EID 1 in your SIEM)
