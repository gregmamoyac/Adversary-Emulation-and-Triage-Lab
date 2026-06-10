<#
.SYNOPSIS
    Adversary Emulation: Suspicious Scheduled Task via Scripting Engine (MITRE T1053.005)

.DESCRIPTION
    Simulates an attacker creating a scheduled task whose action invokes a scripting
    engine (wscript.exe). This pattern is commonly used for persistence and is flagged
    by most modern EDR/SIEM rules because legitimate software rarely creates tasks
    this way.

    Artifacts generated:
      - Security EID 4698 : A scheduled task was created
      - Sysmon EID 1      : schtasks.exe process creation (parent tracking)
      - Task XML file     : C:\Windows\System32\Tasks\<TaskName>

    The script CLEANS UP after itself so your lab stays tidy.
    Set -SkipCleanup to leave the task for deeper forensic analysis.

.PARAMETER TaskName
    Name of the scheduled task to create. Default: "WindowsUpdateHelper"

.PARAMETER SkipCleanup
    If set, leaves the task in place after emulation (for triage practice).

.NOTES
    LAB USE ONLY. Run on isolated VM you own.
    MITRE ATT&CK: T1053.005 — Scheduled Task/Job: Scheduled Task
    Detection: Security EID 4698 | Sysmon EID 1 parent = wscript/cscript/mshta
#>

[CmdletBinding()]
param(
    [string]$TaskName    = "WindowsUpdateHelper",
    [switch]$SkipCleanup
)

Write-Host "`n[*] ADVERSARY EMULATION — Suspicious Scheduled Task via Scripting Engine" -ForegroundColor Cyan
Write-Host "[*] MITRE ATT&CK: T1053.005 — Scheduled Task/Job" -ForegroundColor Cyan
Write-Host "[*] This script generates DETECTABLE artifacts for lab use only.`n" -ForegroundColor Yellow

# ── Build a realistic-looking but benign task payload ─────────────────────────
# The VBS script is a no-op; we care about the TASK CREATION event, not execution
$vbsContent = @"
' Lab emulation payload — no-op script
' In a real attack this would be a dropper or C2 callback
WScript.Echo "Lab emulation: task triggered at " & Now()
"@

$vbsPath = "C:\ProgramData\WindowsUpdateHelper.vbs"

Write-Host "[1] Dropping benign VBS script to simulate attacker staging..."
Write-Host "    Path: $vbsPath" -ForegroundColor DarkYellow
$vbsContent | Out-File -FilePath $vbsPath -Encoding ASCII
Write-Host "    [+] VBS file created." -ForegroundColor Green

# ── Create the scheduled task ─────────────────────────────────────────────────
Write-Host "`n[2] Creating scheduled task via schtasks.exe (generates Security EID 4698)..."

# Technique: task action invokes wscript.exe — the suspicious parent-child pattern
$taskAction  = "wscript.exe //B `"$vbsPath`""
$taskCommand = @(
    "/create",
    "/tn", $TaskName,
    "/tr", $taskAction,
    "/sc", "onlogon",
    "/rl", "HIGHEST",
    "/f"   # Force overwrite if exists
)

Write-Host "    Command: schtasks.exe $($taskCommand -join ' ')" -ForegroundColor DarkYellow

$startTime = Get-Date

try {
    $output = & schtasks.exe @taskCommand 2>&1
    Write-Host "    schtasks output: $output" -ForegroundColor Gray
} catch {
    Write-Warning "schtasks execution failed: $_"
}

# ── Verify artifacts ──────────────────────────────────────────────────────────
Write-Host "`n[3] Verifying artifacts..."

# Check task XML in System32\Tasks
$taskXmlPath = "C:\Windows\System32\Tasks\$TaskName"
if (Test-Path $taskXmlPath) {
    Write-Host "    [+] Task XML created: $taskXmlPath" -ForegroundColor Green

    # Show the action node — this is what defenders look for
    [xml]$taskXml = Get-Content $taskXmlPath
    $actions = $taskXml.Task.Actions.Exec
    if ($actions) {
        Write-Host "    [+] Task Action (Exec):" -ForegroundColor Green
        Write-Host "        Command : $($actions.Command)" -ForegroundColor Gray
        Write-Host "        Arguments: $($actions.Arguments)" -ForegroundColor Gray
    }
} else {
    Write-Host "    [-] Task XML not found — may need elevation or UAC bypass in lab" -ForegroundColor Yellow
}

# Verify via Get-ScheduledTask
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($task) {
    Write-Host "    [+] Task confirmed via Get-ScheduledTask:" -ForegroundColor Green
    Write-Host "        State : $($task.State)" -ForegroundColor Gray
    Write-Host "        Author: $($task.Author)" -ForegroundColor Gray
}

$endTime = Get-Date

# ── Detection hunting summary ─────────────────────────────────────────────────
Write-Host "`n[4] DETECTION HUNTING SUMMARY" -ForegroundColor Cyan
Write-Host "    Execution window: $startTime — $endTime"
Write-Host ""
Write-Host "    Security EID 4698 (Task Created):" -ForegroundColor White
Write-Host "      TaskName: *UpdateHelper* OR TaskContent: *wscript*" -ForegroundColor Gray
Write-Host ""
Write-Host "    Sysmon EID 1 (Process Create):" -ForegroundColor White
Write-Host "      Image: *\schtasks.exe AND CommandLine: */create*" -ForegroundColor Gray
Write-Host "      ParentImage: *\wscript.exe OR *\cscript.exe OR *\mshta.exe" -ForegroundColor Gray
Write-Host ""
Write-Host "    Task XML Hunt (PowerShell):" -ForegroundColor White
Write-Host "      Get-ScheduledTask | Where {`$_.Actions.Execute -match 'wscript|cscript|mshta'}" -ForegroundColor Gray

# ── Cleanup ───────────────────────────────────────────────────────────────────
if (-not $SkipCleanup) {
    Write-Host "`n[5] Cleaning up lab artifacts..."
    schtasks.exe /delete /tn $TaskName /f 2>&1 | Out-Null
    Remove-Item $vbsPath -Force -ErrorAction SilentlyContinue
    Write-Host "    [+] Task and VBS file removed." -ForegroundColor Green
    Write-Host "    Note: Security EID 4698 log entry PERSISTS in Event Log (artifacts remain for triage)" -ForegroundColor Yellow
} else {
    Write-Host "`n[5] -SkipCleanup set — task and files left in place for triage practice." -ForegroundColor Yellow
    Write-Host "    Run triage\Get-ScheduledTaskAnomalies.ps1 to analyze." -ForegroundColor Yellow
}

Write-Host "`n[*] Emulation complete.`n" -ForegroundColor Cyan
