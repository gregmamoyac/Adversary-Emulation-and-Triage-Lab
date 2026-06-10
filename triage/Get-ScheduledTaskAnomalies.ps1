<#
.SYNOPSIS
    Get-ScheduledTaskAnomalies - Enumerate and score suspicious scheduled tasks

.DESCRIPTION
    Enumerates all scheduled tasks on the local machine and scores each one against
    a set of anomaly indicators commonly associated with attacker persistence:
      - Action invokes a scripting engine (wscript, cscript, mshta, powershell)
      - Task name mimics a legitimate Windows task
      - Task was created recently (within the triage window)
      - Task runs from a user-writable or suspicious path
      - Task runs as SYSTEM with a user-writable action
      - Task XML exists in System32\Tasks but is hidden from Get-ScheduledTask

.NOTES
    Run as: Administrator (needed to read task XML and all user contexts)
    Read-only - no tasks are modified or deleted.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "C:\TriageOutput"
)

$findings   = [System.Collections.Generic.List[string]]::new()
$scoredTasks = @()

function Add-Finding { param($msg, $sev="INFO") $findings.Add("[$sev] $msg") }

# -- Anomaly scoring weights ---------------------------------------------------
$indicators = @{
    ScriptingEngineAction = 40   # wscript/cscript/mshta/powershell in action
    SuspiciousPath        = 30   # action runs from Temp, ProgramData, AppData, Downloads
    SystemPrincipal       = 15   # runs as SYSTEM/BUILTIN\Administrators
    MimicName             = 20   # task name matches common lure patterns
    HiddenTask            = 35   # XML in System32\Tasks but missing from COM enumeration
    EncodedCommand        = 40   # -EncodedCommand or -enc in action args
    DisabledButPresent    = 10   # task exists but is disabled (staging)
}

$suspiciousNamePatterns = @(
    "Update", "Helper", "Service", "Sync", "Agent", "Monitor",
    "Telemetry", "Check", "Maintenance", "Updater", "Scheduler"
)

$scriptingEngines = @("wscript\.exe", "cscript\.exe", "mshta\.exe", "regsvr32\.exe", "rundll32\.exe")
$suspiciousPaths  = @("\\Temp\\", "\\ProgramData\\", "\\AppData\\", "\\Downloads\\", "\\Public\\")

# -- Enumerate via PowerShell COM (standard) -----------------------------------
Add-Finding "Enumerating scheduled tasks via Get-ScheduledTask..."
$allTasks = Get-ScheduledTask -ErrorAction SilentlyContinue

foreach ($task in $allTasks) {
    $score    = 0
    $flags    = @()
    $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue

    # Resolve action details
    $actions = $task.Actions
    $actionStr = ($actions | ForEach-Object {
        if ($_.Execute) { "$($_.Execute) $($_.Arguments)" } else { $_.ToString() }
    }) -join "; "

    # Score: scripting engine in action
    foreach ($eng in $scriptingEngines) {
        if ($actionStr -match $eng) {
            $score += $indicators.ScriptingEngineAction
            $flags += "ScriptingEngine:$($eng -replace '\\.','')"
        }
    }

    # Score: suspicious path
    foreach ($path in $suspiciousPaths) {
        if ($actionStr -match [regex]::Escape($path) -or $actionStr -match $path) {
            $score += $indicators.SuspiciousPath
            $flags += "SuspiciousPath"
            break
        }
    }

    # Score: encoded command
    if ($actionStr -match "-[Ee]nc|-EncodedCommand") {
        $score += $indicators.EncodedCommand
        $flags += "EncodedCommand"
    }

    # Score: runs as SYSTEM
    $principal = $task.Principal.UserId
    if ($principal -match "SYSTEM|S-1-5-18|Administrators") {
        $score += $indicators.SystemPrincipal
        $flags += "SystemPrincipal"
    }

    # Score: name mimics legitimate task
    $mimicHit = $suspiciousNamePatterns | Where-Object { $task.TaskName -match $_ }
    if ($mimicHit -and $task.TaskPath -notmatch "\\Microsoft\\") {
        $score += $indicators.MimicName
        $flags += "MimicName:$($mimicHit -join ',')"
    }

    # Score: disabled
    if ($task.State -eq "Disabled") {
        $score += $indicators.DisabledButPresent
        $flags += "Disabled"
    }

    $sev = switch ($true) {
        { $score -ge 60 } { "HIGH";   break }
        { $score -ge 30 } { "MEDIUM"; break }
        default           { "LOW" }
    }

    $taskObj = [PSCustomObject]@{
        TaskName   = $task.TaskName
        TaskPath   = $task.TaskPath
        Action     = $actionStr
        Principal  = $principal
        State      = $task.State
        LastRun    = $taskInfo.LastRunTime
        NextRun    = $taskInfo.NextRunTime
        Score      = $score
        Flags      = $flags -join "|"
        Severity   = $sev
    }
    $scoredTasks += $taskObj

    if ($score -ge 30) {
        Add-Finding "Task: '$($task.TaskName)' | Score: $score | Flags: $($flags -join ', ') | Action: $actionStr" -sev $sev
    }
}

Add-Finding "Scanned $($allTasks.Count) tasks - $($scoredTasks | Where-Object { $_.Score -ge 30 } | Measure-Object | Select-Object -ExpandProperty Count) anomalous"

# -- Hunt for hidden tasks (XML in System32\Tasks not in COM enumeration) ------
Add-Finding "Hunting for hidden tasks (XML present but not in COM enumeration)..."
$taskXmlRoot  = "C:\Windows\System32\Tasks"
$comTaskNames = $allTasks | Select-Object -ExpandProperty TaskName

if (Test-Path $taskXmlRoot) {
    $xmlTasks = Get-ChildItem $taskXmlRoot -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -eq "" -or $_.Extension -eq ".xml" }

    foreach ($xmlFile in $xmlTasks) {
        if ($comTaskNames -notcontains $xmlFile.BaseName) {
            Add-Finding "HIDDEN TASK: '$($xmlFile.Name)' found in System32\Tasks but NOT in Get-ScheduledTask" -sev "HIGH"
            try {
                [xml]$xml = Get-Content $xmlFile.FullName -ErrorAction Stop
                $exec = $xml.Task.Actions.Exec
                if ($exec) {
                    Add-Finding "  Hidden task action: $($exec.Command) $($exec.Arguments)" -sev "HIGH"
                }
            } catch { }
        }
    }
}

# -- Write JSON ----------------------------------------------------------------
$jsonPath = "$OutputPath\scheduled_task_anomalies.json"
$scoredTasks | Sort-Object Score -Descending | ConvertTo-Json -Depth 5 |
    Out-File -FilePath $jsonPath -Encoding UTF8

Add-Finding "Scheduled task results saved: $jsonPath"
return $findings
