<#
.SYNOPSIS
    Get-EventLogIOCs - Hunt Windows Event Logs and Sysmon for emulation IOCs

.DESCRIPTION
    Queries Security, System, and Sysmon event logs for events matching the
    two emulated techniques. Read-only. Returns findings as strings for the
    master triage script to display, and writes raw events to JSON.

.NOTES
    Requires: Sysmon installed, Script Block Logging enabled for full coverage
    Run as: Administrator
#>

[CmdletBinding()]
param(
    [DateTime]$StartTime  = (Get-Date).AddHours(-24),
    [string]  $OutputPath = "C:\TriageOutput"
)

$findings = [System.Collections.Generic.List[string]]::new()
$allEvents = @()

function Add-Finding { param($msg, $sev="INFO") $findings.Add("[$sev] $msg") }

# -- Helper: safe event query --------------------------------------------------
function Get-EventsSafe {
    param([string]$LogName, [int[]]$EventIds, [DateTime]$After)
    try {
        $filterHash = @{
            LogName   = $LogName
            Id        = $EventIds
            StartTime = $After
        }
        Get-WinEvent -FilterHashtable $filterHash -ErrorAction Stop
    } catch {
        @()  # Log may not exist or Sysmon not installed
    }
}

# -- Security Log --------------------------------------------------------------
Add-Finding "Querying Security log (EID 4698 Task Created, 4688 Process Create)..."

# EID 4698: Scheduled task created
$taskCreated = Get-EventsSafe -LogName "Security" -EventIds 4698 -After $StartTime
foreach ($evt in $taskCreated) {
    $xml     = [xml]$evt.ToXml()
    $taskName    = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TaskName" }).'#text'
    $taskContent = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TaskContent" }).'#text'
    $subjectUser = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "SubjectUserName" }).'#text'

    $suspicious = $taskContent -match "wscript|cscript|mshta|powershell|cmd\.exe|rundll32"
    $sev = if ($suspicious) { "HIGH" } else { "LOW" }
    Add-Finding "EID 4698 - Task Created: '$taskName' by '$subjectUser' | ScriptEngine: $suspicious" -sev $sev
    $allEvents += [PSCustomObject]@{ Source="Security"; EID=4698; Time=$evt.TimeCreated; TaskName=$taskName; SuspiciousAction=$suspicious }
}
if ($taskCreated.Count -eq 0) { Add-Finding "EID 4698 - No scheduled task creation events found in window" }

# EID 4688: Process creation (if process auditing enabled)
$procCreate = Get-EventsSafe -LogName "Security" -EventIds 4688 -After $StartTime
$certutilProcs = $procCreate | Where-Object {
    $xml = [xml]$_.ToXml()
    $cmdline = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "CommandLine" }).'#text'
    $cmdline -match "certutil" -and $cmdline -match "urlcache"
}
foreach ($evt in $certutilProcs) {
    $xml     = [xml]$evt.ToXml()
    $cmdline = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "CommandLine" }).'#text'
    Add-Finding "EID 4688 - CertUtil URLcache: $cmdline" -sev "HIGH"
    $allEvents += [PSCustomObject]@{ Source="Security"; EID=4688; Time=$evt.TimeCreated; CommandLine=$cmdline }
}

# -- Sysmon Log ----------------------------------------------------------------
Add-Finding "Querying Sysmon log (EID 1 Process, EID 3 Network, EID 11 File)..."

# EID 1: Process Create - certutil with urlcache
$sysmonProc = Get-EventsSafe -LogName "Microsoft-Windows-Sysmon/Operational" -EventIds 1 -After $StartTime
$certutilSysmon = $sysmonProc | Where-Object {
    $xml = [xml]$_.ToXml()
    $img = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "Image" }).'#text'
    $cmd = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "CommandLine" }).'#text'
    ($img -match "certutil") -or ($cmd -match "certutil.*urlcache")
}
foreach ($evt in $certutilSysmon) {
    $xml        = [xml]$evt.ToXml()
    $image      = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "Image" }).'#text'
    $cmdline    = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "CommandLine" }).'#text'
    $parentImg  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "ParentImage" }).'#text'
    Add-Finding "Sysmon EID 1 - CertUtil: Image=$image | Parent=$parentImg" -sev "HIGH"
    Add-Finding "    CmdLine: $cmdline" -sev "INFO"
    $allEvents += [PSCustomObject]@{ Source="Sysmon"; EID=1; Time=$evt.TimeCreated; Image=$image; CommandLine=$cmdline; ParentImage=$parentImg }
}

# EID 1: Schtasks with /create
$schtasksSysmon = $sysmonProc | Where-Object {
    $xml = [xml]$_.ToXml()
    $cmd = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "CommandLine" }).'#text'
    $cmd -match "schtasks.*\/create"
}
foreach ($evt in $schtasksSysmon) {
    $xml        = [xml]$evt.ToXml()
    $cmdline    = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "CommandLine" }).'#text'
    $parentImg  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "ParentImage" }).'#text'
    $sev = if ($parentImg -match "wscript|cscript|mshta") { "HIGH" } else { "MEDIUM" }
    Add-Finding "Sysmon EID 1 - Schtasks Create | ParentImage: $parentImg" -sev $sev
    $allEvents += [PSCustomObject]@{ Source="Sysmon"; EID=1; Time=$evt.TimeCreated; CommandLine=$cmdline; ParentImage=$parentImg }
}

# EID 3: Network connection from certutil
$sysmonNet = Get-EventsSafe -LogName "Microsoft-Windows-Sysmon/Operational" -EventIds 3 -After $StartTime
$certutilNet = $sysmonNet | Where-Object {
    $xml   = [xml]$_.ToXml()
    $image = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "Image" }).'#text'
    $image -match "certutil"
}
foreach ($evt in $certutilNet) {
    $xml     = [xml]$evt.ToXml()
    $destIP  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "DestinationIp" }).'#text'
    $destPt  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "DestinationPort" }).'#text'
    $destHst = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "DestinationHostname" }).'#text'
    Add-Finding "Sysmon EID 3 - CertUtil Network: $destHst ($destIP):$destPt" -sev "HIGH"
    $allEvents += [PSCustomObject]@{ Source="Sysmon"; EID=3; Time=$evt.TimeCreated; Dest="$destHst ($destIP):$destPt" }
}

# EID 11: File creation in temp/INetCache
$sysmonFile = Get-EventsSafe -LogName "Microsoft-Windows-Sysmon/Operational" -EventIds 11 -After $StartTime
$suspFiles = $sysmonFile | Where-Object {
    $xml    = [xml]$_.ToXml()
    $target = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetFilename" }).'#text'
    $target -match "INetCache|\\Temp\\|\\AppData\\Local\\Temp"
}
foreach ($evt in $suspFiles) {
    $xml    = [xml]$evt.ToXml()
    $target = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "TargetFilename" }).'#text'
    $image  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "Image" }).'#text'
    Add-Finding "Sysmon EID 11 - Suspicious File Created: $target (by $image)" -sev "MEDIUM"
    $allEvents += [PSCustomObject]@{ Source="Sysmon"; EID=11; Time=$evt.TimeCreated; File=$target; CreatedBy=$image }
}

# -- PowerShell Script Block Log -----------------------------------------------
Add-Finding "Querying PowerShell Script Block log..."
$psSBL = Get-EventsSafe -LogName "Microsoft-Windows-PowerShell/Operational" -EventIds 4104 -After $StartTime
$suspPS = $psSBL | Where-Object {
    $_.Message -match "certutil|schtasks|urlcache|IEX|Invoke-Expression|DownloadString|WebClient"
}
foreach ($evt in $suspPS) {
    $snippet = ($evt.Message -split "`n")[0..2] -join " "
    Add-Finding "PSScriptBlock EID 4104 - Suspicious: $snippet" -sev "MEDIUM"
}

# -- Write JSON ----------------------------------------------------------------
$jsonPath = "$OutputPath\eventlog_iocs.json"
$allEvents | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonPath -Encoding UTF8
Add-Finding "Event log results saved: $jsonPath"

Add-Finding "Event Log module complete. Total IOC events: $($allEvents.Count)"
return $findings
