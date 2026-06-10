<#
.SYNOPSIS
    Master Endpoint Triage Script  Blue Team Detection Lab

.DESCRIPTION
    Orchestrates all triage modules against the local machine (or a remote lab VM).
    Collects event log IOCs, browser artifacts, scheduled task anomalies, prefetch
    evidence, and certutil cache artifacts. Outputs JSON + a human-readable report.

.PARAMETER OutputPath
    Directory to write triage output. Created if it doesn't exist.
    Default: C:\TriageOutput\<timestamp>

.PARAMETER Hours
    How many hours back to search for artifacts. Default: 24

.PARAMETER ComputerName
    Remote computer to triage (requires admin rights and WinRM). Default: localhost

.NOTES
    Run as Administrator on your lab VM.
    All queries are READ-ONLY  no changes made to the target system.
#>

[CmdletBinding()]
param(
    [string]$OutputPath   = "C:\TriageOutput\$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [int]   $Hours        = 24,
    [string]$ComputerName = $env:COMPUTERNAME
)

$ErrorActionPreference = "SilentlyContinue"
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

#  Setup 
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
$startTime = (Get-Date).AddHours(-$Hours)
$report    = [System.Collections.Generic.List[string]]::new()

function Write-Section {
    param([string]$Title)
    $line = "=" * 60
    Write-Host "`n$line" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host "$line" -ForegroundColor Cyan
    $script:report.Add("`n$line`n  $Title`n$line")
}

function Write-Finding {
    param([string]$Message, [string]$Severity = "INFO")
    $colors = @{ "HIGH" = "Red"; "MEDIUM" = "Yellow"; "LOW" = "Green"; "INFO" = "Gray" }
    $color  = $colors[$Severity]
    Write-Host "  [$Severity] $Message" -ForegroundColor $color
    $script:report.Add("  [$Severity] $Message")
}

Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host "  ENDPOINT TRIAGE  $ComputerName" -ForegroundColor Cyan
    Write-Host "  Timeframe: Last $Hours hours ($startTime - $(Get-Date))" -ForegroundColor Cyan
Write-Host "  Output: $OutputPath" -ForegroundColor Cyan
Write-Host "================================================================`n" -ForegroundColor Cyan

#  Module 1: Event Log IOCs 
Write-Section "MODULE 1: Event Log & Sysmon IOC Hunt"
$evtResults = & "$scriptRoot\Get-EventLogIOCs.ps1" -StartTime $startTime -OutputPath $OutputPath
$evtResults | ForEach-Object { Write-Finding $_ }

#  Module 2: Browser Artifacts 
Write-Section "MODULE 2: Browser History & Download Artifacts"
$browserResults = & "$scriptRoot\Get-BrowserArtifacts.ps1" -StartTime $startTime -OutputPath $OutputPath
$browserResults | ForEach-Object { Write-Finding $_ }

#  Module 3: Scheduled Task Anomalies 
Write-Section "MODULE 3: Scheduled Task Anomaly Scoring"
$taskResults = & "$scriptRoot\Get-ScheduledTaskAnomalies.ps1" -OutputPath $OutputPath
$taskResults | ForEach-Object { Write-Finding $_ }

#  Module 4: Prefetch Evidence 
Write-Section "MODULE 4: Prefetch  Execution Evidence"
$prefetchResults = & "$scriptRoot\Get-PrefetchEvidence.ps1" -StartTime $startTime -OutputPath $OutputPath
$prefetchResults | ForEach-Object { Write-Finding $_ }

#  Module 5: CertUtil Cache 
Write-Section "MODULE 5: CertUtil INetCache Artifacts"
$certResults = & "$scriptRoot\Get-CertUtilCache.ps1" -StartTime $startTime -OutputPath $OutputPath
$certResults | ForEach-Object { Write-Finding $_ }

#  Write Report 
Write-Section "TRIAGE COMPLETE"
$reportPath = "$OutputPath\triage_report.txt"
$report | Out-File -FilePath $reportPath -Encoding UTF8
Write-Host "  Full report saved: $reportPath" -ForegroundColor Green
Write-Host "  JSON artifacts in: $OutputPath\*.json" -ForegroundColor Green
Write-Host ""




