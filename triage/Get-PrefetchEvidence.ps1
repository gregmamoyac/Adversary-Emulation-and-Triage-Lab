<#
.SYNOPSIS
    Get-PrefetchEvidence - Parse Windows Prefetch for execution evidence

.DESCRIPTION
    Enumerates prefetch files to surface executables that ran recently,
    focusing on binaries executing from suspicious paths (Temp, AppData,
    ProgramData, Downloads) and known LOLBINS used by attackers.

    Prefetch stores the last 8 run times per executable and the list of
    DLLs/files loaded - a goldmine for confirming whether a binary actually
    ran, even if logs were cleared.

    Note: Prefetch must be enabled (it is by default on workstation SKUs).
    On Server SKUs it is often disabled. The script will report if unavailable.

.NOTES
    Run as: Administrator (prefetch files are in C:\Windows\Prefetch)
    Read-only - no files are modified.
    For deep prefetch parsing, install PECmd.exe (Eric Zimmerman):
      https://github.com/EricZimmerman/PECmd
#>

[CmdletBinding()]
param(
    [DateTime]$StartTime  = (Get-Date).AddHours(-24),
    [string]  $OutputPath = "C:\TriageOutput"
)

$findings = [System.Collections.Generic.List[string]]::new()
$results  = @()

function Add-Finding { param($msg, $sev="INFO") $findings.Add("[$sev] $msg") }

$prefetchPath = "C:\Windows\Prefetch"

# LOLBINS of interest for this emulation scenario
$lolbins = @(
    "CERTUTIL.EXE", "WSCRIPT.EXE", "CSCRIPT.EXE", "MSHTA.EXE",
    "SCHTASKS.EXE", "REGSVR32.EXE", "RUNDLL32.EXE", "MSIEXEC.EXE",
    "BITSADMIN.EXE", "POWERSHELL.EXE", "CMD.EXE", "WMIC.EXE",
    "MSBUILD.EXE", "INSTALLUTIL.EXE", "REGASM.EXE"
)

$suspiciousPathFragments = @(
    "TEMP", "APPDATA", "PROGRAMDATA", "DOWNLOADS", "PUBLIC", "RECYCLE"
)

# -- Check prefetch availability -----------------------------------------------
if (-not (Test-Path $prefetchPath)) {
    Add-Finding "Prefetch directory not found - may be disabled (common on Server SKUs)" -sev "MEDIUM"
    Add-Finding "To enable: reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' /v EnablePrefetcher /t REG_DWORD /d 3 /f"
    return $findings
}

# -- Enumerate prefetch files ---------------------------------------------------
Add-Finding "Enumerating prefetch files in $prefetchPath..."
$pfFiles = Get-ChildItem $prefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue |
           Sort-Object LastWriteTime -Descending

Add-Finding "Total prefetch files found: $($pfFiles.Count)"

# -- Check for PECmd (Eric Zimmerman) for deep parsing -------------------------
$pecmd = Get-Command PECmd.exe -ErrorAction SilentlyContinue
if ($pecmd) {
    Add-Finding "PECmd.exe found - using for deep prefetch parsing" -sev "INFO"
    $pecmdOut = "$OutputPath\pecmd_output.csv"
    & PECmd.exe -d $prefetchPath --csv $OutputPath --csvf pecmd_output.csv -q 2>&1 | Out-Null
    Add-Finding "PECmd output written to: $pecmdOut"
} else {
    Add-Finding "PECmd.exe not found - using lightweight LastWriteTime analysis only" -sev "INFO"
    Add-Finding "For full prefetch parsing install PECmd: https://github.com/EricZimmerman/PECmd"
}

# -- Lightweight analysis: LastWriteTime + filename parsing --------------------
# Prefetch filenames: EXECUTABLE-HASH.pf - LastWriteTime = last execution time
foreach ($pf in $pfFiles) {
    $exeName = ($pf.BaseName -split "-")[0]  # Strip the hash suffix
    $lastRun = $pf.LastWriteTime

    # Only report executions in our triage window
    if ($lastRun -lt $StartTime) { continue }

    $isLolbin    = $lolbins -contains $exeName.ToUpper()
    $sev         = "LOW"
    $flags       = @()

    if ($isLolbin) {
        $flags += "LOLBIN"
        $sev    = "MEDIUM"
    }

    # Flag certutil specifically - our primary emulation technique
    if ($exeName -match "CERTUTIL") {
        $sev    = "HIGH"
        $flags += "CertUtil-Execution-Confirmed"
    }

    if ($exeName -match "WSCRIPT|CSCRIPT|MSHTA") {
        $sev    = "HIGH"
        $flags += "ScriptingEngine-Confirmed"
    }

    $obj = [PSCustomObject]@{
        Executable = $exeName
        PfFile     = $pf.Name
        LastRun    = $lastRun.ToString("o")
        IsLolbin   = $isLolbin
        Flags      = $flags -join "|"
        Severity   = $sev
    }
    $results += $obj

    if ($sev -in @("HIGH","MEDIUM")) {
        Add-Finding "PREFETCH HIT: $exeName | LastRun: $lastRun | Flags: $($flags -join ', ')" -sev $sev
    }
}

if ($results.Count -eq 0) {
    Add-Finding "No notable prefetch hits in timeframe (executables may not have run yet)" -sev "INFO"
}

# -- Summary -------------------------------------------------------------------
$highCount = ($results | Where-Object { $_.Severity -eq "HIGH" }).Count
Add-Finding "Prefetch summary - $($results.Count) executions in window | HIGH severity: $highCount"

# -- Write JSON ----------------------------------------------------------------
$jsonPath = "$OutputPath\prefetch_evidence.json"
$results | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonPath -Encoding UTF8
Add-Finding "Prefetch results saved: $jsonPath"

return $findings
