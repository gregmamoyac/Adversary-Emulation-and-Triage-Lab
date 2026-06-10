<#
.SYNOPSIS
    Get-BrowserArtifacts - Triage browser history and downloads on a lab/authorized endpoint

.DESCRIPTION
    Reads browser history and download records from Chrome, Edge, and Firefox on the
    local machine. Filters to a specific time window to correlate with adversary
    emulation events (e.g., was the machine visiting suspicious URLs around the time
    certutil made a network connection?).

    This script is READ-ONLY. It copies the SQLite DB to a temp path before querying
    so the live browser lock is not a problem, and makes no changes to the source files.

    Artifacts queried:
      - Chrome/Edge: %LOCALAPPDATA%\...\User Data\Default\History  (SQLite)
      - Firefox:     %APPDATA%\Mozilla\Firefox\Profiles\*.default\places.sqlite (SQLite)
      - Downloads:   %USERPROFILE%\Downloads\  (filesystem enumeration)
      - INetCache:   %LOCALAPPDATA%\Microsoft\Windows\INetCache\ (certutil drops here)

    AUTHORIZATION NOTE: Only run on machines you own or are explicitly authorized to
    investigate (your own lab VM, or an employee's endpoint with IR authorization).

.PARAMETER StartTime
    Only return browser artifacts newer than this time.

.PARAMETER OutputPath
    Directory to write JSON output.

.PARAMETER ProfileUser
    Username whose profile to query. Defaults to current user.
    For authorized IR on a coworker's machine, pass their username.

.NOTES
    Requires sqlite3.exe on PATH, OR the script will fall back to partial parsing.
    Download sqlite3: https://www.sqlite.org/download.html
    Run as: Administrator (needed to access other users' AppData)
#>

[CmdletBinding()]
param(
    [DateTime]$StartTime    = (Get-Date).AddHours(-24),
    [string]  $OutputPath   = "C:\TriageOutput",
    [string]  $ProfileUser  = $env:USERNAME
)

$findings  = [System.Collections.Generic.List[string]]::new()
$allArtifacts = @()

function Add-Finding { param($msg, $sev="INFO") $findings.Add("[$sev] $msg") }

# -- Resolve user profile path -------------------------------------------------
# Supports triaging another user's profile when running as admin
$userProfile = if ($ProfileUser -eq $env:USERNAME) {
    $env:USERPROFILE
} else {
    "C:\Users\$ProfileUser"
}

if (-not (Test-Path $userProfile)) {
    Add-Finding "User profile not found: $userProfile - check username or run as admin" -sev "MEDIUM"
    return $findings
}

Add-Finding "Triaging browser artifacts for user: $ProfileUser ($userProfile)"

# -- SQLite helper -------------------------------------------------------------
# We copy the DB to temp before querying - browsers lock their files
function Invoke-SqliteQuery {
    param([string]$DbPath, [string]$Query)
    if (-not (Test-Path $DbPath)) { return $null }

    $tempDb = "$env:TEMP\triage_browser_$(Get-Random).db"
    try {
        Copy-Item $DbPath $tempDb -Force

        # Try sqlite3.exe if available
        $sqlite3 = Get-Command sqlite3.exe -ErrorAction SilentlyContinue
        if ($sqlite3) {
            $result = & sqlite3.exe $tempDb $Query 2>&1
            return $result
        } else {
            Add-Finding "sqlite3.exe not found on PATH - install from https://sqlite.org/download.html for full browser history parsing" -sev "INFO"
            return $null
        }
    } finally {
        Remove-Item $tempDb -Force -ErrorAction SilentlyContinue
    }
}

# Chrome/Edge epoch is microseconds since 1601-01-01
# Convert to .NET DateTime for comparison
function Convert-ChromeTime {
    param([long]$ChromeEpoch)
    [datetime]"1601-01-01" + [timespan]::FromMicroseconds($ChromeEpoch)
}

# Firefox epoch is microseconds since Unix epoch (1970-01-01)
function Convert-FirefoxTime {
    param([long]$FFEpoch)
    [datetime]"1970-01-01" + [timespan]::FromMicroseconds($FFEpoch)
}

# -- Chrome & Edge -------------------------------------------------------------
Add-Finding "Scanning Chrome and Edge browser history..."

$chromiumProfiles = @(
    @{ Browser="Chrome"; Path="$userProfile\AppData\Local\Google\Chrome\User Data" },
    @{ Browser="Edge";   Path="$userProfile\AppData\Local\Microsoft\Edge\User Data" }
)

foreach ($browser in $chromiumProfiles) {
    if (-not (Test-Path $browser.Path)) {
        Add-Finding "$($browser.Browser) - not installed or profile not found" -sev "INFO"
        continue
    }

    # Get all profiles (Default + Profile 1, Profile 2, etc.)
    $profiles = @("Default") + (Get-ChildItem $browser.Path -Directory -ErrorAction SilentlyContinue |
                  Where-Object { $_.Name -match "^Profile \d+" } | Select-Object -ExpandProperty Name)

    foreach ($profileName in $profiles) {
        $historyDb = "$($browser.Path)\$profileName\History"
        if (-not (Test-Path $historyDb)) { continue }

        Add-Finding "$($browser.Browser) [$profileName] - History DB found: $historyDb"

        # Chrome stores time as microseconds since 1601. Convert StartTime to Chrome epoch.
        $startChrome = [long](($StartTime - [datetime]"1601-01-01").TotalMicroseconds)

        # Query: URLs visited since StartTime
        $urlQuery = "SELECT url, title, visit_count, datetime((last_visit_time/1000000)-11644473600,'unixepoch','localtime') as last_visit FROM urls WHERE last_visit_time > $startChrome ORDER BY last_visit_time DESC LIMIT 200;"
        $urlRows  = Invoke-SqliteQuery -DbPath $historyDb -Query $urlQuery

        if ($urlRows) {
            $visitCount = ($urlRows | Measure-Object).Count
            Add-Finding "$($browser.Browser) [$profileName] - $visitCount URL visits in timeframe" -sev "INFO"

            # Flag suspicious patterns relevant to certutil emulation
            $suspURLs = $urlRows | Where-Object {
                $_ -match "\.exe|\.ps1|\.bat|\.vbs|\.dll|pastebin|raw\.github|transfer\.sh|file\.io|ngrok|\.onion"
            }
            foreach ($url in $suspURLs) {
                Add-Finding "$($browser.Browser) SUSPICIOUS URL: $url" -sev "HIGH"
            }

            # Save all URLs to JSON for timeline correlation
            $urlRows | ForEach-Object {
                $parts = $_ -split "\|"
                $allArtifacts += [PSCustomObject]@{
                    Source  = "$($browser.Browser)/$profileName"
                    Type    = "URL"
                    Value   = if ($parts.Count -ge 1) { $parts[0] } else { $_ }
                    Title   = if ($parts.Count -ge 2) { $parts[1] } else { "" }
                    Time    = if ($parts.Count -ge 4) { $parts[3] } else { "" }
                }
            }
        }

        # Query: Downloads since StartTime
        $dlQuery  = "SELECT target_path, tab_url, datetime((start_time/1000000)-11644473600,'unixepoch','localtime') as dl_time, total_bytes, danger_type FROM downloads WHERE start_time > $startChrome ORDER BY start_time DESC LIMIT 100;"
        $dlRows   = Invoke-SqliteQuery -DbPath $historyDb -Query $dlQuery

        if ($dlRows) {
            $dlCount = ($dlRows | Measure-Object).Count
            Add-Finding "$($browser.Browser) [$profileName] - $dlCount downloads in timeframe" -sev "INFO"
            foreach ($dl in $dlRows) {
                $sev = if ($dl -match "\.exe|\.ps1|\.bat|\.vbs|\.dll|\.zip|\.rar") { "HIGH" } else { "LOW" }
                Add-Finding "$($browser.Browser) DOWNLOAD: $dl" -sev $sev
                $allArtifacts += [PSCustomObject]@{
                    Source = "$($browser.Browser)/$profileName"
                    Type   = "Download"
                    Value  = $dl
                    Time   = ""
                }
            }
        }
    }
}

# -- Firefox -------------------------------------------------------------------
Add-Finding "Scanning Firefox browser history..."
$ffProfileRoot = "$userProfile\AppData\Roaming\Mozilla\Firefox\Profiles"

if (Test-Path $ffProfileRoot) {
    $ffProfiles = Get-ChildItem $ffProfileRoot -Directory -ErrorAction SilentlyContinue
    foreach ($ffProf in $ffProfiles) {
        $placesDb = "$($ffProf.FullName)\places.sqlite"
        if (-not (Test-Path $placesDb)) { continue }

        Add-Finding "Firefox [$($ffProf.Name)] - places.sqlite found"

        # Firefox uses microseconds since Unix epoch
        $startFF = [long](($StartTime - [datetime]"1970-01-01").TotalMicroseconds)

        $ffQuery = "SELECT p.url, p.title, datetime(h.visit_date/1000000,'unixepoch','localtime') as visit_time FROM moz_historyvisits h JOIN moz_places p ON h.place_id = p.id WHERE h.visit_date > $startFF ORDER BY h.visit_date DESC LIMIT 200;"
        $ffRows  = Invoke-SqliteQuery -DbPath $placesDb -Query $ffQuery

        if ($ffRows) {
            Add-Finding "Firefox [$($ffProf.Name)] - $($ffRows.Count) visits in timeframe"
            $suspFF = $ffRows | Where-Object { $_ -match "\.exe|\.ps1|\.bat|\.vbs|pastebin|raw\.github|transfer\.sh" }
            foreach ($url in $suspFF) {
                Add-Finding "Firefox SUSPICIOUS URL: $url" -sev "HIGH"
            }
            $ffRows | ForEach-Object {
                $allArtifacts += [PSCustomObject]@{ Source="Firefox"; Type="URL"; Value=$_; Time="" }
            }
        }
    }
} else {
    Add-Finding "Firefox - not installed or profile not found" -sev "INFO"
}

# -- Downloads Folder ----------------------------------------------------------
Add-Finding "Scanning Downloads folder..."
$downloadsPath = "$userProfile\Downloads"
if (Test-Path $downloadsPath) {
    $recentDownloads = Get-ChildItem $downloadsPath -File -ErrorAction SilentlyContinue |
                       Where-Object { $_.LastWriteTime -ge $StartTime } |
                       Sort-Object LastWriteTime -Descending

    Add-Finding "Downloads folder - $($recentDownloads.Count) files modified in timeframe"
    foreach ($file in $recentDownloads) {
        $sev = if ($file.Extension -match "\.exe|\.ps1|\.bat|\.vbs|\.dll|\.msi|\.zip|\.rar|\.7z") { "HIGH" } else { "LOW" }
        Add-Finding "DOWNLOAD FILE: $($file.Name) [$($file.Length) bytes] at $($file.LastWriteTime)" -sev $sev
        $allArtifacts += [PSCustomObject]@{
            Source = "Downloads Folder"
            Type   = "File"
            Value  = $file.FullName
            Size   = $file.Length
            Time   = $file.LastWriteTime.ToString("o")
        }
    }
}

# -- INetCache (CertUtil drops here) -------------------------------------------
Add-Finding "Scanning INetCache for certutil artifacts..."
$inetCache = "$userProfile\AppData\Local\Microsoft\Windows\INetCache"
if (Test-Path $inetCache) {
    $cacheFiles = Get-ChildItem $inetCache -Recurse -File -ErrorAction SilentlyContinue |
                  Where-Object { $_.LastWriteTime -ge $StartTime }

    Add-Finding "INetCache - $($cacheFiles.Count) files modified in timeframe"
    foreach ($f in $cacheFiles) {
        $sev = if ($f.Extension -match "\.exe|\.ps1|\.bat|\.vbs|\.dll") { "HIGH" } else { "MEDIUM" }
        Add-Finding "INETCACHE: $($f.FullName) [$($f.Length) bytes] at $($f.LastWriteTime)" -sev $sev
        $allArtifacts += [PSCustomObject]@{
            Source = "INetCache"
            Type   = "CacheFile"
            Value  = $f.FullName
            Size   = $f.Length
            Time   = $f.LastWriteTime.ToString("o")
        }
    }
}

# -- Write JSON ----------------------------------------------------------------
$jsonPath = "$OutputPath\browser_artifacts.json"
$allArtifacts | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonPath -Encoding UTF8
Add-Finding "Browser artifact results saved: $jsonPath"
Add-Finding "Browser module complete. Total artifacts: $($allArtifacts.Count)"

return $findings
