<#
.SYNOPSIS
    Adversary Emulation: CertUtil URLcache Abuse (MITRE T1105)

.DESCRIPTION
    Simulates the attacker technique of using certutil.exe with the -urlcache flag
    to download a file from a remote URL. This is a Living Off the Land Binary (LOLBIN)
    technique observed in multiple threat actor campaigns.

    This script is intentionally noisy — it is designed to GENERATE detectable artifacts
    so blue team analysts can validate their SIEM/Sysmon detection coverage.

    Artifacts generated:
      - Sysmon EID 1  : certutil.exe process creation with -urlcache in CommandLine
      - Sysmon EID 3  : Network connection from certutil.exe
      - Sysmon EID 11 : File creation in INetCache and output path
      - Security EID 4688 (if process auditing enabled)

.PARAMETER TargetURL
    URL to download. Defaults to a benign EICAR-free test file (example.com).

.PARAMETER OutputFile
    Local path to save the downloaded file. Defaults to C:\Windows\Temp\lab_test.txt

.NOTES
    LAB USE ONLY. Run on isolated VM you own. Run as standard user (certutil does not
    require elevation — this is part of what makes it attractive to attackers).

    MITRE ATT&CK: T1105 - Ingress Tool Transfer
    Detection: Sysmon EID 1 | CommandLine contains "-urlcache"
#>

[CmdletBinding()]
param(
    [string]$TargetURL  = "http://example.com/",
    [string]$OutputFile = "C:\Windows\Temp\lab_certutil_test.txt"
)

Write-Host "`n[*] ADVERSARY EMULATION — CertUtil URLcache Abuse" -ForegroundColor Cyan
Write-Host "[*] MITRE ATT&CK: T1105 — Ingress Tool Transfer" -ForegroundColor Cyan
Write-Host "[*] This script generates DETECTABLE artifacts for lab use only.`n" -ForegroundColor Yellow

# ── Pre-flight ────────────────────────────────────────────────────────────────
Write-Host "[1] Verifying certutil.exe is available..."
$certutilPath = Get-Command certutil.exe -ErrorAction SilentlyContinue
if (-not $certutilPath) {
    Write-Error "certutil.exe not found. Exiting."
    exit 1
}
Write-Host "    Found: $($certutilPath.Source)" -ForegroundColor Green

# ── Execution ─────────────────────────────────────────────────────────────────
Write-Host "`n[2] Executing certutil with -urlcache flag (generates Sysmon EID 1, 3, 11)..."
Write-Host "    Command: certutil.exe -urlcache -split -f `"$TargetURL`" `"$OutputFile`"" -ForegroundColor DarkYellow

$startTime = Get-Date

try {
    $result = & certutil.exe -urlcache -split -f $TargetURL $OutputFile 2>&1
    Write-Host "    certutil output: $result" -ForegroundColor Gray
} catch {
    Write-Warning "certutil execution error: $_"
}

$endTime = Get-Date

# ── Artifact Verification ─────────────────────────────────────────────────────
Write-Host "`n[3] Verifying artifacts were created..."

# Check output file
if (Test-Path $OutputFile) {
    Write-Host "    [+] Output file created: $OutputFile" -ForegroundColor Green
    Write-Host "        Size: $((Get-Item $OutputFile).Length) bytes"
} else {
    Write-Host "    [-] Output file not found (network may be blocked in lab — that's OK)" -ForegroundColor Yellow
}

# Check INetCache (certutil always writes here)
$inetCache = "$env:LOCALAPPDATA\Microsoft\Windows\INetCache"
$cacheFiles = Get-ChildItem $inetCache -Recurse -ErrorAction SilentlyContinue |
              Where-Object { $_.LastWriteTime -ge $startTime }
if ($cacheFiles) {
    Write-Host "    [+] INetCache artifacts detected:" -ForegroundColor Green
    $cacheFiles | ForEach-Object { Write-Host "        $($_.FullName)" -ForegroundColor Gray }
} else {
    Write-Host "    [?] No new INetCache files (may require network access)" -ForegroundColor Yellow
}

# ── Summary for Analyst ────────────────────────────────────────────────────────
Write-Host "`n[4] DETECTION HUNTING SUMMARY" -ForegroundColor Cyan
Write-Host "    Execution window: $startTime — $endTime"
Write-Host "    Query your SIEM for this window with:"
Write-Host ""
Write-Host "    Sysmon EID 1 (Process Create):" -ForegroundColor White
Write-Host "      Image: *\certutil.exe AND CommandLine: *-urlcache*" -ForegroundColor Gray
Write-Host ""
Write-Host "    Sysmon EID 11 (File Create):" -ForegroundColor White
Write-Host "      TargetFilename: *INetCache* OR *\Temp\*.txt" -ForegroundColor Gray
Write-Host ""
Write-Host "    Sysmon EID 3 (Network Connection):" -ForegroundColor White
Write-Host "      Image: *\certutil.exe" -ForegroundColor Gray
Write-Host ""
Write-Host "[*] Emulation complete. Run triage\Get-CertUtilCache.ps1 to collect forensic artifacts.`n" -ForegroundColor Cyan
