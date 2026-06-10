@echo off
:: ============================================================
:: Blue Team Detection Lab — Adversary Emulation Runner
:: Runs both emulation modules in sequence for full lab exercise
::
:: MITRE Coverage:
::   T1105  — CertUtil URLcache Abuse
::   T1053.005 — Scheduled Task via Scripting Engine
::
:: LAB USE ONLY — isolated VM you own
:: ============================================================

title Blue Team Lab — Adversary Emulation

echo.
echo  ============================================================
echo   BLUE TEAM DETECTION LAB — Adversary Emulation Suite
echo  ============================================================
echo   This batch file runs both emulation modules in sequence.
echo   Ensure your SIEM / Sysmon is running before proceeding.
echo  ============================================================
echo.

:: Check for PowerShell
where powershell >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] PowerShell not found. Exiting.
    exit /b 1
)

:: Confirm lab readiness
echo [PRE-CHECK] Is your lab VM isolated and Sysmon running? (Y/N)
set /p CONFIRM="> "
if /i not "%CONFIRM%"=="Y" (
    echo Aborted. Please ensure your lab environment is ready.
    exit /b 0
)

echo.
echo [*] Starting emulation at %date% %time%
echo.

:: ── Module 1: CertUtil URLcache ──────────────────────────────────────────────
echo  -------------------------------------------------------
echo  [1/2] Running: CertUtil URLcache Abuse (T1105)
echo  -------------------------------------------------------
powershell.exe -ExecutionPolicy Bypass -NoProfile ^
    -File "%~dp0Invoke-CertUtilDownload.ps1"

if %errorlevel% neq 0 (
    echo [WARN] CertUtil emulation returned non-zero exit code.
)

:: Small delay between modules so events are temporally distinct in SIEM
echo.
echo [*] Pausing 5 seconds between modules (improves SIEM timeline clarity)...
timeout /t 5 /nobreak >nul

:: ── Module 2: Suspicious Scheduled Task ────────────────────────────────────
echo.
echo  -------------------------------------------------------
echo  [2/2] Running: Suspicious Scheduled Task (T1053.005)
echo  -------------------------------------------------------
echo.
echo  Run with -SkipCleanup to leave task for triage? (Y/N)
set /p KEEPARTIFACTS="> "

if /i "%KEEPARTIFACTS%"=="Y" (
    powershell.exe -ExecutionPolicy Bypass -NoProfile ^
        -File "%~dp0New-SuspiciousScheduledTask.ps1" -SkipCleanup
) else (
    powershell.exe -ExecutionPolicy Bypass -NoProfile ^
        -File "%~dp0New-SuspiciousScheduledTask.ps1"
)

:: ── Done ─────────────────────────────────────────────────────────────────────
echo.
echo  ============================================================
echo   Emulation complete at %date% %time%
echo.
echo   NEXT STEPS:
echo     1. Check your SIEM for Sysmon EID 1, 3, 11 and Security EID 4698
echo     2. Run: triage\run_triage.bat to collect endpoint forensics
echo     3. Correlate timestamps between emulation and browser/task artifacts
echo  ============================================================
echo.
pause
