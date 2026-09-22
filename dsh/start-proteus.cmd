@echo off
chcp 65001 >nul
rem ============================================================
rem  Proteus - one-command launcher for deepseek-harness (web)
rem
rem  This file MUST keep CRLF line endings. An LF-only .cmd gets
rem  mis-split by cmd.exe: text after a `rem` is joined with the next
rem  line and executed as one command, so the window flashes and closes
rem  - the user sees 'double-clicked, nothing happened' (measured
rem  2026-09-23: 11 garbage error lines under LF, clean run under CRLF).
rem  tools/dsh_install.py --check verifies this.
rem
rem  All real logic lives in tools/dsh_install.py --launch: sync preset,
rem  close a running instance (else the new one dies with EADDRINUSE
rem  127.0.0.1:4080), resolve workspace from PENTEST_WS or .env, start DSH.
rem ============================================================
set "PROTEUS_PY=%PENTEST_PY312%\python.exe"
if not exist "%PROTEUS_PY%" set "PROTEUS_PY=python"
"%PROTEUS_PY%" "%~dp0..\tools\dsh_install.py" --launch
pause
