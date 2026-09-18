@echo off
rem ============================================================
rem  Proteus - one-command launcher for deepseek-harness (web)
rem  Prerequisites (persisted via setx):
rem    PENTEST_WS    workspace root (contains deepseek-harness + proteus-agent)
rem    PENTEST_PY312 python 3.12 interpreter (used by the preset MCP client)
rem ============================================================
if "%PENTEST_WS%"=="" (
  echo [proteus] PENTEST_WS is not set. Run: setx PENTEST_WS "D:\your\workspace"
  pause
  exit /b 1
)
if not exist "%PENTEST_WS%\deepseek-harness\apps\cli\lib\bin.js" (
  echo [proteus] deepseek-harness not found under %PENTEST_WS%
  pause
  exit /b 1
)
cd /d "%PENTEST_WS%\deepseek-harness"
echo [proteus] starting DSH web profile with Proteus patch...
node apps\cli\lib\bin.js --profile web --patch "%PENTEST_WS%\proteus-agent\dsh\proteus.cordis.patch.yml"
pause
