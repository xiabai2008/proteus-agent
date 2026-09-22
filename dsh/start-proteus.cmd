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
rem 启动前先校验 preset 健康。理由：broken 的 preset 不进选择器、界面上零提示；
rem 而没有内核工具的会话 = 没有模式闸门与证据链（守卫会拒绝目标动作，但那是事后
rem 兜底，不如启动前就说清楚）。这里只校验 preset 与 host 补丁，**不校验审计桥**
rem —— 审计缺失不构成治理缺口，不该拦住启动。
if not "%PENTEST_PY312%"=="" (
  "%PENTEST_PY312%\python.exe" "%PENTEST_WS%\proteus-agent\tools\dsh_install.py" --check --no-bundle-check
) else (
  python "%PENTEST_WS%\proteus-agent\tools\dsh_install.py" --check --no-bundle-check
)
if errorlevel 1 (
  echo [proteus] preset 校验未通过——先按上面的提示修好再启动，不要带着无治理的会话跑。
  pause
  exit /b 1
)

cd /d "%PENTEST_WS%\deepseek-harness"
echo [proteus] starting DSH web profile with Proteus patch...
node apps\cli\lib\bin.js --profile web --patch "%PENTEST_WS%\proteus-agent\dsh\proteus.cordis.patch.yml"
pause
