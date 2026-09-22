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
rem 启动前**同步并校验** preset。两个理由：
rem 1) preset 目录不能用链接（DSH 发现机制不跟随 reparse point，实测链接会让
rem    preset 从选择器里静默消失），所以只能复制——那就必须每次启动前同步，
rem    否则"仓库改了、装的那份还是旧的"，会话照常起得来、行为停在旧版。
rem 2) broken 的 preset 不进选择器、界面零提示；而没有内核工具的会话 = 没有模式
rem    闸门与证据链（守卫会拒绝目标动作，但那是事后兜底，不如启动前说清楚）。
rem 这里只同步/校验 preset 与 host 补丁，**不校验审计桥**——审计缺失不构成治理
rem 缺口，不该拦住启动。
if not "%PENTEST_PY312%"=="" (
  "%PENTEST_PY312%\python.exe" "%PENTEST_WS%\proteus-agent\tools\dsh_install.py" --no-bundle-check --no-roster --no-live
) else (
  python "%PENTEST_WS%\proteus-agent\tools\dsh_install.py" --no-bundle-check --no-roster --no-live
)
if errorlevel 1 (
  echo [proteus] preset 同步/校验未通过——先按上面的提示修好再启动，不要带着无治理的会话跑。
  pause
  exit /b 1
)

cd /d "%PENTEST_WS%\deepseek-harness"
echo [proteus] starting DSH web profile with Proteus patch...
node apps\cli\lib\bin.js --profile web --patch "%PENTEST_WS%\proteus-agent\dsh\proteus.cordis.patch.yml"
pause
