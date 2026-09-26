@echo off
rem Launch DSH desktop app with a clean environment + opencode session-header proxy.
rem WorkBuddy host shell injects ELECTRON_RUN_AS_NODE=1 and NODE_OPTIONS=<shim>,
rem which make the Electron main process run as plain Node and exit immediately.
set ELECTRON_RUN_AS_NODE=
set NODE_OPTIONS=
set ELECTRON_NO_ATTACH_CONSOLE=
rem 路径用 %~dp0（本脚本所在目录）——入库文件不得含本机绝对路径（硬规则 7）
start "opencode-session-proxy" /min cmd /c node "%~dp0opencode_session_proxy.mjs" 19388
rem delay ~1s (ping trick: cmd-native, avoids GNU timeout.exe in Git Bash PATH)
ping -n 2 127.0.0.1 >nul
rem 官方桌面端安装位置：本机绝对路径不入库（硬规则 7），用 %LOCALAPPDATA% 推导
set "DSH_EXE=%LOCALAPPDATA%\Programs\DeepSeek Harness\DeepSeek Harness.exe"
if not exist "%DSH_EXE%" set "DSH_EXE=%ProgramFiles%\DeepSeek Harness\DeepSeek Harness.exe"
if exist "%DSH_EXE%" (
  start "" "%DSH_EXE%"
) else (
  echo 没找到 DeepSeek Harness 安装位置，请手动启动它。
)
