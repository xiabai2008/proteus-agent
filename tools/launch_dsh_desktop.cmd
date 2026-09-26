@echo off
rem Launch DSH desktop app with a clean environment + opencode session-header proxy.
rem WorkBuddy host shell injects ELECTRON_RUN_AS_NODE=1 and NODE_OPTIONS=<shim>,
rem which make the Electron main process run as plain Node and exit immediately.
set ELECTRON_RUN_AS_NODE=
set NODE_OPTIONS=
set ELECTRON_NO_ATTACH_CONSOLE=
start "opencode-session-proxy" /min cmd /c "node D:\HZR_PROJECTS\proteus-agent\tools\opencode_session_proxy.mjs 19388"
rem delay ~1s (ping trick: cmd-native, avoids GNU timeout.exe in Git Bash PATH)
ping -n 2 127.0.0.1 >nul
start "" "C:\Users\HZR\AppData\Local\Programs\DeepSeek Harness\DeepSeek Harness.exe"
