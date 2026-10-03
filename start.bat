@echo off
rem KeyPool 启动脚本（Windows）
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo [KeyPool] 未找到 node，请先安装 Node.js 18+
  pause
  exit /b 1
)
set PORT=8787
if not "%1"=="" set PORT=%1
echo [KeyPool] 启动中... http://127.0.0.1:%PORT%/admin
node server.js --port %PORT%
pause
