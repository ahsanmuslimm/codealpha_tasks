@echo off
REM ============================================================
REM  PyNIDS one-click demo (Windows)
REM  Window 1: SOC dashboard   Window 2: live-style attack replay
REM ============================================================
setlocal
cd /d "%~dp0.."

if not exist "demo\demo_traffic.pcap" (
    echo [*] Generating demo traffic...
    python run_nids.py --generate-demo-pcap || goto :error
)

echo [*] Starting dashboard window...
start "PyNIDS Dashboard" cmd /k python run_nids.py --dashboard

timeout /t 3 /nobreak >nul

echo [*] Replaying the attack scenario (alerts print live)...
python run_nids.py --replay-live demo\demo_traffic.pcap

echo.
echo [*] Done. Open http://127.0.0.1:5000 to inspect the dashboard.
pause
exit /b 0

:error
echo [!] Something failed - check the output above.
pause
exit /b 1
