# ============================================================
#  PyNIDS Windows setup script
#  Usage: powershell -ExecutionPolicy Bypass -File scripts\setup_windows.ps1
# ============================================================
$ErrorActionPreference = "Stop"
$project = Split-Path -Parent $PSScriptRoot
Set-Location $project

Write-Host "[1/5] Checking Python..." -ForegroundColor Cyan
try {
    $version = python --version 2>&1
    Write-Host "    found $version"
    if ($version -notmatch "Python (3\.(9|1[0-9]))") {
        Write-Warning "    Python 3.9+ recommended (found: $version)"
    }
} catch {
    Write-Host "    Python not found - install from https://python.org" -ForegroundColor Red
    exit 1
}

Write-Host "[2/5] Installing Python dependencies..." -ForegroundColor Cyan
pip install -r requirements.txt --quiet
Write-Host "    done"

Write-Host "[3/5] Checking Npcap (needed for LIVE capture only)..." -ForegroundColor Cyan
$npcap = Test-Path "C:\Windows\System32\Npcap\wpcap.dll"
if ($npcap) {
    Write-Host "    Npcap found - live capture available" 
} else {
    Write-Warning "    Npcap NOT found - live capture unavailable."
    Write-Host "    Download from https://npcap.com/ and install with 'WinPcap API-compatible mode'."
    Write-Host "    Offline modes (--pcap / --replay-live / --generate-demo-pcap) work without it."
}

Write-Host "[4/5] Running the built-in self-test..." -ForegroundColor Cyan
python run_nids.py --selftest

Write-Host "[5/5] Generating demo traffic..." -ForegroundColor Cyan
python run_nids.py --generate-demo-pcap

Write-Host ""
Write-Host "Setup complete. Try:" -ForegroundColor Green
Write-Host "  python run_nids.py --pcap demo\demo_traffic.pcap          # offline detection"
Write-Host "  python run_nids.py --replay-live demo\demo_traffic.pcap   # live-style demo"
Write-Host "  python run_nids.py --dashboard                            # SOC dashboard"
Write-Host "  python run_nids.py --list-interfaces                      # pick an interface"
Write-Host "  python run_nids.py --interface <IFACE>                    # real monitoring (admin)"
