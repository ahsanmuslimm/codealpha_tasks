# Installation Guide

## System Requirements

- Python 3.8+
- Administrator/Root privileges
- 512 MB RAM
- 100 MB disk space

## Installation Steps

### 1. Install Python Dependencies

```bash
pip install -r requirements.txt
```

Or individually:
```bash
pip install scapy colorama tabulate
```

### 2. Platform-Specific Setup

#### Windows

1. Run Command Prompt as Administrator
2. Download Npcap from: https://npcap.com/
3. Install Npcap
4. Restart your computer
5. Run: `python netsentry.py --list-interfaces`

#### Linux (Ubuntu/Debian)

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip libpcap-dev
pip3 install -r requirements.txt
sudo python3 netsentry.py --list-interfaces
```

#### Linux (Fedora/CentOS)

```bash
sudo dnf install -y python3 python3-pip libpcap-devel
pip3 install -r requirements.txt
sudo python3 netsentry.py --list-interfaces
```

#### macOS

```bash
brew install python3 libpcap
pip3 install -r requirements.txt
sudo python3 netsentry.py --list-interfaces
```

### 3. Verify Installation

```bash
python netsentry.py --version
```

## Virtual Environment (Recommended)

### Windows
```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### Linux/macOS
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Troubleshooting

### "ModuleNotFoundError: No module named 'scapy'"
```bash
pip install scapy colorama tabulate
```

### "Permission Denied"
- **Windows**: Run as Administrator
- **Linux/macOS**: Use `sudo`

### "No packets captured"
1. Check interfaces: `python netsentry.py --list-interfaces`
2. Try different interface: `python netsentry.py --interface eth0`
3. Increase timeout: `python netsentry.py --timeout 60`

### "Npcap not installed" (Windows)
1. Download from: https://npcap.com/
2. Run installer
3. Restart system

See README.md for more help.
