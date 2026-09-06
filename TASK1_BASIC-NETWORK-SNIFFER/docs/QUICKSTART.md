# Quick Start Guide

## 5-Minute Setup

### Step 1: Install (1 minute)
```bash
pip install -r requirements.txt
```

### Step 2: Verify (1 minute)
```bash
python netsentry.py --version
python netsentry.py --list-interfaces
```

### Step 3: Capture (3 minutes)
```bash
python netsentry.py --interactive
```

## Common Commands

### List Interfaces
```bash
python netsentry.py --list-interfaces
```

### Capture Packets
```bash
python netsentry.py --count 50 --verbose
```

### Capture HTTP Traffic
```bash
python netsentry.py --filter "tcp port 80" --count 100
```

### Save to File
```bash
python netsentry.py --output capture.pcap --count 100
```

### Analyze Saved File
```bash
python netsentry.py --file capture.pcap --analyze
```

### Export to CSV
```bash
python netsentry.py --file capture.pcap --export csv --output-file results.csv
```

### Generate HTML Report
```bash
python netsentry.py --file capture.pcap --export report --output-file report.html
```

## Help

```bash
python netsentry.py --help
```

For more details, see [INSTALLATION.md](INSTALLATION.md) and [CONFIGURATION.md](CONFIGURATION.md).
