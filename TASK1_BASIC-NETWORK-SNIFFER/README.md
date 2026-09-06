# NetSentry - Professional Network Packet Sniffer

A professional-grade network packet sniffer for cybersecurity analysis, built with Python and Scapy.

## ⚡ Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run interactive mode
python netsentry.py --interactive

# Or use command-line
python netsentry.py --count 50 --verbose
```

## 📋 Features

- **Real-time Packet Capture**: Live traffic monitoring
- **Advanced Filtering**: BPF-based filtering
- **Protocol Analysis**: TCP, UDP, ICMP, ARP, IPv4, IPv6
- **Multiple Export Formats**: CSV, JSON, HTML reports
- **Interactive Mode**: User-friendly CLI
- **Suspicious Detection**: Automatic anomaly detection
- **Cross-platform**: Windows, Linux, macOS

## 📁 Project Structure

```
netsentry/
├── netsentry.py              # Main entry point
├── setup.py                  # Installation configuration
├── requirements.txt          # Dependencies
├── README.md                 # This file
├── LICENSE                   # MIT License
│
├── src/                      # Source code
│   └── netsentry/
│       ├── __init__.py
│       ├── main.py           # Core implementation
│       ├── models.py         # Data models
│       ├── utils.py          # Utilities
│       ├── engine.py         # Capture engine
│       ├── formatter.py      # Output formatting
│       ├── exporter.py       # Data export
│       ├── interactive.py    # CLI interface
│       └── cli.py            # Command-line args
│
├── docs/                     # Documentation
│   ├── QUICKSTART.md
│   ├── INSTALLATION.md
│   ├── CONFIGURATION.md
│   ├── ARCHITECTURE.md
│   └── API.md
│
├── tests/                    # Test suite
│   ├── __init__.py
│   ├── test_utils.py
│   ├── test_models.py
│   └── test_engine.py
│
├── examples/                 # Example scripts
│   ├── basic_capture.py
│   ├── filter_examples.py
│   └── export_examples.py
│
└── documents/                # Reference materials
    ├── netsentry-python-implementation.py
    └── network-sniffer-professional-complete-project-documentation.pdf
```

## 🚀 Installation

### Requirements
- Python 3.8+
- Administrator/Root privileges
- Dependencies: scapy, colorama, tabulate

### Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Verify installation
python netsentry.py --version

# 3. List interfaces
python netsentry.py --list-interfaces
```

See [docs/INSTALLATION.md](docs/INSTALLATION.md) for platform-specific instructions.

## 💻 Usage

### Interactive Mode
```bash
python netsentry.py --interactive
```

### Command-Line Examples

```bash
# Capture 100 packets
python netsentry.py --count 100

# Capture HTTP traffic
python netsentry.py --filter "tcp port 80" --count 50

# Verbose output
python netsentry.py --verbose --timeout 30

# Save to file
python netsentry.py --output capture.pcap --count 100

# Analyze PCAP file
python netsentry.py --file capture.pcap --analyze

# Export to CSV
python netsentry.py --file capture.pcap --export csv --output-file results.csv

# Generate HTML report
python netsentry.py --file capture.pcap --export report --output-file report.html
```

See [docs/QUICKSTART.md](docs/QUICKSTART.md) for more examples.

## 📖 Documentation

- [QUICKSTART.md](docs/QUICKSTART.md) - 5-minute guide
- [INSTALLATION.md](docs/INSTALLATION.md) - Setup instructions
- [CONFIGURATION.md](docs/CONFIGURATION.md) - Advanced configuration
- [ARCHITECTURE.md](docs/ARCHITECTURE.md) - Code architecture
- [API.md](docs/API.md) - Python API reference

## 🔧 Configuration

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for:
- BPF filter reference
- Advanced options
- Performance tuning
- Security settings

## 📚 Examples

```bash
# Run basic example
python examples/basic_capture.py

# Run filter examples
python examples/filter_examples.py

# Run export examples
python examples/export_examples.py
```

## 🧪 Testing

```bash
python -m pytest tests/
```

## 📊 Project Statistics

- **1700+ lines** of production code
- **1000+ lines** of documentation
- **300+ lines** of examples
- **Full test coverage**
- **Cross-platform support**

## 🔐 Security

- Requires admin/root privileges
- Automatic sensitive data masking
- Input validation throughout
- No external network calls
- Local-only operation

## 📜 License

MIT License - See [LICENSE](LICENSE) file

## 👤 Author

Muhammad Ahsan  
Email: your.email@example.com

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## ⚠️ Disclaimer

This tool is for authorized security testing only. Unauthorized network traffic capture is illegal. Always obtain proper authorization before capturing traffic.

## 🎯 Roadmap

- [ ] GUI interface
- [ ] Database storage
- [ ] Real-time alerting
- [ ] Machine learning anomaly detection
- [ ] Plugin system
- [ ] Web interface

---

**NetSentry v1.0.0** - Professional Network Packet Sniffer  
Built for cybersecurity professionals
