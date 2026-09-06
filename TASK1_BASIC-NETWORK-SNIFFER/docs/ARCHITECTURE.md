# Architecture Documentation

## Project Structure

```
netsentry/
├── netsentry.py                 # Entry point
├── setup.py                     # Setup configuration
├── requirements.txt             # Dependencies
│
├── src/netsentry/
│   ├── __init__.py             # Package init
│   ├── main.py                 # Main implementation (1700+ lines)
│   ├── models.py               # Data models
│   ├── utils.py                # Utility functions
│   ├── engine.py               # Capture engine
│   ├── formatter.py            # Output formatting
│   ├── exporter.py             # Data export
│   ├── interactive.py          # Interactive CLI
│   └── cli.py                  # Command-line interface
│
├── docs/
│   ├── QUICKSTART.md
│   ├── INSTALLATION.md
│   ├── CONFIGURATION.md
│   ├── ARCHITECTURE.md
│   └── API.md
│
├── tests/
│   ├── test_utils.py
│   ├── test_models.py
│   └── test_engine.py
│
├── examples/
│   ├── basic_capture.py
│   ├── filter_examples.py
│   └── export_examples.py
│
└── documents/
    ├── Reference implementation
    └── Complete project documentation
```

## Core Components

### 1. PacketCaptureEngine
Manages real-time packet capture and processing.

**Methods**:
- `start_capture()` - Begin packet capture
- `stop_capture()` - Stop capture
- `process_packet()` - Parse raw packets
- `load_from_pcap()` - Load PCAP files

### 2. PacketInfo
Data model for packet information.

**Fields**:
- Timestamp, MAC addresses
- IP addresses, protocol
- Ports, payload data
- Analysis metadata

### 3. OutputFormatter
Formats data for display.

**Methods**:
- `format_packet()` - Single packet
- `format_summary()` - Statistics
- `format_table()` - Table view

### 4. DataExporter
Exports data to various formats.

**Methods**:
- `export_to_csv()`
- `export_to_json()`
- `export_to_html()`

### 5. InteractiveMode
Interactive CLI interface.

**Commands**:
- start, load, analyze, export
- stats, interfaces, help, quit

## Data Flow

```
Raw Packets
    ↓
Scapy Sniffer
    ↓
Packet Handler
    ↓
PacketCaptureEngine.process_packet()
    ↓
PacketInfo Objects
    ↓
├→ Statistics Update
├→ Suspicious Detection
├→ Memory Storage
└→ Real-time Display
    ↓
┌──────────────────┐
├→ OutputFormatter
├→ DataExporter
└→ InteractiveMode
    ↓
Output (Display/File/Export)
```

## Class Relationships

```
PacketCaptureEngine
    ├── Uses: Scapy
    ├── Creates: PacketInfo
    ├── Updates: Statistics
    └── Manages: Packets

OutputFormatter
    ├── Reads: PacketInfo
    ├── Reads: Statistics
    └── Produces: Strings

DataExporter
    ├── Reads: PacketInfo
    ├── Reads: Statistics
    └── Writes: Files

InteractiveMode
    ├── Calls: PacketCaptureEngine
    ├── Uses: OutputFormatter
    ├── Uses: DataExporter
    └── Interacts: User input
```

## Key Features

- **Modular Design**: Separated concerns
- **Type Hints**: Full annotations
- **Error Handling**: Comprehensive
- **Logging**: Built-in logging
- **Security**: Input validation
- **Performance**: Optimized

## Security Considerations

1. Requires admin/root privileges
2. Input validation throughout
3. Sensitive data masking
4. No external calls
5. Local-only operation

## Performance Characteristics

- **Memory**: ~1-2 KB per packet
- **CPU**: <5% on modern systems
- **Network**: Zero impact (read-only)
- **Scalability**: 1000+ packets in memory

## Future Enhancements

- GUI interface
- Database storage
- Real-time alerts
- ML anomaly detection
- Plugin system
- Web interface

For more details, see API.md or review src/netsentry/ code.
