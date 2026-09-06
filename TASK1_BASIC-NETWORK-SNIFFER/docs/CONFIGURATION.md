# Configuration Guide

## BPF Filter Reference

### Protocol Filters
```bash
tcp          # TCP traffic
udp          # UDP traffic
icmp         # ICMP (ping)
arp          # ARP protocol
```

### Port Filters
```bash
port 80              # Specific port
tcp port 443         # TCP on specific port
udp port 53          # UDP on specific port
portrange 6000-6500  # Port range
```

### IP Filters
```bash
host 192.168.1.1              # Any traffic with host
src host 192.168.1.1          # Source IP
dst host 8.8.8.8              # Destination IP
net 192.168.1.0/24            # Subnet
not host 127.0.0.1            # Exclude host
```

### MAC Filters
```bash
src mac aa:bb:cc:dd:ee:ff     # Source MAC
dst mac 00:11:22:33:44:55     # Destination MAC
```

### Combined Filters
```bash
tcp port 80                           # HTTP
tcp port 80 or tcp port 443           # HTTP or HTTPS
tcp port 80 and host 192.168.1.1      # HTTP from specific host
(tcp port 80 or tcp port 443) and host 192.168.1.100
not tcp port 22                       # Everything except SSH
```

## Command-Line Options

```bash
--interface INTERFACE    # Network interface
--count COUNT           # Number of packets
--timeout TIMEOUT       # Capture timeout (seconds)
--filter FILTER         # BPF filter
--output FILE          # Save to PCAP file
--file FILE            # Load PCAP file
--analyze              # Analyze loaded packets
--export {csv,json,report}  # Export format
--output-file FILE     # Export filename
--verbose              # Verbose output
--interactive          # Interactive mode
--list-interfaces      # Show interfaces
--version              # Show version
--help                 # Show help
```

## Examples

### Basic Capture
```bash
python netsentry.py --count 100
```

### TCP Only
```bash
python netsentry.py --filter "tcp" --count 100
```

### HTTP Traffic
```bash
python netsentry.py --filter "tcp port 80" --count 100
```

### DNS Queries
```bash
python netsentry.py --filter "port 53" --count 100
```

### Specific Host
```bash
python netsentry.py --filter "host 192.168.1.1" --count 100
```

### Save and Analyze
```bash
python netsentry.py --output capture.pcap --count 500
python netsentry.py --file capture.pcap --export csv --output-file results.csv
```

## Performance Tips

- Use specific filters to reduce data
- Set appropriate timeout values
- Reduce packet count for quick tests
- Use verbose mode for learning

For more information, see [ARCHITECTURE.md](ARCHITECTURE.md).
