# Wireshark MCP Server

A comprehensive Model Context Protocol (MCP) server that provides AI assistants with professional-grade network analysis capabilities. Combines Wireshark packet analysis with nmap scanning, threat intelligence, and modern MCP features for enhanced network troubleshooting and security analysis.

## Features

### Core Wireshark Capabilities
- **Live Packet Capture**: Real-time network traffic capture from any interface
- **PCAP File Analysis**: Advanced analysis of capture files with filtering
- **Protocol Statistics**: Comprehensive protocol hierarchy and conversation stats
- **Stream Following**: Reconstruct TCP/UDP conversations from captures
- **Data Export**: Export packets to JSON, CSV formats

### Network Scanning (Nmap Integration)
- **Port Scanning**: Multiple scan types (SYN, connect, UDP)
- **Service Detection**: Identify services and versions
- **OS Fingerprinting**: Operating system detection
- **Vulnerability Scanning**: NSE vulnerability detection scripts
- **Quick & Comprehensive Scans**: Flexible scan options

### Security Features
- **Threat Intelligence**: URLhaus and AbuseIPDB integration
- **Malicious IP Detection**: Automatic threat checking
- **Security Audit Workflows**: Guided security analysis prompts
- **Credential Scanning**: Detect cleartext credentials
- **Defense in Depth**: Multiple layers of input validation

### Modern MCP Features
- **MCP Resources**: Dynamic access to interfaces and captures
- **MCP Prompts**: Guided workflows for security audits and troubleshooting
- **Structured JSON Output**: LLM-optimized response formats
- **Rate Limiting**: Prevent abuse of scanning operations
- **Async Operations**: Non-blocking high-performance analysis

## Installation

### Quick Install (PyPI)

```bash
pip install wireshark-mcp-server
```

### Development Install

```bash
# Clone repository
git clone https://github.com/yourusername/wireshark-mcp.git
cd wireshark-mcp

# Install in development mode
pip install -e .

# Or install from requirements
pip install -r requirements.txt
```

## Requirements

### System Requirements
- **Python 3.8+** with pip
- **Wireshark/TShark** installed and in PATH
- **Nmap** (optional, for scanning features)
- **Network capture permissions** (see setup below)

### Installation Commands

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install tshark nmap
sudo usermod -aG wireshark $USER
```

#### macOS
```bash
brew install wireshark nmap
```

#### Windows
1. Download and install [Wireshark](https://www.wireshark.org/download.html)
2. Download and install [Nmap](https://nmap.org/download.html)
3. Run as Administrator for packet capture

### Network Permissions

#### Linux (Recommended)
```bash
# Set capabilities on dumpcap (no root needed)
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap

# Or add user to wireshark group
sudo usermod -aG wireshark $USER
newgrp wireshark  # Apply group without logout
```

## Configuration

### Claude Desktop

Edit your Claude Desktop config:
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "wireshark": {
      "command": "wireshark-mcp-server",
      "env": {
        "ABUSEIPDB_API_KEY": "your_api_key_here"
      }
    }
  }
}
```

### Environment Variables

```bash
# Optional: AbuseIPDB API key for threat intelligence
export ABUSEIPDB_API_KEY="your_api_key_here"

# Optional: VirusTotal API key (future support)
export VIRUSTOTAL_API_KEY="your_api_key_here"
```

## Available Tools

### Network Interface & Capture (5 tools)

**get_network_interfaces()**
- Lists all available network interfaces

**capture_live_packets(interface, count, capture_filter, timeout, format)**
- Captures live packets with BPF filtering
- Supports JSON and text output formats

**analyze_pcap_file(filepath, display_filter, max_packets)**
- Analyzes PCAP files with Wireshark display filters

**get_protocol_statistics(filepath)**
- Generates protocol hierarchy and IP conversations

**get_capture_file_info(filepath)**
- Retrieves capture file metadata

### Stream Analysis (3 tools)

**follow_tcp_stream(filepath, stream_index, format)**
- Reconstructs TCP conversations (ASCII, hex, raw)

**follow_udp_stream(filepath, stream_index, format)**
- Reconstructs UDP conversations

**list_tcp_streams(filepath)**
- Lists all TCP conversations in capture

### Data Export (3 tools)

**export_packets_json(filepath, display_filter, max_packets)**
- Exports packets to structured JSON

**export_packets_csv(filepath, fields, display_filter)**
- Exports custom fields to CSV

**convert_pcap_format(filepath, output_format)**
- Converts between pcap/pcapng formats

### Nmap Scanning (6 tools)

**nmap_port_scan(target, ports, scan_type, format)**
- Scans for open ports (connect, SYN, UDP)

**nmap_service_detection(target, ports)**
- Detects service versions

**nmap_os_detection(target)**
- Identifies operating system (requires root)

**nmap_vulnerability_scan(target, ports)**
- Runs NSE vulnerability scripts

**nmap_quick_scan(target)**
- Fast scan of top 100 ports

**nmap_comprehensive_scan(target)**
- Full scan with all features

### Threat Intelligence (2 tools)

**check_ip_threat_intel(ip_or_filepath, providers)**
- Checks IPs against URLhaus, AbuseIPDB

**scan_capture_for_threats(filepath, providers)**
- Comprehensive threat scan of PCAP file

### MCP Resources

**wireshark://interfaces/**
- Dynamic list of network interfaces

**wireshark://captures/**
- Available PCAP files in common directories

**wireshark://system/info**
- System capabilities and tool availability

**network://help**
- Comprehensive tool documentation

### MCP Prompts

**security_audit**
- Guided security analysis workflow

**network_troubleshooting**
- Network diagnostics workflow

**incident_response**
- Security incident investigation workflow

## Usage Examples

### Basic Network Capture

```
User: "Capture 100 packets from eth0 with HTTP traffic"
AI: Uses capture_live_packets("eth0", 100, "tcp port 80")
```

### Security Analysis Workflow

```
User: "Perform a security audit on suspicious.pcap"
AI:
1. Uses security_audit prompt
2. Analyzes file with get_protocol_statistics()
3. Extracts IPs and checks scan_capture_for_threats()
4. Follows suspicious TCP streams
5. Generates comprehensive report
```

### Scan & Capture Workflow

```
User: "Scan 192.168.1.100 then capture its traffic"
AI:
1. nmap_quick_scan("192.168.1.100")
2. capture_live_packets("eth0", 500, "host 192.168.1.100")
3. analyze_pcap_file() with findings
4. follow_tcp_stream() for interesting connections
```

### Threat Intelligence Check

```
User: "Check if this capture has any malicious IPs"
AI: scan_capture_for_threats("/path/to/capture.pcap", "urlhaus,abuseipdb")
```

## Security

### Input Validation
- IP/CIDR/hostname validation
- Port range validation
- BPF and display filter sanitization
- File path resolution and sandboxing

### Command Injection Prevention
- **shell=False** enforced in ALL subprocess calls
- List-based command construction
- No user input directly in shell commands

### Rate Limiting
- Max 10 nmap scans per hour
- Configurable scan history tracking

### Privilege Management
- Detects when root/sudo required
- Never auto-escalates privileges
- Clear error messages for permission issues

### Audit Logging
- All scans logged with timestamps
- Security-relevant operations tracked
- Validation failures recorded

## Development

### Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# With coverage
pytest --cov=wireshark_mcp --cov-report=html

# Linting
ruff check wireshark_mcp/
black --check wireshark_mcp/

# Type checking
mypy wireshark_mcp/
```

### Project Structure

```
wireshark_mcp/
├── server.py                   # Main server orchestration
├── core/
│   ├── security.py             # Security validation
│   └── output_formatter.py     # Response formatting
├── interfaces/
│   ├── wireshark_interface.py  # TShark wrapper
│   ├── nmap_interface.py       # Nmap wrapper
│   └── threat_intel_interface.py # Threat APIs
├── tools/
│   ├── capture.py              # Capture tools
│   ├── analysis.py             # Analysis tools
│   ├── nmap_scan.py            # Scanning tools
│   ├── network_streams.py      # Stream tools
│   ├── export.py               # Export tools
│   └── threat_intel.py         # Threat tools
├── resources/                  # MCP Resources
└── prompts/                    # MCP Prompts
```

## Troubleshooting

### "TShark not found"
```bash
# Verify installation
tshark --version

# Add to PATH or use absolute path
export PATH=$PATH:/usr/bin
```

### "Permission denied" for capture
```bash
# Linux - set capabilities
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap

# Or use sudo (not recommended)
sudo wireshark-mcp-server
```

### "Nmap not available"
```bash
# Install nmap
sudo apt-get install nmap  # Debian/Ubuntu
brew install nmap           # macOS

# Verify
nmap --version
```

### Threat Intelligence Not Working
```bash
# Check API key
echo $ABUSEIPDB_API_KEY

# URLhaus requires no key (works by default)
# AbuseIPDB requires free API key from https://www.abuseipdb.com/
```

## License

MIT License - see LICENSE file for details

## Acknowledgments

- Built on the Model Context Protocol (MCP) by Anthropic
- Powered by Wireshark network analysis toolkit
- Integrated with Nmap security scanner
- Threat intelligence from URLhaus and AbuseIPDB

## Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/wireshark-mcp/issues)
- **Documentation**: See `network://help` resource in MCP
- **Security**: Report vulnerabilities via GitHub Security Advisories

## Roadmap

- GeoIP enrichment for IP addresses
- HTTP/TLS credential extraction
- Real-time WebSocket streaming
- VirusTotal integration
- AlienVault OTX integration
- Machine learning traffic classification
- Anomaly detection algorithms
- PCAP merging and splitting tools
- Statistics visualization export

---

**Transform your network analysis with AI-powered Wireshark + Nmap integration**
