# Changelog

All notable changes to the Wireshark MCP Server will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-02-06

### Added
- **Modular Architecture**: Refactored single-file server into professional package structure
  - `wireshark_mcp.core`: Security validation and output formatting
  - `wireshark_mcp.interfaces`: External tool wrappers (Wireshark, nmap)
  - `wireshark_mcp.tools`: MCP tool implementations
  - `wireshark_mcp.resources`: MCP resource providers
  - `wireshark_mcp.prompts`: Guided workflow prompts

- **Nmap Integration**: Comprehensive network scanning capabilities
  - `nmap_port_scan`: Port scanning with multiple scan types (SYN, connect, UDP)
  - `nmap_service_detection`: Service version detection
  - `nmap_os_detection`: Operating system fingerprinting
  - `nmap_vulnerability_scan`: NSE vulnerability scanning
  - `nmap_quick_scan`: Fast top-100 port scan
  - `nmap_comprehensive_scan`: Full-featured deep scan
  - `scan_and_capture`: Combined nmap scan + packet capture workflow

- **Network Stream Analysis**: TCP/UDP conversation reconstruction
  - `follow_tcp_stream`: Reconstruct TCP conversations
  - `follow_udp_stream`: Reconstruct UDP conversations
  - `list_tcp_streams`: Enumerate all TCP streams in capture

- **Export Tools**: Multiple output format support
  - `export_packets_json`: Full packet export to JSON
  - `export_packets_csv`: CSV export with custom fields
  - `convert_pcap_format`: Format conversion (pcap/pcapng)

- **Threat Intelligence**: Malicious IP detection
  - URLhaus integration (free, no API key)
  - AbuseIPDB support (optional API key)
  - DNS enrichment with reverse lookups
  - Cached API responses to minimize requests

- **MCP Resources**: Dynamic data access
  - `wireshark://interfaces/`: List available network interfaces
  - `wireshark://captures/`: List available PCAP files

- **MCP Prompts**: Guided analysis workflows
  - `security_audit`: Systematic security analysis workflow

- **Enhanced Output**: Structured JSON responses for all tools
  - Consistent `{status, data, error_type, message, metadata}` format
  - Text and JSON output modes for better LLM processing

- **PyPI Packaging**: Professional distribution
  - `pip install wireshark-mcp-server`
  - Proper entry points: `wireshark-mcp-server` command
  - Comprehensive dependency management

### Changed
- **Security Enhancements**: Extended validation for nmap operations
  - Added `validate_target()` for IP/CIDR/hostname validation
  - Added `validate_port_range()` for port specification validation
  - Enforced `shell=False` in all subprocess calls (command injection prevention)
  - Added rate limiting framework for nmap operations

- **API Improvements**: All tools now support optional `format` parameter
  - `format="json"`: Structured JSON output
  - `format="text"`: Human-readable text output (default)

### Fixed
- Removed committed `__pycache__` directory from repository
- Improved error handling in packet capture operations
- Enhanced timeout handling for long-running operations

### Security
- **Defense in Depth**: Multiple layers of input validation
- **Command Injection Prevention**: No shell=True subprocess calls
- **Path Traversal Protection**: Path.resolve() validation
- **Rate Limiting**: Prevent abuse of scanning operations
- **Audit Logging**: Security-relevant operations logged

## [Unreleased]

### Planned
- GeoIP enrichment for IP addresses
- HTTP/TLS credential extraction
- Real-time capture sessions with WebSocket streaming
- Integration with additional threat intelligence sources (VirusTotal, AlienVault OTX)
- Advanced anomaly detection algorithms
- Machine learning-based traffic classification
