# Architecture Documentation

## Overview

The Wireshark MCP Server is a modular, production-ready Python package that provides AI assistants with comprehensive network analysis capabilities through the Model Context Protocol (MCP).

## Design Principles

### 1. Defense in Depth Security
- Multiple layers of input validation
- Command injection prevention (shell=False everywhere)
- Path traversal protection
- Rate limiting for abuse prevention
- Privilege detection without auto-escalation

### 2. Modular Architecture
- Single Responsibility Principle
- Clear separation of concerns
- Testable components
- Easy to extend and maintain

### 3. LLM-Optimized
- Structured JSON responses
- Consistent error format
- Rich metadata for context
- Human-readable text alternatives

## Package Structure

```
wireshark_mcp/
├── __init__.py                         # Package entry point
├── server.py                           # Main orchestration
├── core/
│   ├── security.py                     # Input validation
│   └── output_formatter.py             # Response formatting
├── interfaces/
│   ├── wireshark_interface.py          # TShark wrapper
│   ├── nmap_interface.py               # Nmap wrapper
│   └── threat_intel_interface.py       # API clients
├── tools/
│   ├── capture.py                      # Packet capture
│   ├── analysis.py                     # PCAP analysis
│   ├── network_streams.py              # Stream following
│   ├── export.py                       # Data export
│   ├── nmap_scan.py                    # Port scanning
│   └── threat_intel.py                 # Threat checking
├── resources/
│   ├── interface_resource.py           # MCP Resources
│   └── capture_resource.py
├── prompts/
│   └── security_audit.py               # MCP Prompts
└── utils/                              # Future utilities
```

## Component Responsibilities

### Core Layer

**SecurityValidator** (`core/security.py`)
- Input validation for all user inputs
- Interface, IP, port, file path validation
- Command injection prevention
- Rate limiting logic

**OutputFormatter** (`core/output_formatter.py`)
- Consistent response formatting
- JSON/text output modes
- Error response standardization
- Packet data formatting

### Interface Layer

**WiresharkInterface** (`interfaces/wireshark_interface.py`)
- TShark CLI wrapper
- Packet capture operations
- PCAP analysis
- Stream following
- Protocol statistics
- **Security**: shell=False, validated inputs

**NmapInterface** (`interfaces/nmap_interface.py`)
- Nmap CLI wrapper
- Port scanning (multiple types)
- Service/OS detection
- Vulnerability scanning
- XML parsing
- **Security**: shell=False, privilege detection

**ThreatIntelInterface** (`interfaces/threat_intel_interface.py`)
- URLhaus API client
- AbuseIPDB API client
- Response caching (1 hour TTL)
- Multi-provider aggregation

### Tools Layer

**Capture Tools** (`tools/capture.py`)
- get_network_interfaces()
- capture_live_packets()

**Analysis Tools** (`tools/analysis.py`)
- analyze_pcap_file()
- get_protocol_statistics()
- get_capture_file_info()

**Stream Tools** (`tools/network_streams.py`)
- follow_tcp_stream()
- follow_udp_stream()
- list_tcp_streams()

**Export Tools** (`tools/export.py`)
- export_packets_json()
- export_packets_csv()
- convert_pcap_format()

**Nmap Tools** (`tools/nmap_scan.py`)
- nmap_port_scan()
- nmap_service_detection()
- nmap_os_detection()
- nmap_vulnerability_scan()
- nmap_quick_scan()
- nmap_comprehensive_scan()

**Threat Intel Tools** (`tools/threat_intel.py`)
- check_ip_threat_intel()
- scan_capture_for_threats()

### Resource Layer

**MCP Resources**
- Dynamic data providers
- wireshark://interfaces/ - List interfaces
- wireshark://captures/ - List PCAP files
- wireshark://system/info - System capabilities

### Prompt Layer

**MCP Prompts**
- Guided workflows for common tasks
- security_audit - Comprehensive security analysis
- network_troubleshooting - Network diagnostics
- incident_response - Security investigation

## Data Flow

### Typical Tool Invocation

1. **User Request** → Claude Desktop
2. **MCP Call** → WiresharkMCPServer
3. **Security Validation** → SecurityValidator
4. **Async Execution** → ThreadPoolExecutor
5. **Interface Call** → WiresharkInterface/NmapInterface
6. **Subprocess** → tshark/nmap (shell=False)
7. **Result Parsing** → Interface
8. **Format Response** → OutputFormatter
9. **Return to User** ← Structured JSON

### Security Validation Flow

```
Input → validate_* methods → sanitize → execute → format → return
         ├─ validate_interface()
         ├─ validate_target()
         ├─ validate_port_range()
         ├─ validate_capture_filter()
         └─ sanitize_filepath()
```

## Security Architecture

### Layer 1: Input Validation
- Regex-based pattern matching
- IP/CIDR validation using ipaddress module
- Port range validation
- File extension and size checks

### Layer 2: Command Construction
- List-based command arguments (not strings)
- shell=False enforced everywhere
- No string interpolation into commands
- Validated paths only

### Layer 3: Subprocess Execution
- Timeouts on all operations
- No shell evaluation
- Captured output only
- Error handling

### Layer 4: Rate Limiting
- Track operation history
- Configurable limits
- Time-based windows
- Per-operation tracking

### Layer 5: Privilege Management
- Detect privilege requirements
- Return clear errors
- Never auto-escalate
- Log privilege attempts

## Extension Points

### Adding New Tools

1. Create tool module in `tools/`
2. Define register_*_tools(mcp, interfaces, executor) function
3. Add @mcp.tool decorated functions
4. Import and call in server.py _register_tools()

### Adding New Interfaces

1. Create interface in `interfaces/`
2. Initialize in server.py __init__()
3. Pass to tool registration functions
4. Handle optional availability

### Adding New Resources

1. Create resource module in `resources/`
2. Define register_resources(mcp, ...) function
3. Add @mcp.resource decorated functions
4. Call in server.py _register_resources()

### Adding New Prompts

1. Create prompt module in `prompts/`
2. Define register_prompts(mcp) function
3. Add @mcp.prompt decorated functions
4. Call in server.py _register_prompts()

## Performance Considerations

### Async Operations
- ThreadPoolExecutor for blocking I/O
- asyncio.run_in_executor() for subprocess calls
- Max 4 concurrent workers

### Caching
- Threat intel responses cached (1 hour)
- Interface list not cached (dynamic)
- File operations not cached

### Resource Limits
- Max packet count: 10,000
- Max file size: 100MB
- Max capture duration: 300s
- Nmap timeout: 300s (600s for vuln scans)

## Testing Strategy

### Unit Tests
- SecurityValidator methods
- OutputFormatter functions
- Individual tool functions
- Mock subprocess calls

### Integration Tests
- Full tool workflows
- Error handling paths
- MCP protocol compliance

### Security Tests
- Command injection attempts (should fail)
- Path traversal attempts (should fail)
- Rate limit enforcement
- Privilege escalation detection

## Future Enhancements

### Planned Features
- GeoIP enrichment
- HTTP credential extraction
- Real-time WebSocket streaming
- VirusTotal integration
- ML-based anomaly detection

### Architectural Improvements
- Plugin system for custom tools
- Configuration file support
- Database for persistent state
- Web UI for visualization
