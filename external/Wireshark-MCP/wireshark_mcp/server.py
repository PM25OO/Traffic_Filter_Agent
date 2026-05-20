"""Main Wireshark + Nmap MCP Server orchestration."""

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor

from fastmcp import FastMCP

from .interfaces.wireshark_interface import WiresharkInterface
from .tools import capture, analysis, network_streams

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class WiresharkMCPServer:
    """Main Wireshark + Nmap MCP Server."""

    def __init__(self):
        self.mcp = FastMCP("wireshark-analyzer")
        self.executor = ThreadPoolExecutor(max_workers=4)

        # Initialize Wireshark interface
        try:
            self.wireshark = WiresharkInterface()
            logger.info("Wireshark interface initialized successfully")
        except RuntimeError as e:
            logger.error(f"Wireshark initialization failed: {e}")
            raise

        # Initialize Nmap interface (optional)
        self.nmap = None
        try:
            from .interfaces.nmap_interface import NmapInterface
            self.nmap = NmapInterface()
            logger.info("Nmap interface initialized successfully")
        except RuntimeError as e:
            logger.warning(f"Nmap not available: {e}")
        except ImportError:
            logger.warning("Nmap interface module not found")

        # Initialize Threat Intelligence interface (optional)
        self.threat_intel = None
        try:
            from .interfaces.threat_intel_interface import ThreatIntelInterface
            self.threat_intel = ThreatIntelInterface()
            logger.info("Threat intelligence interface initialized successfully")
        except Exception as e:
            logger.warning(f"Threat intelligence not available: {e}")

        # Register all tools
        self._register_tools()
        self._register_resources()
        self._register_prompts()

        logger.info("Wireshark MCP Server initialized")

    def _register_tools(self):
        """Register all MCP tools."""
        # Wireshark tools
        capture.register_capture_tools(self.mcp, self.wireshark, self.executor)
        analysis.register_analysis_tools(self.mcp, self.wireshark, self.executor)
        network_streams.register_stream_tools(self.mcp, self.wireshark)

        # Export tools
        from .tools import export
        export.register_export_tools(self.mcp, self.wireshark)

        # Nmap tools (if available)
        if self.nmap:
            from .tools import nmap_scan
            nmap_scan.register_nmap_tools(self.mcp, self.nmap, self.executor)
            logger.info("Registered nmap scanning tools")

        # Threat intelligence tools (if available)
        if self.threat_intel:
            from .tools import threat_intel
            threat_intel.register_threat_intel_tools(
                self.mcp, self.threat_intel, self.wireshark, self.executor
            )
            logger.info("Registered threat intelligence tools")

        logger.info("All tools registered successfully")

    def _register_resources(self):
        """Register MCP resources."""
        # Interface and capture resources
        from .resources import interface_resource, capture_resource
        interface_resource.register_resources(self.mcp, self.wireshark)
        capture_resource.register_resources(self.mcp)

        @self.mcp.resource("network://help")
        def get_help_documentation() -> str:
            """Comprehensive help documentation for Wireshark MCP tools."""
            help_text = """
# Wireshark MCP Server Help

## Available Tools

### Network Interface Tools

**get_network_interfaces()**
- Lists all available network interfaces for packet capture
- No parameters required
- Returns interface names and numbers

### Packet Capture Tools

**capture_live_packets(interface, count, capture_filter, timeout, format)**
- Captures live network packets from specified interface
- Parameters:
  - interface: Interface name (e.g., "eth0") or number (e.g., "1")
  - count: Number of packets to capture (default: 50, max: 1000)
  - capture_filter: BPF filter expression (optional)
  - timeout: Capture timeout in seconds (default: 30, max: 60)
  - format: Output format ("text" or "json")

### File Analysis Tools

**analyze_pcap_file(filepath, display_filter, max_packets)**
- Analyzes existing PCAP/PCAPNG files
- Parameters:
  - filepath: Path to capture file
  - display_filter: Wireshark display filter (optional)
  - max_packets: Maximum packets to analyze (default: 100, max: 1000)

**get_protocol_statistics(filepath)**
- Generates protocol hierarchy and conversation statistics
- Parameters:
  - filepath: Path to capture file

**get_capture_file_info(filepath)**
- Gets detailed information about capture file
- Parameters:
  - filepath: Path to capture file

### Stream Following Tools

**follow_tcp_stream(filepath, stream_index, format)**
- Reconstructs TCP conversation
- Parameters:
  - filepath: Path to PCAP file
  - stream_index: TCP stream index (0-based)
  - format: Output format ("ascii", "hex", "raw")

**follow_udp_stream(filepath, stream_index, format)**
- Reconstructs UDP conversation
- Parameters:
  - filepath: Path to PCAP file
  - stream_index: UDP stream index (0-based)
  - format: Output format ("ascii", "hex", "raw")

**list_tcp_streams(filepath)**
- Lists all TCP conversations in capture
- Parameters:
  - filepath: Path to PCAP file
"""

            # Add nmap tools if available
            if self.nmap:
                help_text += """
### Nmap Scanning Tools

**nmap_port_scan(target, ports, scan_type, format)**
- Scans target for open ports
- Parameters:
  - target: IP, CIDR, or hostname (e.g., "192.168.1.1", "10.0.0.0/24")
  - ports: Port specification (e.g., "80,443", "1-1000")
  - scan_type: "connect", "syn", or "udp" (syn/udp require root)
  - format: Output format ("json" or "text")

**nmap_service_detection(target, ports)**
- Detects service versions on open ports
- Parameters:
  - target: IP address or hostname
  - ports: Port specification (empty = all open ports)

**nmap_os_detection(target)**
- Detects operating system (requires root)
- Parameters:
  - target: IP address or hostname

**nmap_vulnerability_scan(target, ports)**
- Runs NSE vulnerability detection scripts
- Parameters:
  - target: IP address or hostname
  - ports: Port specification (default: "1-1000")

**nmap_quick_scan(target)**
- Quick scan of top 100 common ports
- Parameters:
  - target: IP address or hostname

**nmap_comprehensive_scan(target)**
- Full scan with OS, version, and script detection
- Parameters:
  - target: IP address or hostname
"""

            help_text += """
## Common Filters

### Capture Filters (BPF syntax):
- "tcp port 80" - HTTP traffic
- "host 192.168.1.1" - Traffic to/from specific host
- "net 10.0.0.0/8" - Traffic on specific network
- "tcp port 443" - HTTPS traffic

### Display Filters (Wireshark syntax):
- "http.request" - HTTP requests
- "tcp.flags.syn == 1" - TCP SYN packets
- "dns.flags.response == 1" - DNS responses
- "tls.handshake.type == 1" - TLS Client Hello

## Security Notes
- All inputs are validated for security
- File paths are sanitized and checked
- Capture limits are enforced
- Only PCAP/PCAPNG files are accepted
- Nmap scans are rate-limited to prevent abuse
- shell=False enforced in all subprocess calls

## Example Workflows

### 1. Capture and Analyze HTTP Traffic
```
1. get_network_interfaces() - Find your interface
2. capture_live_packets("eth0", 100, "tcp port 80")
3. analyze_pcap_file("/path/to/capture.pcap", "http.request")
```

### 2. Scan and Capture Workflow
```
1. nmap_quick_scan("192.168.1.100") - Find open ports
2. capture_live_packets("eth0", 200, "host 192.168.1.100")
3. follow_tcp_stream("/path/to/capture.pcap", 0)
```

### 3. Security Analysis
```
1. nmap_vulnerability_scan("target.example.com", "1-1000")
2. analyze_pcap_file("suspicious.pcap", "")
3. get_protocol_statistics("suspicious.pcap")
```
"""
            return help_text

        logger.info("Resources registered successfully")

    def _register_prompts(self):
        """Register MCP prompts."""
        from .prompts import security_audit
        security_audit.register_prompts(self.mcp)
        logger.info("Prompts registered successfully")

    def run(self):
        """Run the MCP server."""
        logger.info("Starting Wireshark MCP Server...")
        try:
            self.mcp.run()
        except KeyboardInterrupt:
            logger.info("Server stopped by user")
        except Exception as e:
            logger.error(f"Server error: {e}")
            raise
        finally:
            self.executor.shutdown(wait=True)


def main():
    """Main entry point for CLI."""
    try:
        server = WiresharkMCPServer()
        server.run()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        raise


if __name__ == "__main__":
    main()
