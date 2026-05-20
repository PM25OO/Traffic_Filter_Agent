"""PCAP file analysis tools."""

import asyncio
from typing import Dict, Any
from concurrent.futures import ThreadPoolExecutor

from ..core.security import SecurityValidator
from ..core.output_formatter import OutputFormatter


def register_analysis_tools(mcp, wireshark, executor: ThreadPoolExecutor):
    """Register PCAP analysis tools.

    Args:
        mcp: FastMCP instance
        wireshark: WiresharkInterface instance
        executor: ThreadPoolExecutor for async operations
    """

    @mcp.tool
    async def analyze_pcap_file(
        filepath: str,
        display_filter: str = "",
        max_packets: int = 100
    ) -> Dict[str, Any]:
        """Analyze an existing PCAP/PCAPNG file.

        Args:
            filepath: Path to the PCAP/PCAPNG file
            display_filter: Wireshark display filter (e.g., "http.request", "tcp.port == 443")
            max_packets: Maximum number of packets to analyze (max 1000)

        Returns:
            Packet analysis results

        Example:
            {
              "status": "success",
              "file": "/path/to/capture.pcap",
              "packet_count": 100,
              "packets": [...]
            }

        Common Display Filters:
            - "http.request" - HTTP requests
            - "tcp.flags.syn == 1" - TCP SYN packets
            - "dns.flags.response == 1" - DNS responses
            - "tls.handshake.type == 1" - TLS Client Hello
        """
        # Validate and sanitize file path
        sanitized_path = SecurityValidator.sanitize_filepath(filepath)
        if not sanitized_path:
            return OutputFormatter.format_error(
                "validation",
                "Invalid or inaccessible file path"
            )

        # Validate display filter
        if display_filter and not SecurityValidator.validate_display_filter(display_filter):
            return OutputFormatter.format_error(
                "validation",
                "Invalid display filter"
            )

        # Apply limits
        max_packets = min(max_packets, 1000)

        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                executor,
                wireshark.analyze_pcap_file,
                sanitized_path, display_filter, max_packets
            )
            return result

        except Exception as e:
            return OutputFormatter.format_error(
                "exception",
                f"File analysis error: {str(e)}"
            )

    @mcp.tool
    def get_protocol_statistics(filepath: str) -> Dict[str, Any]:
        """Generate protocol hierarchy and conversation statistics from a PCAP file.

        Args:
            filepath: Path to the PCAP/PCAPNG file

        Returns:
            Protocol statistics including hierarchy and IP conversations

        Example:
            {
              "status": "success",
              "file": "/path/to/capture.pcap",
              "protocol_hierarchy": "...",
              "ip_conversations": "..."
            }
        """
        # Validate file path
        sanitized_path = SecurityValidator.sanitize_filepath(filepath)
        if not sanitized_path:
            return OutputFormatter.format_error(
                "validation",
                "Invalid or inaccessible file path"
            )

        return wireshark.get_protocol_statistics(sanitized_path)

    @mcp.tool
    def get_capture_file_info(filepath: str) -> Dict[str, Any]:
        """Get detailed information about a capture file.

        Args:
            filepath: Path to the PCAP/PCAPNG file

        Returns:
            File metadata including size, packet count, duration, etc.

        Example:
            {
              "status": "success",
              "file": "/path/to/capture.pcap",
              "info": "File name: ...\nFile size: ...\nPacket count: ..."
            }
        """
        # Validate file path
        sanitized_path = SecurityValidator.sanitize_filepath(filepath)
        if not sanitized_path:
            return OutputFormatter.format_error(
                "validation",
                "Invalid or inaccessible file path"
            )

        return wireshark.get_file_info(sanitized_path)
