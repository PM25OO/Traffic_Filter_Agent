"""Network stream following tools."""

from typing import Dict, Any

from ..core.security import SecurityValidator
from ..core.output_formatter import OutputFormatter


def register_stream_tools(mcp, wireshark):
    """Register network stream following tools.

    Args:
        mcp: FastMCP instance
        wireshark: WiresharkInterface instance
    """

    @mcp.tool
    def follow_tcp_stream(
        filepath: str,
        stream_index: int,
        format: str = "ascii"
    ) -> Dict[str, Any]:
        """Follow TCP stream to reconstruct conversation.

        Args:
            filepath: Path to PCAP file
            stream_index: TCP stream index (0-based)
            format: Output format ("ascii", "hex", "raw")

        Returns:
            Reconstructed TCP conversation

        Example:
            {
              "status": "success",
              "stream_index": 0,
              "format": "ascii",
              "data": "GET / HTTP/1.1\r\nHost: example.com\r\n..."
            }
        """
        # Validate file path
        sanitized_path = SecurityValidator.sanitize_filepath(filepath)
        if not sanitized_path:
            return OutputFormatter.format_error(
                "validation",
                "Invalid or inaccessible file path"
            )

        if stream_index < 0:
            return OutputFormatter.format_error(
                "validation",
                "Stream index must be non-negative"
            )

        if format not in ["ascii", "hex", "raw"]:
            return OutputFormatter.format_error(
                "validation",
                "Format must be 'ascii', 'hex', or 'raw'"
            )

        return wireshark.follow_tcp_stream(sanitized_path, stream_index, format)

    @mcp.tool
    def follow_udp_stream(
        filepath: str,
        stream_index: int,
        format: str = "ascii"
    ) -> Dict[str, Any]:
        """Follow UDP stream to reconstruct conversation.

        Args:
            filepath: Path to PCAP file
            stream_index: UDP stream index (0-based)
            format: Output format ("ascii", "hex", "raw")

        Returns:
            Reconstructed UDP conversation

        Example:
            {
              "status": "success",
              "stream_index": 0,
              "format": "ascii",
              "data": "DNS query data..."
            }
        """
        # Validate file path
        sanitized_path = SecurityValidator.sanitize_filepath(filepath)
        if not sanitized_path:
            return OutputFormatter.format_error(
                "validation",
                "Invalid or inaccessible file path"
            )

        if stream_index < 0:
            return OutputFormatter.format_error(
                "validation",
                "Stream index must be non-negative"
            )

        if format not in ["ascii", "hex", "raw"]:
            return OutputFormatter.format_error(
                "validation",
                "Format must be 'ascii', 'hex', or 'raw'"
            )

        return wireshark.follow_udp_stream(sanitized_path, stream_index, format)

    @mcp.tool
    def list_tcp_streams(filepath: str) -> Dict[str, Any]:
        """Enumerate all TCP conversations in capture file.

        Args:
            filepath: Path to PCAP file

        Returns:
            List of TCP streams with endpoints and statistics

        Example:
            {
              "status": "success",
              "streams": "TCP Conversations\n192.168.1.1:50234 <-> 93.184.216.34:80  ..."
            }
        """
        # Validate file path
        sanitized_path = SecurityValidator.sanitize_filepath(filepath)
        if not sanitized_path:
            return OutputFormatter.format_error(
                "validation",
                "Invalid or inaccessible file path"
            )

        return wireshark.list_tcp_streams(sanitized_path)
