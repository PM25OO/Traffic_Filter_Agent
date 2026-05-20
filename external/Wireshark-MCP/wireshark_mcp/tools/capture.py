"""Packet capture tools."""

import asyncio
from typing import Dict, Any
from concurrent.futures import ThreadPoolExecutor

from ..core.security import SecurityValidator
from ..core.output_formatter import OutputFormatter


def register_capture_tools(mcp, wireshark, executor: ThreadPoolExecutor):
    """Register packet capture tools.

    Args:
        mcp: FastMCP instance
        wireshark: WiresharkInterface instance
        executor: ThreadPoolExecutor for async operations
    """

    @mcp.tool
    def get_network_interfaces() -> Dict[str, Any]:
        """Get list of available network interfaces for packet capture.

        Returns:
            List of network interfaces with their names and numbers

        Example:
            {
              "status": "success",
              "interfaces": [
                "1. eth0",
                "2. wlan0",
                "3. lo"
              ],
              "count": 3
            }
        """
        return wireshark.get_interfaces()

    @mcp.tool
    async def capture_live_packets(
        interface: str,
        count: int = 50,
        capture_filter: str = "",
        timeout: int = 30,
        format: str = "text"
    ) -> Dict[str, Any]:
        """Capture live network packets from a specified interface.

        Args:
            interface: Network interface name or number (e.g., "eth0", "1")
            count: Number of packets to capture (max 1000)
            capture_filter: BPF capture filter (e.g., "tcp port 80", "host 192.168.1.1")
            timeout: Capture timeout in seconds (max 60)
            format: Output format ("text" or "json")

        Returns:
            Captured packet data with metadata

        Example:
            {
              "status": "success",
              "interface": "eth0",
              "packet_count": 50,
              "packets": [...],
              "total_captured": 50
            }

        Common Filters:
            - "tcp port 80" - HTTP traffic
            - "host 192.168.1.1" - Traffic to/from specific host
            - "net 10.0.0.0/8" - Traffic on specific network
            - "tcp port 443" - HTTPS traffic
        """
        # Input validation
        if not SecurityValidator.validate_interface(interface):
            return OutputFormatter.format_error(
                "validation",
                "Invalid interface name"
            )

        if not SecurityValidator.validate_capture_filter(capture_filter):
            return OutputFormatter.format_error(
                "validation",
                "Invalid capture filter"
            )

        # Apply limits
        count = min(count, SecurityValidator.MAX_PACKET_COUNT)
        timeout = min(timeout, 60)

        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                executor,
                wireshark.capture_packets,
                interface, count, capture_filter, timeout
            )

            # Format output
            if result.get("status") == "success" and format == "json":
                result["packets"] = result.get("packets", [])

            return result

        except Exception as e:
            return OutputFormatter.format_error(
                "exception",
                f"Live capture error: {str(e)}"
            )
