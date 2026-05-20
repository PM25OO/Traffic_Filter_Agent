"""MCP Resource for network interfaces."""

import json


def register_resources(mcp, wireshark):
    """Register interface-related MCP resources.

    Args:
        mcp: FastMCP instance
        wireshark: WiresharkInterface instance
    """

    @mcp.resource("wireshark://interfaces/")
    def list_interfaces() -> str:
        """List available network interfaces.

        Returns:
            JSON string with interface information
        """
        interfaces = wireshark.get_interfaces()
        return json.dumps(interfaces, indent=2)

    @mcp.resource("wireshark://system/info")
    def system_info() -> str:
        """Get Wireshark system information.

        Returns:
            JSON string with system capabilities
        """
        info = {
            "tshark_available": wireshark.tshark_path is not None,
            "dumpcap_available": wireshark.dumpcap_path is not None,
            "capinfos_available": wireshark.capinfos_path is not None,
            "tshark_path": wireshark.tshark_path,
            "capabilities": [
                "packet_capture",
                "pcap_analysis",
                "protocol_statistics",
                "tcp_stream_following",
                "udp_stream_following"
            ]
        }
        return json.dumps(info, indent=2)
