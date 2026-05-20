"""Output formatting utilities for consistent tool responses."""

import json
from datetime import datetime
from typing import Dict, Any, List, Optional


class OutputFormatter:
    """Format tool outputs consistently for LLM consumption."""

    @staticmethod
    def format_response(
        status: str,
        data: Any = None,
        error_type: Optional[str] = None,
        message: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Create standardized response format for all tools.

        Args:
            status: Response status ("success" or "error")
            data: Tool output data (only for success)
            error_type: Error category (only for error)
            message: Human-readable message
            metadata: Additional metadata (timestamps, tool info, etc.)

        Returns:
            Structured response dictionary
        """
        response = {
            "status": status,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

        if status == "success":
            if data is not None:
                response["data"] = data
            if message:
                response["message"] = message

        elif status == "error":
            response["error_type"] = error_type or "unknown"
            response["message"] = message or "An error occurred"

        if metadata:
            response["metadata"] = metadata

        return response

    @staticmethod
    def format_packets_json(packets: List[Dict], output_format: str = "text") -> Any:
        """Format packet data based on output mode.

        Args:
            packets: List of packet dictionaries
            output_format: "json" for structured data, "text" for human-readable

        Returns:
            Formatted packet data
        """
        if output_format == "json":
            return packets

        # Convert to readable text format
        return OutputFormatter._packets_to_text(packets)

    @staticmethod
    def _packets_to_text(packets: List[Dict]) -> str:
        """Convert packet list to human-readable text.

        Args:
            packets: List of packet dictionaries

        Returns:
            Formatted text string
        """
        if not packets:
            return "No packets to display"

        lines = []
        lines.append(f"Total packets: {len(packets)}\n")
        lines.append("=" * 80)

        for i, packet in enumerate(packets[:50], 1):  # Limit to 50 for readability
            lines.append(f"\nPacket #{i}")
            lines.append("-" * 40)

            # Extract common fields
            if "_source" in packet and "layers" in packet["_source"]:
                layers = packet["_source"]["layers"]

                # Frame info
                if "frame" in layers:
                    frame = layers["frame"]
                    if "frame_frame_len" in frame:
                        lines.append(f"  Length: {frame['frame_frame_len']} bytes")
                    if "frame_frame_protocols" in frame:
                        lines.append(f"  Protocols: {frame['frame_frame_protocols']}")

                # Ethernet
                if "eth" in layers:
                    eth = layers["eth"]
                    src = eth.get("eth_eth_src", "unknown")
                    dst = eth.get("eth_eth_dst", "unknown")
                    lines.append(f"  Ethernet: {src} -> {dst}")

                # IP
                if "ip" in layers:
                    ip = layers["ip"]
                    src = ip.get("ip_ip_src", "unknown")
                    dst = ip.get("ip_ip_dst", "unknown")
                    lines.append(f"  IP: {src} -> {dst}")

                # TCP
                if "tcp" in layers:
                    tcp = layers["tcp"]
                    src_port = tcp.get("tcp_tcp_srcport", "?")
                    dst_port = tcp.get("tcp_tcp_dstport", "?")
                    lines.append(f"  TCP: {src_port} -> {dst_port}")

                # UDP
                if "udp" in layers:
                    udp = layers["udp"]
                    src_port = udp.get("udp_udp_srcport", "?")
                    dst_port = udp.get("udp_udp_dstport", "?")
                    lines.append(f"  UDP: {src_port} -> {dst_port}")

        if len(packets) > 50:
            lines.append(f"\n... and {len(packets) - 50} more packets")

        return "\n".join(lines)

    @staticmethod
    def format_error(
        error_type: str,
        message: str,
        details: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Shorthand for formatting error responses.

        Args:
            error_type: Error category
            message: Error message
            details: Additional error details

        Returns:
            Formatted error response
        """
        metadata = {"details": details} if details else None
        return OutputFormatter.format_response(
            status="error",
            error_type=error_type,
            message=message,
            metadata=metadata
        )

    @staticmethod
    def format_success(
        data: Any,
        message: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Shorthand for formatting success responses.

        Args:
            data: Response data
            message: Optional success message
            metadata: Optional metadata

        Returns:
            Formatted success response
        """
        return OutputFormatter.format_response(
            status="success",
            data=data,
            message=message,
            metadata=metadata
        )

    @staticmethod
    def format_nmap_results(
        scan_data: Dict[str, Any],
        output_format: str = "json"
    ) -> Any:
        """Format nmap scan results for output.

        Args:
            scan_data: Parsed nmap scan results
            output_format: "json" or "text"

        Returns:
            Formatted scan results
        """
        if output_format == "json":
            return scan_data

        # Convert to readable text
        lines = []
        if "target" in scan_data:
            lines.append(f"Target: {scan_data['target']}\n")

        if "open_ports" in scan_data:
            lines.append(f"Open Ports: {len(scan_data['open_ports'])}")
            lines.append("-" * 40)
            for port in scan_data['open_ports']:
                port_num = port.get('port', '?')
                service = port.get('service', 'unknown')
                state = port.get('state', 'unknown')
                version = port.get('version', '')
                lines.append(f"  {port_num}/{service}: {state} {version}".strip())

        return "\n".join(lines)
