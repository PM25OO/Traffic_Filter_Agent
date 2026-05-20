"""Data export tools for PCAP files."""

import subprocess
import logging
from typing import Dict, Any

from ..core.security import SecurityValidator
from ..core.output_formatter import OutputFormatter

logger = logging.getLogger(__name__)


def register_export_tools(mcp, wireshark):
    """Register data export tools.

    Args:
        mcp: FastMCP instance
        wireshark: WiresharkInterface instance
    """

    @mcp.tool
    def export_packets_json(
        filepath: str,
        display_filter: str = "",
        max_packets: int = 1000
    ) -> Dict[str, Any]:
        """Export packets from PCAP to structured JSON format.

        Args:
            filepath: Path to PCAP file
            display_filter: Wireshark display filter
            max_packets: Maximum packets to export

        Returns:
            Full packet data in JSON format
        """
        # Validate file path
        sanitized_path = SecurityValidator.sanitize_filepath(filepath)
        if not sanitized_path:
            return OutputFormatter.format_error(
                "validation",
                "Invalid or inaccessible file path"
            )

        if display_filter and not SecurityValidator.validate_display_filter(display_filter):
            return OutputFormatter.format_error(
                "validation",
                "Invalid display filter"
            )

        # Use wireshark interface's analyze method
        result = wireshark.analyze_pcap_file(sanitized_path, display_filter, max_packets)

        if result.get("status") == "success":
            # Return full packet data (not truncated)
            return OutputFormatter.format_success(
                result.get("packets", []),
                f"Exported {len(result.get('packets', []))} packets"
            )

        return result

    @mcp.tool
    def export_packets_csv(
        filepath: str,
        fields: str = "frame.number,frame.time,ip.src,ip.dst,tcp.srcport,tcp.dstport",
        display_filter: str = ""
    ) -> Dict[str, Any]:
        """Export packets to CSV format with custom fields.

        Args:
            filepath: Path to PCAP file
            fields: Comma-separated list of fields to export
            display_filter: Wireshark display filter

        Returns:
            CSV formatted packet data

        Example fields:
            - "frame.number,frame.time,ip.src,ip.dst"
            - "tcp.srcport,tcp.dstport,tcp.flags"
            - "dns.qry.name,dns.resp.addr"
        """
        # Validate file path
        sanitized_path = SecurityValidator.sanitize_filepath(filepath)
        if not sanitized_path:
            return OutputFormatter.format_error(
                "validation",
                "Invalid or inaccessible file path"
            )

        if display_filter and not SecurityValidator.validate_display_filter(display_filter):
            return OutputFormatter.format_error(
                "validation",
                "Invalid display filter"
            )

        try:
            # Build tshark command for CSV export
            cmd = [
                wireshark.tshark_path,
                "-r", sanitized_path,
                "-T", "fields",
                "-E", "separator=,",
                "-E", "header=y"
            ]

            # Add fields
            for field in fields.split(","):
                cmd.extend(["-e", field.strip()])

            if display_filter:
                cmd.extend(["-Y", display_filter])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                shell=False
            )

            if result.returncode == 0:
                return OutputFormatter.format_success(
                    {"csv_data": result.stdout},
                    f"Exported packets as CSV"
                )
            else:
                return OutputFormatter.format_error(
                    "execution",
                    f"CSV export failed: {result.stderr}"
                )

        except subprocess.TimeoutExpired:
            return OutputFormatter.format_error("timeout", "CSV export timeout")
        except Exception as e:
            logger.error(f"CSV export error: {e}")
            return OutputFormatter.format_error("exception", str(e))

    @mcp.tool
    def convert_pcap_format(
        filepath: str,
        output_format: str = "pcapng"
    ) -> Dict[str, Any]:
        """Convert PCAP file between formats.

        Args:
            filepath: Path to input PCAP file
            output_format: Target format ("pcap" or "pcapng")

        Returns:
            Conversion result with output file path

        Note: Output file is created in same directory with new extension.
        """
        # Validate file path
        sanitized_path = SecurityValidator.sanitize_filepath(filepath)
        if not sanitized_path:
            return OutputFormatter.format_error(
                "validation",
                "Invalid or inaccessible file path"
            )

        if output_format not in ["pcap", "pcapng"]:
            return OutputFormatter.format_error(
                "validation",
                "Output format must be 'pcap' or 'pcapng'"
            )

        try:
            from pathlib import Path
            input_path = Path(sanitized_path)
            output_path = input_path.with_suffix(f".{output_format}")

            # Use editcap for format conversion
            cmd = [
                "editcap",
                "-F", output_format,
                str(input_path),
                str(output_path)
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                shell=False
            )

            if result.returncode == 0:
                return OutputFormatter.format_success(
                    {
                        "input_file": str(input_path),
                        "output_file": str(output_path),
                        "format": output_format
                    },
                    f"Converted to {output_format}"
                )
            else:
                return OutputFormatter.format_error(
                    "execution",
                    f"Conversion failed: {result.stderr}"
                )

        except FileNotFoundError:
            return OutputFormatter.format_error(
                "execution",
                "editcap not found. Install Wireshark to get editcap."
            )
        except subprocess.TimeoutExpired:
            return OutputFormatter.format_error("timeout", "Conversion timeout")
        except Exception as e:
            logger.error(f"Conversion error: {e}")
            return OutputFormatter.format_error("exception", str(e))
