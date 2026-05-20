"""Interface to Wireshark CLI tools (tshark, dumpcap, capinfos)."""

import json
import logging
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class WiresharkInterface:
    """Interface to Wireshark CLI tools with security controls."""

    def __init__(self):
        self.tshark_path = self._find_tshark()
        self.dumpcap_path = self._find_dumpcap()
        self.capinfos_path = self._find_capinfos()

        if not self.tshark_path:
            raise RuntimeError("TShark not found. Please install Wireshark.")

    def _find_tshark(self) -> Optional[str]:
        """Find TShark executable."""
        common_paths = [
            "tshark",
            "tshark.exe",
            r"C:\Program Files\Wireshark\tshark.exe",
            "/usr/bin/tshark",
            "/usr/local/bin/tshark"
        ]

        for path in common_paths:
            try:
                result = subprocess.run(
                    [path, "--version"],
                    capture_output=True,
                    timeout=5,
                    shell=False  # SECURITY: Prevent command injection
                )
                if result.returncode == 0:
                    return path
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue

        return None

    def _find_dumpcap(self) -> Optional[str]:
        """Find dumpcap executable."""
        common_paths = [
            "dumpcap",
            "dumpcap.exe",
            r"C:\Program Files\Wireshark\dumpcap.exe",
            "/usr/bin/dumpcap",
            "/usr/local/bin/dumpcap"
        ]

        for path in common_paths:
            try:
                result = subprocess.run(
                    [path, "--version"],
                    capture_output=True,
                    timeout=5,
                    shell=False
                )
                if result.returncode == 0:
                    return path
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue

        return None

    def _find_capinfos(self) -> Optional[str]:
        """Find capinfos executable."""
        common_paths = [
            "capinfos",
            "capinfos.exe",
            r"C:\Program Files\Wireshark\capinfos.exe",
            "/usr/bin/capinfos",
            "/usr/local/bin/capinfos"
        ]

        for path in common_paths:
            try:
                result = subprocess.run(
                    [path, "--version"],
                    capture_output=True,
                    timeout=5,
                    shell=False
                )
                if result.returncode == 0:
                    return path
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue

        return None

    def get_interfaces(self) -> Dict[str, Any]:
        """Get list of available network interfaces."""
        try:
            if self.tshark_path:
                result = subprocess.run(
                    [self.tshark_path, "-D"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    shell=False
                )

                if result.returncode == 0:
                    interfaces = []
                    for line in result.stdout.strip().split('\n'):
                        if line:
                            interfaces.append(line)

                    return {
                        "status": "success",
                        "interfaces": interfaces,
                        "count": len(interfaces)
                    }

            return {"status": "error", "message": "Unable to list interfaces"}

        except Exception as e:
            logger.error(f"Error getting interfaces: {e}")
            return {"status": "error", "message": str(e)}

    def capture_packets(
        self,
        interface: str,
        count: int = 100,
        filter_expr: str = "",
        timeout: int = 30
    ) -> Dict[str, Any]:
        """Capture packets from network interface using TShark."""
        try:
            # Build command (list, not string - prevents injection)
            cmd = [self.tshark_path, "-i", interface, "-c", str(count), "-T", "json"]

            if filter_expr:
                cmd.extend(["-f", filter_expr])

            # Execute capture
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False  # SECURITY: Critical for preventing command injection
            )

            if result.returncode != 0:
                return {
                    "status": "error",
                    "message": f"Capture failed: {result.stderr}"
                }

            # Parse JSON output
            packets = []
            if result.stdout.strip():
                try:
                    # TShark outputs one JSON object per line
                    for line in result.stdout.strip().split('\n'):
                        if line:
                            packet = json.loads(line)
                            packets.append(packet)
                except json.JSONDecodeError:
                    # Fallback to raw output
                    packets = [{"raw_output": result.stdout}]

            return {
                "status": "success",
                "interface": interface,
                "packet_count": len(packets),
                "packets": packets[:20],  # Limit output for display
                "total_captured": len(packets)
            }

        except subprocess.TimeoutExpired:
            return {"status": "error", "message": "Capture timeout"}
        except Exception as e:
            logger.error(f"Capture error: {e}")
            return {"status": "error", "message": str(e)}

    def analyze_pcap_file(
        self,
        filepath: str,
        filter_expr: str = "",
        max_packets: int = 1000
    ) -> Dict[str, Any]:
        """Analyze PCAP file using TShark."""
        try:
            cmd = [self.tshark_path, "-r", filepath, "-T", "json"]

            if filter_expr:
                cmd.extend(["-Y", filter_expr])

            if max_packets > 0:
                cmd.extend(["-c", str(max_packets)])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                shell=False
            )

            if result.returncode != 0:
                return {
                    "status": "error",
                    "message": f"Analysis failed: {result.stderr}"
                }

            # Parse packets
            packets = []
            if result.stdout.strip():
                try:
                    for line in result.stdout.strip().split('\n'):
                        if line:
                            packet = json.loads(line)
                            packets.append(packet)
                except json.JSONDecodeError:
                    packets = [{"raw_output": result.stdout}]

            return {
                "status": "success",
                "file": filepath,
                "packet_count": len(packets),
                "packets": packets[:10],  # Sample for display
                "total_analyzed": len(packets)
            }

        except Exception as e:
            logger.error(f"Analysis error: {e}")
            return {"status": "error", "message": str(e)}

    def get_protocol_statistics(self, filepath: str) -> Dict[str, Any]:
        """Generate protocol statistics from PCAP file."""
        try:
            # Protocol hierarchy
            cmd_hierarchy = [self.tshark_path, "-r", filepath, "-q", "-z", "io,phs"]
            hierarchy_result = subprocess.run(
                cmd_hierarchy,
                capture_output=True,
                text=True,
                timeout=30,
                shell=False
            )

            # Conversation statistics
            cmd_conv = [self.tshark_path, "-r", filepath, "-q", "-z", "conv,ip"]
            conv_result = subprocess.run(
                cmd_conv,
                capture_output=True,
                text=True,
                timeout=30,
                shell=False
            )

            return {
                "status": "success",
                "file": filepath,
                "protocol_hierarchy": hierarchy_result.stdout if hierarchy_result.returncode == 0 else "Error generating hierarchy",
                "ip_conversations": conv_result.stdout if conv_result.returncode == 0 else "Error generating conversations"
            }

        except Exception as e:
            logger.error(f"Statistics error: {e}")
            return {"status": "error", "message": str(e)}

    def get_file_info(self, filepath: str) -> Dict[str, Any]:
        """Get information about a capture file using capinfos."""
        if not self.capinfos_path:
            return {"status": "error", "message": "capinfos not available"}

        try:
            result = subprocess.run(
                [self.capinfos_path, filepath],
                capture_output=True,
                text=True,
                timeout=10,
                shell=False
            )

            if result.returncode == 0:
                return {
                    "status": "success",
                    "file": filepath,
                    "info": result.stdout
                }
            else:
                return {
                    "status": "error",
                    "message": f"capinfos failed: {result.stderr}"
                }

        except Exception as e:
            return {"status": "error", "message": str(e)}

    def follow_tcp_stream(
        self,
        filepath: str,
        stream_index: int,
        output_format: str = "ascii"
    ) -> Dict[str, Any]:
        """Follow TCP stream to reconstruct conversation.

        Args:
            filepath: PCAP file path
            stream_index: TCP stream index (0-based)
            output_format: Output format ("ascii", "hex", "raw")

        Returns:
            Stream conversation data
        """
        try:
            # Map format to tshark format
            format_map = {
                "ascii": "ascii",
                "hex": "hex",
                "raw": "raw"
            }
            tshark_format = format_map.get(output_format, "ascii")

            cmd = [
                self.tshark_path,
                "-r", filepath,
                "-z", f"follow,tcp,{tshark_format},{stream_index}"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                shell=False
            )

            if result.returncode == 0:
                return {
                    "status": "success",
                    "stream_index": stream_index,
                    "format": output_format,
                    "data": result.stdout
                }
            else:
                return {
                    "status": "error",
                    "message": f"Stream follow failed: {result.stderr}"
                }

        except Exception as e:
            logger.error(f"TCP stream follow error: {e}")
            return {"status": "error", "message": str(e)}

    def follow_udp_stream(
        self,
        filepath: str,
        stream_index: int,
        output_format: str = "ascii"
    ) -> Dict[str, Any]:
        """Follow UDP stream to reconstruct conversation.

        Args:
            filepath: PCAP file path
            stream_index: UDP stream index (0-based)
            output_format: Output format ("ascii", "hex", "raw")

        Returns:
            Stream conversation data
        """
        try:
            format_map = {
                "ascii": "ascii",
                "hex": "hex",
                "raw": "raw"
            }
            tshark_format = format_map.get(output_format, "ascii")

            cmd = [
                self.tshark_path,
                "-r", filepath,
                "-z", f"follow,udp,{tshark_format},{stream_index}"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                shell=False
            )

            if result.returncode == 0:
                return {
                    "status": "success",
                    "stream_index": stream_index,
                    "format": output_format,
                    "data": result.stdout
                }
            else:
                return {
                    "status": "error",
                    "message": f"Stream follow failed: {result.stderr}"
                }

        except Exception as e:
            logger.error(f"UDP stream follow error: {e}")
            return {"status": "error", "message": str(e)}

    def list_tcp_streams(self, filepath: str) -> Dict[str, Any]:
        """Enumerate all TCP conversations in capture.

        Args:
            filepath: PCAP file path

        Returns:
            List of TCP streams with endpoints
        """
        try:
            cmd = [
                self.tshark_path,
                "-r", filepath,
                "-q",
                "-z", "conv,tcp"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                shell=False
            )

            if result.returncode == 0:
                return {
                    "status": "success",
                    "streams": result.stdout
                }
            else:
                return {
                    "status": "error",
                    "message": f"Stream enumeration failed: {result.stderr}"
                }

        except Exception as e:
            logger.error(f"TCP stream list error: {e}")
            return {"status": "error", "message": str(e)}
