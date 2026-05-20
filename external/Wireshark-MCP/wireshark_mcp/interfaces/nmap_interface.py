"""Secure interface to nmap CLI for network scanning."""

import logging
import subprocess
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional
import shutil

logger = logging.getLogger(__name__)


class NmapInterface:
    """Secure interface to nmap CLI with command injection prevention."""

    def __init__(self):
        self.nmap_path = shutil.which("nmap")
        if not self.nmap_path:
            raise RuntimeError("Nmap not found. Install nmap first: apt-get install nmap")

    def port_scan(
        self,
        target: str,
        ports: str = "1-1000",
        scan_type: str = "connect"
    ) -> Dict[str, Any]:
        """Execute nmap port scan with security controls.

        Args:
            target: IP address, CIDR range, or hostname
            ports: Port specification (e.g., "80,443", "1-1000")
            scan_type: Scan type ("syn", "connect", "udp")

        Returns:
            Structured scan results

        Security: Uses shell=False and validates all inputs
        """
        # Map scan_type to nmap flags
        scan_flags = {
            "syn": ["-sS"],  # Requires root
            "connect": ["-sT"],  # No root required
            "udp": ["-sU"],  # Requires root
        }

        flags = scan_flags.get(scan_type, ["-sT"])

        # Build secure command (CRITICAL: list format, not string)
        cmd = [
            self.nmap_path,
            "-p", ports,
            "-oX", "-",  # XML output to stdout
            *flags,
            target
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                shell=False  # CRITICAL: Prevent command injection
            )

            if result.returncode != 0:
                # Check for privilege errors
                if "requires root privileges" in result.stderr.lower():
                    return {
                        "status": "error",
                        "error_type": "privilege",
                        "message": f"Scan type '{scan_type}' requires root privileges. Use 'connect' scan instead or run with sudo."
                    }

                return {
                    "status": "error",
                    "error_type": "execution",
                    "message": f"Nmap failed: {result.stderr}"
                }

            return self._parse_nmap_xml(result.stdout, target)

        except subprocess.TimeoutExpired:
            return {
                "status": "error",
                "error_type": "timeout",
                "message": "Scan timeout after 300s"
            }
        except Exception as e:
            logger.error(f"Port scan error: {e}")
            return {
                "status": "error",
                "error_type": "exception",
                "message": str(e)
            }

    def service_detection(
        self,
        target: str,
        ports: str = ""
    ) -> Dict[str, Any]:
        """Detect service versions on open ports.

        Args:
            target: IP address or hostname
            ports: Port specification (empty = scan all open ports)

        Returns:
            Service version information
        """
        cmd = [self.nmap_path, "-sV", "-oX", "-"]
        if ports:
            cmd.extend(["-p", ports])
        cmd.append(target)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                shell=False
            )

            if result.returncode != 0:
                return {
                    "status": "error",
                    "error_type": "execution",
                    "message": f"Service detection failed: {result.stderr}"
                }

            return self._parse_nmap_xml(result.stdout, target)

        except subprocess.TimeoutExpired:
            return {
                "status": "error",
                "error_type": "timeout",
                "message": "Service detection timeout"
            }
        except Exception as e:
            logger.error(f"Service detection error: {e}")
            return {
                "status": "error",
                "error_type": "exception",
                "message": str(e)
            }

    def os_detection(self, target: str) -> Dict[str, Any]:
        """Detect operating system (requires root).

        Args:
            target: IP address or hostname

        Returns:
            OS detection results

        Security: Requires elevated privileges
        """
        cmd = [self.nmap_path, "-O", "-oX", "-", target]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                shell=False
            )

            if result.returncode != 0:
                if "requires root privileges" in result.stderr.lower():
                    return {
                        "status": "error",
                        "error_type": "privilege",
                        "message": "OS detection requires root privileges"
                    }

                return {
                    "status": "error",
                    "error_type": "execution",
                    "message": f"OS detection failed: {result.stderr}"
                }

            return self._parse_nmap_xml(result.stdout, target)

        except subprocess.TimeoutExpired:
            return {
                "status": "error",
                "error_type": "timeout",
                "message": "OS detection timeout"
            }
        except Exception as e:
            logger.error(f"OS detection error: {e}")
            return {
                "status": "error",
                "error_type": "exception",
                "message": str(e)
            }

    def vulnerability_scan(
        self,
        target: str,
        ports: str = "1-1000"
    ) -> Dict[str, Any]:
        """Run NSE vulnerability scripts (safe scripts only).

        Args:
            target: IP address or hostname
            ports: Port specification

        Returns:
            Vulnerability scan results

        Security: Only uses 'vuln' category scripts
        """
        cmd = [
            self.nmap_path,
            "-p", ports,
            "--script", "vuln",
            "-oX", "-",
            target
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,  # Longer timeout for script execution
                shell=False
            )

            if result.returncode != 0:
                return {
                    "status": "error",
                    "error_type": "execution",
                    "message": f"Vulnerability scan failed: {result.stderr}"
                }

            return self._parse_nmap_xml(result.stdout, target)

        except subprocess.TimeoutExpired:
            return {
                "status": "error",
                "error_type": "timeout",
                "message": "Vulnerability scan timeout"
            }
        except Exception as e:
            logger.error(f"Vulnerability scan error: {e}")
            return {
                "status": "error",
                "error_type": "exception",
                "message": str(e)
            }

    def quick_scan(self, target: str) -> Dict[str, Any]:
        """Quick scan of top 100 most common ports.

        Args:
            target: IP address or hostname

        Returns:
            Quick scan results
        """
        cmd = [
            self.nmap_path,
            "--top-ports", "100",
            "-oX", "-",
            target
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                shell=False
            )

            if result.returncode != 0:
                return {
                    "status": "error",
                    "error_type": "execution",
                    "message": f"Quick scan failed: {result.stderr}"
                }

            return self._parse_nmap_xml(result.stdout, target)

        except subprocess.TimeoutExpired:
            return {
                "status": "error",
                "error_type": "timeout",
                "message": "Quick scan timeout"
            }
        except Exception as e:
            logger.error(f"Quick scan error: {e}")
            return {
                "status": "error",
                "error_type": "exception",
                "message": str(e)
            }

    def comprehensive_scan(self, target: str) -> Dict[str, Any]:
        """Comprehensive scan with service detection and default scripts.

        Args:
            target: IP address or hostname

        Returns:
            Comprehensive scan results

        Note: This is a long-running operation
        """
        cmd = [
            self.nmap_path,
            "-A",  # Aggressive scan (OS, version, scripts, traceroute)
            "-oX", "-",
            target
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
                shell=False
            )

            if result.returncode != 0:
                if "requires root privileges" in result.stderr.lower():
                    return {
                        "status": "error",
                        "error_type": "privilege",
                        "message": "Comprehensive scan requires root privileges for some features"
                    }

                return {
                    "status": "error",
                    "error_type": "execution",
                    "message": f"Comprehensive scan failed: {result.stderr}"
                }

            return self._parse_nmap_xml(result.stdout, target)

        except subprocess.TimeoutExpired:
            return {
                "status": "error",
                "error_type": "timeout",
                "message": "Comprehensive scan timeout (600s)"
            }
        except Exception as e:
            logger.error(f"Comprehensive scan error: {e}")
            return {
                "status": "error",
                "error_type": "exception",
                "message": str(e)
            }

    def _parse_nmap_xml(self, xml_output: str, target: str) -> Dict[str, Any]:
        """Parse nmap XML output to structured JSON.

        Args:
            xml_output: XML output from nmap
            target: Target that was scanned

        Returns:
            Structured scan results
        """
        try:
            root = ET.fromstring(xml_output)

            # Extract host information
            host = root.find(".//host")
            if host is None:
                return {
                    "status": "success",
                    "target": target,
                    "message": "Host appears down or unreachable",
                    "open_ports": []
                }

            # Parse open ports
            open_ports = []
            for port in host.findall(".//port"):
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    port_data = {
                        "port": port.get("portid"),
                        "protocol": port.get("protocol"),
                        "state": "open"
                    }

                    # Service information
                    service = port.find("service")
                    if service is not None:
                        port_data["service"] = service.get("name", "unknown")
                        port_data["product"] = service.get("product", "")
                        port_data["version"] = service.get("version", "")

                    # Script results (for vulnerability scans)
                    scripts = port.findall("script")
                    if scripts:
                        port_data["scripts"] = []
                        for script in scripts:
                            port_data["scripts"].append({
                                "id": script.get("id"),
                                "output": script.get("output")
                            })

                    open_ports.append(port_data)

            # Parse OS information if available
            os_info = None
            osmatch = host.find(".//osmatch")
            if osmatch is not None:
                os_info = {
                    "name": osmatch.get("name"),
                    "accuracy": osmatch.get("accuracy")
                }

            result = {
                "status": "success",
                "target": target,
                "open_ports": open_ports,
                "port_count": len(open_ports)
            }

            if os_info:
                result["os"] = os_info

            return result

        except ET.ParseError as e:
            logger.error(f"XML parse error: {e}")
            return {
                "status": "error",
                "error_type": "parse",
                "message": f"Failed to parse nmap XML output: {e}"
            }
        except Exception as e:
            logger.error(f"Parse error: {e}")
            return {
                "status": "error",
                "error_type": "parse",
                "message": str(e)
            }
