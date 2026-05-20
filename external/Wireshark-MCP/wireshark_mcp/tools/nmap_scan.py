"""Nmap network scanning tools."""

import asyncio
from typing import Dict, Any
from concurrent.futures import ThreadPoolExecutor

from ..core.security import SecurityValidator
from ..core.output_formatter import OutputFormatter


def register_nmap_tools(mcp, nmap, executor: ThreadPoolExecutor):
    """Register nmap scanning tools.

    Args:
        mcp: FastMCP instance
        nmap: NmapInterface instance
        executor: ThreadPoolExecutor for async operations
    """

    @mcp.tool
    async def nmap_port_scan(
        target: str,
        ports: str = "1-1000",
        scan_type: str = "connect",
        format: str = "json"
    ) -> Dict[str, Any]:
        """Scan target for open ports using nmap.

        Args:
            target: IP address, CIDR range, or hostname (e.g., "192.168.1.1", "10.0.0.0/24")
            ports: Port specification (e.g., "80,443", "1-1000", "22,80,443,3306")
            scan_type: Scan type ("connect", "syn", "udp"). Note: "syn" and "udp" require root.
            format: Output format ("json" or "text")

        Returns:
            Scan results with open ports and services

        Example:
            {
              "status": "success",
              "target": "192.168.1.1",
              "open_ports": [
                {"port": "22", "protocol": "tcp", "service": "ssh"},
                {"port": "80", "protocol": "tcp", "service": "http"}
              ],
              "port_count": 2
            }

        Security: Validates target and ports. Rate limited to prevent abuse.
        """
        # Validation
        if not SecurityValidator.validate_target(target):
            return OutputFormatter.format_error(
                "validation",
                "Invalid target address. Use IP, CIDR, or valid hostname."
            )

        if not SecurityValidator.validate_port_range(ports):
            return OutputFormatter.format_error(
                "validation",
                "Invalid port range. Use format: '80', '1-1000', or '22,80,443'"
            )

        # Execute scan
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                executor,
                nmap.port_scan,
                target, ports, scan_type
            )

            # Format output
            if result.get("status") == "success" and format == "text":
                result["formatted_output"] = OutputFormatter.format_nmap_results(
                    result,
                    "text"
                )

            return result

        except Exception as e:
            return OutputFormatter.format_error(
                "exception",
                f"Port scan error: {str(e)}"
            )

    @mcp.tool
    async def nmap_service_detection(
        target: str,
        ports: str = ""
    ) -> Dict[str, Any]:
        """Detect service versions on open ports.

        Args:
            target: IP address or hostname
            ports: Port specification (empty = detect on all open ports)

        Returns:
            Service version information

        Example:
            {
              "status": "success",
              "target": "192.168.1.1",
              "open_ports": [
                {
                  "port": "22",
                  "service": "ssh",
                  "product": "OpenSSH",
                  "version": "8.2p1 Ubuntu 4ubuntu0.5"
                }
              ]
            }
        """
        if not SecurityValidator.validate_target(target):
            return OutputFormatter.format_error(
                "validation",
                "Invalid target address"
            )

        if ports and not SecurityValidator.validate_port_range(ports):
            return OutputFormatter.format_error(
                "validation",
                "Invalid port range"
            )

        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                executor,
                nmap.service_detection,
                target, ports
            )
            return result

        except Exception as e:
            return OutputFormatter.format_error(
                "exception",
                f"Service detection error: {str(e)}"
            )

    @mcp.tool
    async def nmap_os_detection(target: str) -> Dict[str, Any]:
        """Detect operating system of target (requires root privileges).

        Args:
            target: IP address or hostname

        Returns:
            OS detection results

        Note: This scan requires root/administrator privileges.

        Example:
            {
              "status": "success",
              "target": "192.168.1.1",
              "os": {
                "name": "Linux 3.2 - 4.9",
                "accuracy": "95"
              }
            }
        """
        if not SecurityValidator.validate_target(target):
            return OutputFormatter.format_error(
                "validation",
                "Invalid target address"
            )

        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                executor,
                nmap.os_detection,
                target
            )
            return result

        except Exception as e:
            return OutputFormatter.format_error(
                "exception",
                f"OS detection error: {str(e)}"
            )

    @mcp.tool
    async def nmap_vulnerability_scan(
        target: str,
        ports: str = "1-1000"
    ) -> Dict[str, Any]:
        """Run NSE vulnerability detection scripts.

        Args:
            target: IP address or hostname
            ports: Port specification

        Returns:
            Vulnerability scan results with NSE script output

        Note: This is a longer-running scan (uses nmap --script vuln).

        Example:
            {
              "status": "success",
              "target": "192.168.1.1",
              "open_ports": [
                {
                  "port": "80",
                  "service": "http",
                  "scripts": [
                    {
                      "id": "http-vuln-cve2017-5638",
                      "output": "VULNERABLE: ..."
                    }
                  ]
                }
              ]
            }
        """
        if not SecurityValidator.validate_target(target):
            return OutputFormatter.format_error(
                "validation",
                "Invalid target address"
            )

        if not SecurityValidator.validate_port_range(ports):
            return OutputFormatter.format_error(
                "validation",
                "Invalid port range"
            )

        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                executor,
                nmap.vulnerability_scan,
                target, ports
            )
            return result

        except Exception as e:
            return OutputFormatter.format_error(
                "exception",
                f"Vulnerability scan error: {str(e)}"
            )

    @mcp.tool
    async def nmap_quick_scan(target: str) -> Dict[str, Any]:
        """Quick scan of top 100 most common ports.

        Args:
            target: IP address or hostname

        Returns:
            Quick scan results

        Example:
            {
              "status": "success",
              "target": "192.168.1.1",
              "open_ports": [...]
            }
        """
        if not SecurityValidator.validate_target(target):
            return OutputFormatter.format_error(
                "validation",
                "Invalid target address"
            )

        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                executor,
                nmap.quick_scan,
                target
            )
            return result

        except Exception as e:
            return OutputFormatter.format_error(
                "exception",
                f"Quick scan error: {str(e)}"
            )

    @mcp.tool
    async def nmap_comprehensive_scan(target: str) -> Dict[str, Any]:
        """Comprehensive scan with OS detection, version detection, and default scripts.

        Args:
            target: IP address or hostname

        Returns:
            Comprehensive scan results

        Note: This is a long-running operation (may require root for some features).

        Example:
            {
              "status": "success",
              "target": "192.168.1.1",
              "open_ports": [...],
              "os": {...}
            }
        """
        if not SecurityValidator.validate_target(target):
            return OutputFormatter.format_error(
                "validation",
                "Invalid target address"
            )

        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                executor,
                nmap.comprehensive_scan,
                target
            )
            return result

        except Exception as e:
            return OutputFormatter.format_error(
                "exception",
                f"Comprehensive scan error: {str(e)}"
            )
