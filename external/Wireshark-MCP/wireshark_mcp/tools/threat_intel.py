"""Threat intelligence tools."""

import asyncio
import re
from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor

from ..core.security import SecurityValidator
from ..core.output_formatter import OutputFormatter


def register_threat_intel_tools(mcp, threat_intel, wireshark, executor: ThreadPoolExecutor):
    """Register threat intelligence tools.

    Args:
        mcp: FastMCP instance
        threat_intel: ThreatIntelInterface instance
        wireshark: WiresharkInterface instance (for IP extraction)
        executor: ThreadPoolExecutor for async operations
    """

    @mcp.tool
    async def check_ip_threat_intel(
        ip_or_filepath: str,
        providers: str = "urlhaus"
    ) -> Dict[str, Any]:
        """Check IP addresses against threat intelligence databases.

        Args:
            ip_or_filepath: Single IP address, comma-separated IPs, or PCAP file path
            providers: Comma-separated providers ("urlhaus", "abuseipdb")

        Returns:
            Threat intelligence results for each IP

        Example:
            check_ip_threat_intel("1.2.3.4,5.6.7.8", "urlhaus,abuseipdb")
            check_ip_threat_intel("/path/to/capture.pcap", "urlhaus")

        Note: AbuseIPDB requires ABUSEIPDB_API_KEY environment variable
        """
        provider_list = [p.strip() for p in providers.split(",")]

        # Determine if input is file or IPs
        if "/" in ip_or_filepath or "\\" in ip_or_filepath:
            # Treat as file path
            sanitized_path = SecurityValidator.sanitize_filepath(ip_or_filepath)
            if not sanitized_path:
                return OutputFormatter.format_error(
                    "validation",
                    "Invalid or inaccessible file path"
                )

            # Extract IPs from PCAP
            ips = await _extract_ips_from_pcap(sanitized_path, wireshark, executor)
        else:
            # Treat as comma-separated IPs
            ips = [ip.strip() for ip in ip_or_filepath.split(",")]

            # Validate IPs
            for ip in ips:
                if not SecurityValidator.validate_target(ip):
                    return OutputFormatter.format_error(
                        "validation",
                        f"Invalid IP address: {ip}"
                    )

        # Check against threat intel
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                executor,
                threat_intel.check_multiple_ips,
                ips, provider_list
            )
            return result

        except Exception as e:
            return OutputFormatter.format_error(
                "exception",
                f"Threat intelligence check error: {str(e)}"
            )

    @mcp.tool
    async def scan_capture_for_threats(
        filepath: str,
        providers: str = "urlhaus"
    ) -> Dict[str, Any]:
        """Comprehensive threat scan of PCAP file.

        Extracts all IPs and checks against threat intelligence, providing
        a summary report of malicious traffic.

        Args:
            filepath: Path to PCAP file
            providers: Comma-separated threat intel providers

        Returns:
            Threat analysis report

        Example:
            {
              "status": "success",
              "total_ips": 45,
              "threats_found": 3,
              "malicious_ips": ["1.2.3.4", "5.6.7.8"],
              "results": [...]
            }
        """
        # Validate file path
        sanitized_path = SecurityValidator.sanitize_filepath(filepath)
        if not sanitized_path:
            return OutputFormatter.format_error(
                "validation",
                "Invalid or inaccessible file path"
            )

        provider_list = [p.strip() for p in providers.split(",")]

        try:
            # Extract unique IPs
            ips = await _extract_ips_from_pcap(sanitized_path, wireshark, executor)

            # Check threat intel
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                executor,
                threat_intel.check_multiple_ips,
                ips, provider_list
            )

            # Add summary
            if result.get("status") == "success":
                malicious_ips = [
                    r["ip"] for r in result["results"]
                    if r.get("threat_found", False)
                ]
                result["malicious_ips"] = malicious_ips

                # Generate summary
                if malicious_ips:
                    result["summary"] = f"Found {len(malicious_ips)} malicious IPs out of {len(ips)} total unique IPs"
                else:
                    result["summary"] = f"No threats found among {len(ips)} unique IPs"

            return result

        except Exception as e:
            return OutputFormatter.format_error(
                "exception",
                f"Threat scan error: {str(e)}"
            )


async def _extract_ips_from_pcap(
    filepath: str,
    wireshark,
    executor: ThreadPoolExecutor
) -> List[str]:
    """Extract unique IP addresses from PCAP file.

    Args:
        filepath: Path to PCAP file
        wireshark: WiresharkInterface instance
        executor: ThreadPoolExecutor

    Returns:
        List of unique IP addresses
    """
    # Analyze PCAP to get packets
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        executor,
        wireshark.analyze_pcap_file,
        filepath, "", 1000
    )

    if result.get("status") != "success":
        return []

    # Extract IPs from packets
    ips = set()
    for packet in result.get("packets", []):
        if "_source" in packet and "layers" in packet["_source"]:
            layers = packet["_source"]["layers"]
            if "ip" in layers:
                ip_layer = layers["ip"]
                src = ip_layer.get("ip_ip_src")
                dst = ip_layer.get("ip_ip_dst")
                if src:
                    ips.add(src)
                if dst:
                    ips.add(dst)

    # Filter out private IPs (focus on external threats)
    external_ips = []
    for ip in ips:
        if not _is_private_ip(ip):
            external_ips.append(ip)

    return external_ips


def _is_private_ip(ip: str) -> bool:
    """Check if IP is private/internal.

    Args:
        ip: IP address string

    Returns:
        True if private, False if public
    """
    # RFC 1918 private ranges
    private_patterns = [
        r'^10\.',
        r'^172\.(1[6-9]|2[0-9]|3[01])\.',
        r'^192\.168\.',
        r'^127\.',
        r'^169\.254\.',
        r'^::1$',
        r'^fe80:'
    ]

    return any(re.match(pattern, ip) for pattern in private_patterns)
