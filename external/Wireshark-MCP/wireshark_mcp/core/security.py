"""Security validation utilities for network analysis operations."""

import re
import ipaddress
from pathlib import Path
from typing import Optional


class SecurityValidator:
    """Input validation and security controls."""

    # Allowed interface patterns (Windows and Linux)
    INTERFACE_PATTERNS = [
        r'^(eth|wlan|lo|en|enp|wlp|docker|br-)[a-zA-Z0-9]{1,15}$',  # Linux
        r'^Ethernet \d+$',  # Windows Ethernet
        r'^Wi-Fi \d*$',  # Windows WiFi
        r'^Local Area Connection \d*$',  # Windows LAN
        r'^\d+$'  # Interface number
    ]

    # Security limits
    MAX_CAPTURE_DURATION = 300  # 5 minutes
    MAX_PACKET_COUNT = 10000  # Maximum packets per capture
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB

    # Nmap rate limiting
    MAX_NMAP_SCANS_PER_HOUR = 10
    NMAP_SCAN_HISTORY_SIZE = 100

    @staticmethod
    def validate_interface(interface: str) -> bool:
        """Validate network interface name against allowed patterns.

        Args:
            interface: Network interface name to validate

        Returns:
            True if interface name is valid, False otherwise
        """
        if not interface or len(interface) > 50:
            return False

        return any(
            re.match(pattern, interface)
            for pattern in SecurityValidator.INTERFACE_PATTERNS
        )

    @staticmethod
    def validate_capture_filter(filter_expr: str) -> bool:
        """Validate BPF capture filter expression.

        Args:
            filter_expr: BPF filter expression to validate

        Returns:
            True if filter is safe, False if potentially dangerous
        """
        if not filter_expr:
            return True

        # Check for dangerous patterns (command injection attempts)
        dangerous_patterns = [';', '|', '&', '$(', '`', '\n', '\r', '..']
        if any(pattern in filter_expr for pattern in dangerous_patterns):
            return False

        # Basic length check
        return len(filter_expr) < 500

    @staticmethod
    def sanitize_filepath(filepath: str) -> Optional[str]:
        """Sanitize and validate file paths.

        Args:
            filepath: Path to validate and resolve

        Returns:
            Resolved absolute path if valid, None otherwise
        """
        try:
            resolved_path = Path(filepath).resolve()

            # Check if file exists
            if not resolved_path.exists():
                return None

            # Check file extension
            if resolved_path.suffix.lower() not in ['.pcap', '.pcapng', '.cap']:
                return None

            # Check file size
            if resolved_path.stat().st_size > SecurityValidator.MAX_FILE_SIZE:
                return None

            return str(resolved_path)
        except Exception:
            return None

    @staticmethod
    def validate_target(target: str) -> bool:
        """Validate IP/CIDR/hostname target for nmap scanning.

        Args:
            target: Target specification (IP, CIDR, or hostname)

        Returns:
            True if target is valid, False otherwise

        Security: Prevents command injection via target specification.
        """
        if not target or len(target) > 255:
            return False

        # Check for command injection attempts
        dangerous_chars = [';', '|', '&', '$', '`', '\n', '\r', '<', '>', '\\']
        if any(char in target for char in dangerous_chars):
            return False

        # Try parsing as IP/CIDR
        try:
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            pass

        # Try hostname validation (RFC 1123)
        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(hostname_pattern, target))

    @staticmethod
    def validate_port_range(ports: str) -> bool:
        """Validate port specification for nmap.

        Args:
            ports: Port specification (e.g., "80", "1-1000", "22,80,443")

        Returns:
            True if port specification is valid, False otherwise

        Security: Prevents command injection via port specification.
        """
        if not ports:
            return True

        # Check for command injection
        if any(char in ports for char in [';', '|', '&', '$', '`', '\n', '\r', '<', '>']):
            return False

        # Validate format: single ports, ranges, or comma-separated
        pattern = r'^(\d+(-\d+)?)(,\d+(-\d+)?)*$'
        if not re.match(pattern, ports):
            return False

        # Validate port numbers are in valid range (1-65535)
        for part in ports.split(','):
            if '-' in part:
                start, end = part.split('-')
                if not (1 <= int(start) <= 65535 and 1 <= int(end) <= 65535):
                    return False
                if int(start) > int(end):
                    return False
            else:
                if not (1 <= int(part) <= 65535):
                    return False

        return True

    @staticmethod
    def validate_nmap_flags(flags: list) -> bool:
        """Validate nmap command flags for security.

        Args:
            flags: List of nmap flags to validate

        Returns:
            True if all flags are safe, False if any are dangerous

        Security: Prevents execution of dangerous nmap operations.
        """
        # Whitelist of allowed flags
        allowed_flags = {
            '-sT', '-sS', '-sU', '-sV', '-O', '-A', '-p', '-oX', '-Pn',
            '--top-ports', '--version-intensity', '--osscan-limit',
            '--max-retries', '--host-timeout'
        }

        # Dangerous flags that should never be allowed
        dangerous_flags = {
            '--script=exploit',  # Exploitation scripts
            '--script-args',  # Arbitrary script arguments
            '--privileged',  # Force privileged mode
            '--datadir',  # Custom data directory
            '--servicedb',  # Custom service database
            '--script-updatedb',  # Update script database
        }

        for flag in flags:
            flag_name = flag.split('=')[0] if '=' in flag else flag

            # Reject dangerous flags
            if any(dangerous in flag for dangerous in dangerous_flags):
                return False

            # Only allow whitelisted flags (for flags that start with -)
            if flag_name.startswith('-') and flag_name not in allowed_flags:
                # Allow specific value flags
                if '=' in flag and flag_name in allowed_flags:
                    continue
                return False

        return True

    @staticmethod
    def validate_display_filter(filter_expr: str) -> bool:
        """Validate Wireshark display filter expression.

        Args:
            filter_expr: Display filter to validate

        Returns:
            True if filter is safe, False if potentially dangerous
        """
        if not filter_expr:
            return True

        # Similar to capture filter validation
        dangerous_patterns = [';', '|', '&', '$(', '`', '\n', '\r']
        if any(pattern in filter_expr for pattern in dangerous_patterns):
            return False

        return len(filter_expr) < 1000
