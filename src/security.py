"""Security validation utilities for tool inputs."""

from __future__ import annotations

import ipaddress
import os
import re
from typing import Iterable


_DISPLAY_FILTER_ALLOWED = re.compile(
    r"^[A-Za-z0-9\s\._:\-\(\)\[\]\=\!\<\>\&\|\+\*\/,\'\"]+$"
)


def ensure_pcap_path(pcap_path: str) -> str:
    """Validate and normalize a PCAP/PCAPNG path."""
    if not pcap_path:
        raise ValueError("pcap_path is required")
    abs_path = os.path.abspath(pcap_path)
    if not os.path.isfile(abs_path):
        raise FileNotFoundError(f"pcap file not found: {abs_path}")
    if not abs_path.lower().endswith((".pcap", ".pcapng")):
        raise ValueError("pcap_path must end with .pcap or .pcapng")
    return abs_path


def validate_display_filter(filter_expr: str) -> str:
    """Whitelist validation for Wireshark display filter expressions."""
    if filter_expr is None:
        raise ValueError("display filter is required")
    cleaned = filter_expr.strip()
    if not cleaned:
        raise ValueError("display filter cannot be empty")
    if "\n" in cleaned or "\r" in cleaned:
        raise ValueError("display filter contains newline characters")
    if not _DISPLAY_FILTER_ALLOWED.fullmatch(cleaned):
        raise ValueError("display filter contains illegal characters")
    return cleaned


def validate_ip(ip_value: str) -> str:
    """Validate IPv4/IPv6 addresses."""
    if not ip_value:
        raise ValueError("ip address is required")
    try:
        ipaddress.ip_address(ip_value)
    except ValueError as exc:
        raise ValueError(f"invalid ip address: {ip_value}") from exc
    return ip_value


def validate_port(port_value: str | int | None) -> int | None:
    """Validate TCP/UDP port values."""
    if port_value in (None, "", "null"):
        return None
    try:
        port_int = int(port_value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid port: {port_value}") from exc
    if not 1 <= port_int <= 65535:
        raise ValueError(f"port out of range: {port_int}")
    return port_int


def limit_list(values: Iterable, max_items: int) -> list:
    """Limit a list-like iterable to a maximum number of items."""
    if max_items <= 0:
        return []
    return list(values)[:max_items]
