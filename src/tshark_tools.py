"""Minimal TShark wrapper with defensive limits."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass

from .security import ensure_pcap_path, validate_display_filter


@dataclass(frozen=True)
class TsharkConfig:
    max_packets: int = 100
    tshark_path: str | None = None


def _resolve_tshark_path(config: TsharkConfig) -> str:
    if config.tshark_path:
        return config.tshark_path
    env_path = os.getenv("TSHARK_PATH")
    if env_path:
        return env_path
    resolved = shutil.which("tshark")
    if not resolved:
        raise FileNotFoundError(
            "tshark not found. Install Wireshark/TShark or set TSHARK_PATH."
        )
    return resolved


def _run_tshark(args: list[str]) -> str:
    result = subprocess.run(
        args,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _truncate_text(text: str, max_chars: int = 20000) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n...<truncated>"


def get_protocol_hierarchy(pcap_path: str, config: TsharkConfig) -> str:
    pcap_path = ensure_pcap_path(pcap_path)
    tshark = _resolve_tshark_path(config)
    output = _run_tshark(
        [tshark, "-r", pcap_path, "-q", "-z", "io,phs", "-n"]
    )
    return _truncate_text(output)


def get_ip_conversations(pcap_path: str, config: TsharkConfig) -> str:
    pcap_path = ensure_pcap_path(pcap_path)
    tshark = _resolve_tshark_path(config)
    output = _run_tshark(
        [tshark, "-r", pcap_path, "-q", "-z", "conv,ip", "-n"]
    )
    return _truncate_text(output)


def export_packets_json(
    pcap_path: str, display_filter: str, config: TsharkConfig
) -> str:
    pcap_path = ensure_pcap_path(pcap_path)
    display_filter = validate_display_filter(display_filter)
    tshark = _resolve_tshark_path(config)
    output = _run_tshark(
        [
            tshark,
            "-r",
            pcap_path,
            "-Y",
            display_filter,
            "-T",
            "json",
            "-c",
            str(config.max_packets),
            "-n",
        ]
    )
    return _truncate_text(output)


def export_packets_hex(
    pcap_path: str, display_filter: str, config: TsharkConfig
) -> str:
    pcap_path = ensure_pcap_path(pcap_path)
    display_filter = validate_display_filter(display_filter)
    tshark = _resolve_tshark_path(config)
    output = _run_tshark(
        [
            tshark,
            "-r",
            pcap_path,
            "-Y",
            display_filter,
            "-x",
            "-c",
            str(config.max_packets),
            "-n",
        ]
    )
    return _truncate_text(output)
