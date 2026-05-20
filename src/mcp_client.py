"""Wireshark-MCP stdio client wrapper."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

import anyio
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


@dataclass(frozen=True)
class MCPServerSettings:
    command: str
    args: list[str]
    cwd: str | None = None
    env: dict[str, str] | None = None


def _project_root() -> Path:
    return Path(__file__).parents[1]


def _default_settings() -> MCPServerSettings:
    root = _project_root()
    external_root = root / "external" / "Wireshark-MCP"
    python_path = os.getenv("WIRESHARK_MCP_PYTHON") or str(
        external_root / ".venv" / "Scripts" / "python.exe"
    )
    server_script = os.getenv("WIRESHARK_MCP_SERVER") or str(
        external_root / "wireshark-mcp-server.py"
    )
    cwd = os.getenv("WIRESHARK_MCP_CWD") or str(external_root)

    env: Dict[str, str] = {}
    for key in ("ABUSEIPDB_API_KEY", "VIRUSTOTAL_API_KEY", "TSHARK_PATH"):
        value = os.getenv(key)
        if value:
            env[key] = value

    return MCPServerSettings(
        command=python_path,
        args=[server_script],
        cwd=cwd,
        env=env or None,
    )


def _content_blocks_to_text(blocks: Iterable[Any]) -> str:
    chunks: list[str] = []
    for block in blocks:
        text = getattr(block, "text", None)
        if isinstance(text, str) and text:
            chunks.append(text)
    return "\n".join(chunks)


class WiresharkMCPClient:
    """Thin wrapper around MCP stdio client for Wireshark-MCP tools."""

    def __init__(self, settings: MCPServerSettings | None = None) -> None:
        self._settings = settings

    @classmethod
    def from_env(cls) -> "WiresharkMCPClient":
        return cls()

    def _get_settings(self) -> MCPServerSettings:
        if self._settings is None:
            self._settings = _default_settings()
        return self._settings

    def get_protocol_statistics(self, filepath: str) -> Dict[str, Any]:
        return self._call_tool_sync(
            "get_protocol_statistics",
            {"filepath": filepath},
        )

    def export_packets_json(
        self, filepath: str, display_filter: str, max_packets: int
    ) -> Dict[str, Any]:
        return self._call_tool_sync(
            "export_packets_json",
            {
                "filepath": filepath,
                "display_filter": display_filter,
                "max_packets": max_packets,
            },
        )

    def check_ip_threat_intel(
        self, ip_addresses: list[str], providers: str
    ) -> Dict[str, Any]:
        ip_or_filepath = ",".join(ip_addresses)
        return self._call_tool_sync(
            "check_ip_threat_intel",
            {"ip_or_filepath": ip_or_filepath, "providers": providers},
        )

    def get_capture_file_info(self, filepath: str) -> Dict[str, Any]:
        return self._call_tool_sync(
            "get_capture_file_info",
            {"filepath": filepath},
        )

    def scan_capture_for_threats(self, filepath: str) -> Dict[str, Any]:
        return self._call_tool_sync(
            "scan_capture_for_threats",
            {"filepath": filepath},
        )

    def list_tcp_streams(self, filepath: str) -> Dict[str, Any]:
        return self._call_tool_sync(
            "list_tcp_streams",
            {"filepath": filepath},
        )

    def follow_tcp_stream(
        self, filepath: str, stream_index: int
    ) -> Dict[str, Any]:
        return self._call_tool_sync(
            "follow_tcp_stream",
            {"filepath": filepath, "stream_index": stream_index},
        )

    def _call_tool_sync(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return anyio.run(self.call_tool, name, arguments)

    async def call_tool(
        self, name: str, arguments: Dict[str, Any]
    ) -> Dict[str, Any]:
        settings = self._get_settings()
        server_params = StdioServerParameters(
            command=settings.command,
            args=settings.args,
            env=settings.env,
            cwd=settings.cwd,
        )

        async with stdio_client(server_params) as (read_stream, write_stream):
            session = ClientSession(read_stream, write_stream)
            await session.initialize()
            result = await session.call_tool(name, arguments)

        if result.isError:
            message = _content_blocks_to_text(result.content)
            raise RuntimeError(f"MCP tool call failed: {name}: {message}")

        if result.structuredContent is not None:
            return result.structuredContent

        text_payload = _content_blocks_to_text(result.content)
        if text_payload:
            try:
                return json.loads(text_payload)
            except json.JSONDecodeError:
                return {"text": text_payload}

        return {}
