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
    return Path(__file__).resolve().parents[1]


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
        self._settings = settings or _default_settings()

    @classmethod
    def from_env(cls) -> "WiresharkMCPClient":
        return cls(_default_settings())

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

    def _call_tool_sync(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return anyio.run(self._call_tool_async, name, arguments)

    async def _call_tool_async(
        self, name: str, arguments: Dict[str, Any]
    ) -> Dict[str, Any]:
        server_params = StdioServerParameters(
            command=self._settings.command,
            args=self._settings.args,
            env=self._settings.env,
            cwd=self._settings.cwd,
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
