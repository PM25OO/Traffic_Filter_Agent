"""LangChain tools wrapping Wireshark MCP server via langchain-mcp-adapters."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, List

from langchain.tools import tool
from langchain_mcp_adapters.client import MultiServerMCPClient
from mcp import ClientSession


def _payload_to_json(payload: Any) -> str:
    if isinstance(payload, dict) and "data" in payload:
        payload = payload.get("data")
    try:
        return json.dumps(payload, ensure_ascii=False, indent=2)
    except TypeError:
        return str(payload)


def _extract_result(result: Any) -> Any:
    """Extract usable data from a CallToolResult."""
    if result.structuredContent is not None:
        return result.structuredContent
    text_parts = []
    for block in result.content:
        text = getattr(block, "text", None)
        if isinstance(text, str) and text:
            text_parts.append(text)
    text = "\n".join(text_parts)
    if text:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"text": text}
    return {}


def build_mcp_client() -> MultiServerMCPClient:
    """Build a MultiServerMCPClient configured for the Wireshark-MCP server.

    Environment variables:
        WIRESHARK_MCP_PYTHON — override Python interpreter path
        WIRESHARK_MCP_SERVER  — override server script path
        WIRESHARK_MCP_CWD     — override working directory
        ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY, TSHARK_PATH — forwarded to server
    """
    root = Path(__file__).resolve().parents[1]
    external = root / "external" / "Wireshark-MCP"

    python_path = os.getenv("WIRESHARK_MCP_PYTHON") or str(
        external / ".venv" / "Scripts" / "python.exe"
    )
    server_script = os.getenv("WIRESHARK_MCP_SERVER") or str(
        external / "wireshark-mcp-server.py"
    )
    cwd = os.getenv("WIRESHARK_MCP_CWD") or str(external)

    env: dict[str, str] = {}
    for key in ("ABUSEIPDB_API_KEY", "VIRUSTOTAL_API_KEY", "TSHARK_PATH"):
        value = os.getenv(key)
        if value:
            env[key] = value

    config: dict[str, Any] = {
        "transport": "stdio",
        "command": python_path,
        "args": [server_script],
        "cwd": cwd,
    }
    if env:
        config["env"] = env

    return MultiServerMCPClient({"wireshark": config})


# ---------------------------------------------------------------------------
# Macro Triage tools
# ---------------------------------------------------------------------------


def create_macro_triage_tools(
    session: ClientSession, pcap_path: str
) -> List:
    """为宏观分诊阶段创建探索工具：协议统计、文件信息、TCP会话列表。"""

    @tool
    async def get_protocol_statistics() -> str:
        """获取PCAP文件的协议层级统计和IP会话概况。
        包含各协议的包数/字节数占比、端点间通信统计。
        用于了解流量整体构成，识别异常协议使用和可疑通信端点。"""
        result = await session.call_tool(
            "get_protocol_statistics", {"filepath": pcap_path}
        )
        return _payload_to_json(_extract_result(result))

    @tool
    async def get_capture_file_info() -> str:
        """获取捕获文件基本信息：包数量、时间跨度、数据量、捕获接口。
        用于快速了解PCAP规模和时间范围。"""
        result = await session.call_tool(
            "get_capture_file_info", {"filepath": pcap_path}
        )
        return _payload_to_json(_extract_result(result))

    @tool
    async def list_tcp_streams() -> str:
        """列出所有TCP会话及其端点地址、端口、包数、字节数。
        按字节数降序排列，用于快速定位大流量或异常连接。"""
        result = await session.call_tool(
            "list_tcp_streams", {"filepath": pcap_path}
        )
        return _payload_to_json(_extract_result(result))

    return [get_protocol_statistics, get_capture_file_info, list_tcp_streams]


# ---------------------------------------------------------------------------
# Micro Deepdive tools
# ---------------------------------------------------------------------------


def create_micro_deepdive_tools(
    session: ClientSession, pcap_path: str, max_packets: int
) -> List:
    """为微观深度分析阶段创建工具：按过滤器导出包、TCP流跟踪。"""

    @tool
    async def export_packets_json(display_filter: str, max_pkts: int = 50) -> str:
        """按Wireshark显示过滤器导出数据包详情JSON。
        返回每个包的帧号、时间戳、源/目标IP和端口、协议字段、载荷摘要。
        用于获取匹配特定条件的数据包进行逐包分析。

        Args:
            display_filter: Wireshark显示过滤器，如 ip.addr==1.2.3.4 && tcp.port==443
            max_pkts: 最大返回包数，默认50。适当减小可节省分析时间。
        """
        safe_pkts = min(max_pkts, max_packets)
        result = await session.call_tool(
            "export_packets_json",
            {
                "filepath": pcap_path,
                "display_filter": display_filter,
                "max_packets": safe_pkts,
            },
        )
        return _payload_to_json(_extract_result(result))

    @tool
    async def list_tcp_streams() -> str:
        """列出所有TCP会话及端点地址、端口、包数和字节数统计。
        用于在深度分析中发现可疑连接并获取流索引号。"""
        result = await session.call_tool(
            "list_tcp_streams", {"filepath": pcap_path}
        )
        return _payload_to_json(_extract_result(result))

    @tool
    async def follow_tcp_stream(stream_index: int) -> str:
        """跟踪指定TCP流，重建完整的应用层对话内容（ASCII格式）。
        用于深入分析可疑会话的载荷数据，识别C2指令、数据外泄等。

        Args:
            stream_index: TCP流索引号（从0开始），可从list_tcp_streams获取
        """
        result = await session.call_tool(
            "follow_tcp_stream",
            {"filepath": pcap_path, "stream_index": stream_index},
        )
        return _payload_to_json(_extract_result(result))

    return [export_packets_json, list_tcp_streams, follow_tcp_stream]
