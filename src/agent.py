"""Conversational agent graph for LangGraph Studio.

Exposes Wireshark-MCP tools to an LLM agent so users can upload .pcapng files
and interactively analyse network traffic through the chat interface.
"""

from __future__ import annotations

import json
import os
from typing import Annotated, Any

import anyio
from langchain_core.messages import SystemMessage
from langchain_core.tools import tool
from langgraph.prebuilt import create_react_agent

from .graph import build_graph
from .mcp_client import WiresharkMCPClient
from .model_provider import create_chat_model
from .security import ensure_pcap_path_async
from .state import TrafficAnalysisState

SYSTEM_PROMPT = """\
You are a professional network traffic analysis agent. You have access to Wireshark-MCP tools
for deep packet inspection of PCAP/PCAPNG files.

## File handling

Users may upload .pcap/.pcapng files through the chat interface. When a user attaches a file,
the uploaded file path appears in the message — use it directly with your tools. You can also
accept a manually typed absolute file path.

**Important**: When you detect a .pcap/.pcapng file path in the user's message (whether from
an upload or typed manually), immediately begin the analysis workflow below. Do NOT ask the
user to confirm or provide additional information — just start analysing.

## Analysis workflow

1. get_capture_file_info — understand the file metadata (size, packet count, duration)
2. get_protocol_statistics — macro-level protocol distribution and IP conversation stats
3. list_tcp_streams — enumerate all TCP conversations, spot unusual connections
4. Identify suspicious IPs/ports, then use export_packets_json with precise Wireshark display
   filters for deep packet-level inspection (e.g. "ip.addr == x.x.x.x && tcp.port == 443")
5. check_ip_threat_intel on external/public IPs against AbuseIPDB/URLhaus
6. follow_tcp_stream on any streams that look malicious for payload reconstruction
7. Synthesise all findings into a structured security audit report in Markdown (Chinese)

## Rules

- If a tool returns an error, explain it to the user and suggest next steps.
- Write the final report in Chinese.
"""



def _make_tools(mcp: WiresharkMCPClient, pipeline_graph):
    @tool
    async def run_traffic_analysis(filepath: str) -> str:
        """Run the fully automated 5-stage traffic analysis pipeline on a PCAP file.

        This is a one-shot, end-to-end analysis that produces a complete Markdown
        security audit report in Chinese. Use this when the user wants a comprehensive
        automated report without step-by-step interactive guidance.

        The pipeline: macro_triage → target_extraction → micro_deepdive → threat_intel → report_synthesis

        Args:
            filepath: Absolute path to the .pcap or .pcapng file.
        """
        path = await ensure_pcap_path_async(filepath)
        initial_state: TrafficAnalysisState = {
            "pcap_path": path,
            "macro_stats": {},
            "suspicious_targets": [],
            "tshark_filters": [],
            "micro_details": [],
            "threat_intel": [],
            "final_report": "",
        }
        result = await anyio.to_thread.run_sync(pipeline_graph.invoke, initial_state)
        return result.get("final_report", "")

    @tool
    async def get_capture_file_info(filepath: str) -> str:
        """Get metadata for a PCAP/PCAPNG file: size, packet count, duration, encapsulation type, etc.

        Args:
            filepath: Absolute path to the .pcap or .pcapng file.
        """
        path = await ensure_pcap_path_async(filepath)
        result = await mcp.call_tool("get_capture_file_info", {"filepath": path})
        return json.dumps(result, ensure_ascii=False, indent=2)

    @tool
    async def get_protocol_statistics(filepath: str) -> str:
        """Get protocol hierarchy distribution and IP conversation statistics from a PCAP file.

        Call this first to understand the macro-level traffic composition.

        Args:
            filepath: Absolute path to the .pcap or .pcapng file.
        """
        path = await ensure_pcap_path_async(filepath)
        result = await mcp.call_tool("get_protocol_statistics", {"filepath": path})
        return json.dumps(result, ensure_ascii=False, indent=2)

    @tool
    async def export_packets_json(
        filepath: str,
        display_filter: str,
        max_packets: Annotated[int, "Maximum packets to export, capped at 100"] = 100,
    ) -> str:
        """Export packets matching a Wireshark display filter to structured JSON.

        Use this for deep packet inspection on specific IPs, ports, or protocols.
        Examples of display filters:
          - ip.addr == 192.168.1.100
          - tcp.port == 443
          - ip.addr == 10.0.0.5 && (tcp.port == 80 || udp.port == 53)
          - http.request or dns

        Args:
            filepath: Absolute path to the .pcap or .pcapng file.
            display_filter: A valid Wireshark display filter string.
            max_packets: Maximum number of packets to return (1-100).
        """
        path = await ensure_pcap_path_async(filepath)
        safe_max = min(max(max_packets, 1), 100)
        result = await mcp.call_tool(
            "export_packets_json",
            {"filepath": path, "display_filter": display_filter, "max_packets": safe_max},
        )
        return json.dumps(result, ensure_ascii=False, indent=2)

    @tool
    async def check_ip_threat_intel(ip_addresses: str) -> str:
        """Check IP addresses against threat intelligence databases (AbuseIPDB, URLhaus).

        Args:
            ip_addresses: Comma-separated list of IP addresses to check (e.g. "8.8.8.8,1.1.1.1").
        """
        ips = [ip.strip() for ip in ip_addresses.split(",") if ip.strip()]
        if not ips:
            return json.dumps({"error": "no valid IP addresses provided"}, ensure_ascii=False)
        result = await mcp.call_tool(
            "check_ip_threat_intel",
            {"ip_or_filepath": ",".join(ips), "providers": "urlhaus,abuseipdb"},
        )
        return json.dumps(result, ensure_ascii=False, indent=2)

    @tool
    async def scan_capture_for_threats(filepath: str) -> str:
        """Run a comprehensive threat scan on a PCAP file.

        Extracts all IP addresses, checks them against threat intelligence,
        and returns a summary report of any malicious indicators.

        Args:
            filepath: Absolute path to the .pcap or .pcapng file.
        """
        path = await ensure_pcap_path_async(filepath)
        result = await mcp.call_tool("scan_capture_for_threats", {"filepath": path})
        return json.dumps(result, ensure_ascii=False, indent=2)

    @tool
    async def list_tcp_streams(filepath: str) -> str:
        """List all TCP conversations/streams in a PCAP file with endpoint addresses and ports.

        Useful for identifying communication pairs and spotting unusual connections.

        Args:
            filepath: Absolute path to the .pcap or .pcapng file.
        """
        path = await ensure_pcap_path_async(filepath)
        result = await mcp.call_tool("list_tcp_streams", {"filepath": path})
        return json.dumps(result, ensure_ascii=False, indent=2)

    @tool
    async def follow_tcp_stream(filepath: str, stream_index: int) -> str:
        """Follow and reconstruct a specific TCP stream's conversation data.

        Args:
            filepath: Absolute path to the .pcap or .pcapng file.
            stream_index: The 0-based index of the TCP stream to follow.
        """
        path = await ensure_pcap_path_async(filepath)
        result = await mcp.call_tool(
            "follow_tcp_stream", {"filepath": path, "stream_index": stream_index}
        )
        return json.dumps(result, ensure_ascii=False, indent=2)

    return [
        run_traffic_analysis,
        get_capture_file_info,
        get_protocol_statistics,
        list_tcp_streams,
        export_packets_json,
        follow_tcp_stream,
        check_ip_threat_intel,
        scan_capture_for_threats,
    ]


def _get_agent_graph():
    """Build and return the compiled agent graph from environment variables."""
    provider = os.getenv("MODEL_PROVIDER", "deepseek").lower()
    model_name = os.getenv("MODEL_NAME")
    if not model_name:
        if provider == "deepseek":
            model_name = os.getenv("DEEPSEEK_MODEL", "deepseek-v4-pro")
        else:
            model_name = os.getenv("OPENAI_MODEL", "gpt-4o")

    model = create_chat_model(
        provider=provider,
        model_name=model_name,
        temperature=0,
        base_url=None,
    )
    mcp_client = WiresharkMCPClient.from_env()
    pipeline_graph = build_graph(model=model, mcp_client=mcp_client)
    tools = _make_tools(mcp_client, pipeline_graph)

    return create_react_agent(
        model=model,
        tools=tools,
        prompt=SystemMessage(content=SYSTEM_PROMPT),
    )


# Module-level compiled graph for "langgraph dev" server.
agent_graph = _get_agent_graph()
