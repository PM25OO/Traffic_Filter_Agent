"""LangGraph workflow construction."""

from __future__ import annotations

from langchain_core.language_models.chat_models import BaseChatModel
from langgraph.graph import END, START, StateGraph
from mcp import ClientSession

from .nodes import (
    NodeConfig,
    macro_triage_node,
    micro_deepdive_node,
    report_synthesis_node,
    target_extraction_node,
    threat_intel_node,
)
from .state import TrafficAnalysisState

DEFAULT_MAX_PACKETS = 100
DEFAULT_MAX_ITERATIONS = 5


async def build_graph(
    model: BaseChatModel,
    session: ClientSession,
    max_packets: int = DEFAULT_MAX_PACKETS,
    max_iterations: int = DEFAULT_MAX_ITERATIONS,
):
    """Build and compile the traffic analysis graph.

    Args:
        model: Chat model instance.
        session: An initialized MCP ClientSession connected to Wireshark-MCP.
        max_packets: Hard cap on packets per filter (clamped to 100).
        max_iterations: Max ReAct iterations for micro deepdive.

    Returns:
        A compiled LangGraph graph ready for ainvoke/astream.
    """
    node_config = NodeConfig(
        model=model,
        session=session,
        max_packets=min(max_packets, DEFAULT_MAX_PACKETS),
        max_iterations=max_iterations,
    )

    graph = StateGraph(TrafficAnalysisState)
    graph.add_node("macro_triage", macro_triage_node(node_config))
    graph.add_node("target_extraction", target_extraction_node(node_config))
    graph.add_node("micro_deepdive", micro_deepdive_node(node_config))
    graph.add_node("threat_intel", threat_intel_node(node_config))
    graph.add_node("report_synthesis", report_synthesis_node(node_config))

    graph.add_edge(START, "macro_triage")
    graph.add_edge("macro_triage", "target_extraction")
    graph.add_edge("target_extraction", "micro_deepdive")
    graph.add_edge("micro_deepdive", "threat_intel")
    graph.add_edge("threat_intel", "report_synthesis")
    graph.add_edge("report_synthesis", END)

    return graph.compile()
