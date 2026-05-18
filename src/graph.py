"""LangGraph workflow construction."""

from __future__ import annotations

from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, StateGraph

from .nodes import (
    NodeConfig,
    macro_triage_node,
    micro_deepdive_node,
    report_synthesis_node,
    target_extraction_node,
    threat_intel_node,
)
from .state import TrafficAnalysisState
from .tshark_tools import TsharkConfig

DEFAULT_MAX_PACKETS = 100
DEFAULT_MAX_ITERATIONS = 5


def build_graph(
    model_name: str,
    temperature: float,
    max_packets: int = DEFAULT_MAX_PACKETS,
    max_iterations: int = DEFAULT_MAX_ITERATIONS,
):
    model = ChatOpenAI(model=model_name, temperature=temperature)
    tshark_config = TsharkConfig(max_packets=min(max_packets, DEFAULT_MAX_PACKETS))
    node_config = NodeConfig(
        model=model,
        tshark=tshark_config,
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
