"""LangGraph workflow construction."""

from __future__ import annotations

import os
from pathlib import Path as _Path

# Load .env when imported outside of langgraph dev / streamlit run (which load it first).
# Uses setdefault semantics — explicit env vars take priority over .env values.
try:
    from dotenv import load_dotenv as _load_dotenv

    _env_file = _Path(__file__).resolve().parents[1] / ".env"
    if _env_file.exists():
        _load_dotenv(_env_file, override=False)
except ImportError:
    pass

from langchain_core.language_models.chat_models import BaseChatModel
from langgraph.graph import END, START, StateGraph

from .mcp_client import WiresharkMCPClient
from .model_provider import create_chat_model
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



def build_graph(
    model: BaseChatModel,
    mcp_client: WiresharkMCPClient,
    max_packets: int = DEFAULT_MAX_PACKETS,
    max_iterations: int = DEFAULT_MAX_ITERATIONS,
):
    node_config = NodeConfig(
        model=model,
        mcp=mcp_client,
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


def _get_graph():
    """Build and return the compiled graph from environment variables."""
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
    return build_graph(model=model, mcp_client=mcp_client)


# Module-level compiled graph for "langgraph dev" server.
# Reads configuration from environment variables / .env file.
graph = _get_graph()
