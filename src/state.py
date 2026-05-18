"""State schema for the Traffic Filter Agent graph."""

from typing import Any, Dict, List, TypedDict


class TrafficAnalysisState(TypedDict):
    """Shared state passed between nodes in the graph.

    This schema mirrors the contract defined in instruction.md and is used
    across all LangGraph nodes for consistent state transfer.
    """

    pcap_path: str
    macro_stats: Dict[str, Any]
    suspicious_targets: List[Dict[str, Any]]
    tshark_filters: List[str]
    micro_details: List[Dict[str, Any]]
    threat_intel: List[Dict[str, Any]]
    final_report: str
