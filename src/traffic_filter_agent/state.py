"""State schema for the Traffic Filter Agent graph."""

from typing import TypedDict


class AgentState(TypedDict):
    """Shared state passed between nodes in the graph.

    Attributes:
        messages: Conversation history (HumanMessage, AIMessage, ToolMessage).
        pcap_file: Path to the PCAP file being analyzed, if any.
        filter_query: Wireshark display filter string.
        analysis_result: Structured output from the last analysis step.
        next_action: Routing hint set by nodes (e.g., "analyze", "end").
    """

    messages: list
    pcap_file: str | None
    filter_query: str
    analysis_result: str
    next_action: str
