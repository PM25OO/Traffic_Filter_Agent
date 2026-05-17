# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Traffic Filter Agent — a LangGraph-based intelligent agent for network traffic analysis, filtering, and threat detection. Uses the Wireshark MCP tools for packet capture/analysis and nmap for network scanning.

## Python Environment

```bash
# Activate the virtual environment (Windows bash/git-bash)
source .venv/Scripts/activate
# Or for PowerShell
.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

## Running the Agent

```bash
# Run the agent
python -m traffic_filter_agent

# Run with custom input
python -m traffic_filter_agent --pcap <filepath>
```

## Architecture

The project follows the standard LangGraph pattern:

- `src/traffic_filter_agent/` — main package
  - `graph.py` — StateGraph definition (nodes, edges, conditional routing)
  - `state.py` — TypedDict state schema
  - `tools.py` — Tool definitions for packet analysis, threat intel lookups
  - `nodes/` — Individual graph node implementations (one per file)

Key LangGraph concepts in use:
- **StateGraph** with typed state schema
- **Checkpointing** (SQLite backend) for conversation persistence
- **ToolNode** for Wireshark/nmap MCP tool execution
- **Conditional edges** for routing based on analysis results

## Key Dependencies

- `langgraph` (1.2+) — graph-based agent orchestration
- `langchain-core` — shared primitives (messages, tools)
- `langchain-openai` — LLM provider integration
- `openai` — OpenAI SDK

## Important Notes

- Wireshark MCP tools (`mcp__wireshark__*`) and nmap tools are available for packet analysis — these are invoked through the agent's tool layer, not directly
- The LLM backend is configured via environment variables (`OPENAI_API_KEY`, `OPENAI_BASE_URL`, `OPENAI_MODEL`)
