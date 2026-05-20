# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

Traffic Filter Agent — a LangGraph-based network traffic analysis agent. It ingests PCAP/PCAPNG files and produces a Markdown security audit report through a 5-node funnel pipeline. The agent detects VPN traffic, malware C2 communication, and anomalous behavior using Tshark (via Wireshark-MCP), threat intelligence lookups, and LLM-driven deep packet inspection.

## Commands

```bash
# Run a PCAP analysis from the CLI
.venv/Scripts/python -m src --pcap <path-to-pcap>

# Start the LangGraph API dev server (hot-reload enabled)
.venv/Scripts/langgraph dev

# Install project dependencies
.venv/Scripts/pip install -r requirements.txt
```

No test suite exists yet. When adding tests, use `pytest`.

## Architecture

```
[Start] → macro_triage → target_extraction → micro_deepdive → threat_intel → report_synthesis → [END]
```

The workflow is a linear StateGraph in `src/graph.py` with five nodes defined in `src/nodes.py`. State is a `TrafficAnalysisState` TypedDict (`src/state.py`) shared across all nodes.

| Node | Purpose | Tool calls |
|---|---|---|
| `macro_triage` | Protocol/endpoint stats, identify Top-10 suspicious IPs | `get_protocol_statistics` |
| `target_extraction` | Convert suspicious targets into Tshark display filters | None (LLM-only) |
| `micro_deepdive` | Deep packet inspection per filter; detect VPN, C2 beaconing, lateral movement | `export_packets_json` |
| `threat_intel` | Check external IPs against AbuseIPDB / URLhaus | `check_ip_threat_intel` |
| `report_synthesis` | Compile findings into a Markdown audit report | None (LLM-only) |

### Key source files

- `src/graph.py` — graph builder + module-level `graph` used by `langgraph dev`
- `src/nodes.py` — all five node implementations with `NodeConfig` dataclass
- `src/state.py` — `TrafficAnalysisState` TypedDict schema
- `src/prompts.py` — Chinese-language system/user prompt templates for each node
- `src/mcp_client.py` — stdio MCP client wrapping Wireshark-MCP server (launched as a subprocess)
- `src/model_provider.py` — factory for DeepSeek and OpenAI chat models via `langchain-openai`
- `src/security.py` — input validation: BPF filter whitelist, IP/port validation, path guards
- `src/__main__.py` — CLI entry point (`--pcap`, `--provider`, `--model`, `--max-packets`, `--max-iterations`)

### External dependency

Wireshark-MCP lives at `external/Wireshark-MCP/` with its own `.venv`. The `WiresharkMCPClient` (`src/mcp_client.py`) spawns the MCP server as a subprocess via `mcp.client.stdio`. Environment variables controlling this:

- `WIRESHARK_MCP_PYTHON` — path to the Python interpreter in Wireshark-MCP's venv
- `WIRESHARK_MCP_SERVER` — path to `wireshark-mcp-server.py`
- `WIRESHARK_MCP_CWD` — working directory for the server process
- `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY`, `TSHARK_PATH` — forwarded to the MCP server

## Environment setup

Copy `.env` and fill in the required keys:

| Variable | Required | Purpose |
|---|---|---|
| `DEEPSEEK_API_KEY` | For DeepSeek | API key for DeepSeek provider |
| `OPENAI_API_KEY` | For OpenAI | API key for OpenAI provider |
| `MODEL_PROVIDER` | Yes | `deepseek` or `openai` |
| `MODEL_NAME` | No | Override the default model name |
| `ABUSEIPDB_API_KEY` | Optional | Threat intel lookups in node 4 |

## Defensive coding constraints (from `instruction.md`)

These are hard requirements, not suggestions:

1. **Command injection prevention** — all Tshark display filters pass through `validate_display_filter()` which whitelists BPF-safe characters only. IPs and ports are validated with `validate_ip()` / `validate_port()` before use.
2. **ReAct circuit breaker** — `micro_deepdive_node` loop is capped at `max_iterations` (default 5). Never remove this guard.
3. **Token cascade control** — packets per filter are hard-capped at `max_packets` (default 100, max 100). The CLI enforces `min(args.max_packets, 100)`.
4. **Funnel triage principle** — never feed raw full PCAP data directly to the LLM. Always filter through the node pipeline to reduce data volume exponentially at each stage.

## Design philosophy

- **Macro deterministic + micro exploratory**: The LangGraph topology is fixed and deterministic. Only `micro_deepdive_node` uses an LLM ReAct loop for flexible deep inspection.
- **Chinese-language prompts**: All system/user prompt templates in `src/prompts.py` are in Chinese. The final report is generated in Chinese.
