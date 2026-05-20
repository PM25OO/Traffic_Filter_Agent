# Wireshark MCP — Current State & Next Level Roadmap

## Current State Assessment

### What You Have (5 Tools)

| Tool | What It Does |
|------|-------------|
| `get_network_interfaces()` | Lists available capture interfaces |
| `capture_live_packets()` | Live capture with BPF filters, count/timeout limits |
| `analyze_pcap_file()` | Read PCAP/PCAPNG with display filters |
| `get_protocol_statistics()` | Protocol hierarchy + IP conversation stats |
| `get_capture_file_info()` | File metadata (size, duration, packet count) |

### Architecture
- Python + FastMCP
- Wraps `tshark` CLI via subprocess
- Input validation / filter sanitization
- Async operations
- Single-file server (`wireshark-mcp-server.py`)

---

## Pros

**Solid foundation.** The five core tools cover the basic capture → analyze → report loop that most users need. It works, it's understandable, and the tool surface is small enough that LLMs won't get confused picking the right one.

**Security controls exist.** Input validation, filter sanitization, path resolution, resource limits on capture duration/count/filesize — these are non-trivial to get right and you have them.

**Cross-platform.** Windows/Linux/macOS with documented permission setup for each.

**Clean MCP integration.** Straightforward Claude Desktop + VS Code/Cursor config. No over-engineering.

**Async operations.** Non-blocking captures mean the LLM isn't sitting frozen waiting for a 60-second capture to finish.

---

## Cons

**No threat intelligence at all.** Your biggest competitor (0xKoda/WireMCP, 281 stars vs your 5) has `check_threats` against URLhaus and `check_ip_threats` against multiple feeds. This is the #1 thing people actually want from an AI-powered network tool — "is this traffic bad?"

**No credential/sensitive data detection.** WireMCP has `extract_credentials` scanning for HTTP Basic Auth, FTP, Telnet creds in PCAPs. Yours doesn't touch this.

**No IP anonymization/redaction.** sarthaksiddha's implementation has an `IPProtectionManager` with pseudonymize/redact modes. Yours sends raw IPs to the LLM. For enterprise/professional use, this is a dealbreaker.

**Single commit, no releases, no CI/CD.** The repo looks abandoned at first glance. No tags, no changelog, no GitHub Actions. 1 open issue, 0 PRs. For something that touches network traffic, this doesn't inspire confidence.

**`__pycache__` committed to the repo.** Small thing, but signals "quick project pushed without cleanup."

**No PyPI package.** `khuynh22/mcp-wireshark` already claimed the `mcp-wireshark` PyPI name with `pip install mcp-wireshark`. Yours requires manual clone + path setup.

**No TCP stream following.** Can't reconstruct a conversation. `mcp-wireshark` on PyPI has `follow_tcp_stream`. This is a core Wireshark feature that's missing.

**No JSON export.** tshark's `-T json` or `-T ek` output is the most LLM-friendly format available and you're not explicitly using it for structured output.

**No DNS resolution or enrichment.** Raw IPs are meaningless to most users without reverse DNS or GeoIP context.

**Limited output formatting for LLMs.** The raw tshark text output forces the LLM to parse semi-structured text instead of getting clean JSON it can reason over directly.

**5 stars.** Harsh but real — in a space with 6+ Wireshark MCPs now, you're not standing out.

---

## Improvement Roadmap

### Tier 1 — Immediate Fixes (Low effort, high impact)

#### 1. Clean up the repo
- Delete `__pycache__` from git, add to `.gitignore` properly
- Add proper `.gitignore` for Python (venv, .egg-info, dist, etc.)
- Create a `pyproject.toml` with proper packaging
- Add a `CHANGELOG.md`
- Tag a v0.1.0 release

#### 2. Structured JSON output mode
Add `--json` or `-T ek` (Elasticsearch/Kibana) output from tshark. Every tool that returns packet data should have a `format` parameter: `"text"` (default, backward compat) or `"json"` (structured). LLMs work dramatically better with JSON than with tshark's default text tables.

#### 3. Follow TCP/UDP streams
```
Tool: follow_stream(filepath, stream_index, stream_type="tcp")
```
This is `tshark -r file.pcap -z follow,tcp,ascii,0` under the hood. Essential for reconstructing HTTP conversations, seeing full request/response pairs, spotting data exfiltration.

#### 4. Export packets to JSON
```
Tool: export_packets_json(filepath, display_filter, max_packets)
```
Full structured packet data as JSON. This is the tool the LLM will call most — it gives the richest context for reasoning.

---

### Tier 2 — Competitive Parity (Medium effort, high differentiation)

#### 5. Threat intelligence integration
Start simple, expand later:
- **Phase 1:** Check extracted IPs against URLhaus API (free, no key needed)
- **Phase 2:** Add AbuseIPDB (free tier, API key)
- **Phase 3:** Add VirusTotal IP/domain lookup (free tier, API key)
- **Phase 4:** Add local IOC list support (user-provided CSV/JSON of bad IPs/domains)

```
Tool: check_threat_intel(filepath_or_ips, providers=["urlhaus"])
```

#### 6. DNS enrichment
```
Tool: dns_resolve_capture(filepath)
```
Extract all unique IPs from a capture, do reverse DNS, return mapping. Optionally add GeoIP via MaxMind GeoLite2 (free). This transforms "192.168.1.50 talked to 142.250.80.46" into "workstation-5 talked to google.com (Mountain View, US)" — infinitely more useful for LLM analysis.

#### 7. Sensitive data detection
Scan captures for:
- Credentials (HTTP Basic, FTP USER/PASS, Telnet)
- Credit card number patterns
- SSN patterns
- API keys / tokens in HTTP headers
- Unencrypted PII

```
Tool: scan_sensitive_data(filepath, categories=["credentials", "pii"])
```

#### 8. IP anonymization mode
Add a server-level config or per-tool parameter:
```python
anonymization_mode: "none" | "pseudonymize" | "redact"
```
- `pseudonymize`: deterministic mapping (192.168.1.1 → Host-A) consistent within a session
- `redact`: replace with [REDACTED]

This is table stakes for enterprise adoption.

---

### Tier 3 — Next Level (Higher effort, major differentiation)

#### 9. Capture session management
Right now captures are fire-and-forget. Add persistent sessions:
```
Tool: start_capture_session(interface, filter, session_name) → session_id
Tool: stop_capture_session(session_id) → filepath
Tool: get_session_status(session_id) → {running, packets_captured, duration, file_size}
```
This lets the LLM do things like "start capturing, let me investigate something else, then come back and analyze what we caught." Much more natural workflow.

#### 10. Differential analysis
```
Tool: compare_captures(filepath_a, filepath_b)
```
"What changed between this morning's baseline and right now?" — show new IPs, new protocols, new ports, changed traffic volumes. Incredibly useful for incident response and troubleshooting.

#### 11. MCP Resources (not just Tools)
Expose PCAP files as MCP Resources so clients can browse available captures:
```
Resource: wireshark://captures/ → list of .pcap files in a configured directory
Resource: wireshark://captures/{filename} → file metadata + summary
```
Also expose interface list as a resource rather than requiring a tool call.

#### 12. Automated analysis prompts
Bundle pre-built analysis templates as MCP Prompts:
```
Prompt: "security_audit" → systematic check for threats, creds, anomalies
Prompt: "performance_diagnosis" → retransmissions, latency, throughput analysis  
Prompt: "baseline_comparison" → compare current traffic against known-good
```
These guide the LLM through a structured analysis workflow instead of making it figure out what tools to call.

#### 13. HTTP/HTTPS traffic analysis tool
Dedicated tool for web traffic (most common use case):
```
Tool: analyze_http_traffic(filepath)
```
Returns structured data: request methods, status codes, URLs, user agents, content types, response times. This is what 80% of users are actually looking for.

#### 14. Real-time alerting / streaming
Instead of "capture N packets and return them," support a streaming mode:
```
Tool: monitor_traffic(interface, alert_rules, duration)
```
Where `alert_rules` could be: "alert if any traffic to known-bad IPs" or "alert if DNS queries to unusual TLDs" or "alert on any cleartext credentials." Returns alerts as they happen via MCP notifications.

---

### Tier 4 — Ecosystem & Packaging

#### 15. Publish to PyPI
Name suggestion: `wireshark-mcp-server` or `sharkshark-mcp` (since `mcp-wireshark` is taken)
```
pip install wireshark-mcp-server
wireshark-mcp-server  # starts the server
```
This alone will dramatically increase adoption.

#### 16. Docker image
```dockerfile
FROM python:3.11-slim
RUN apt-get update && apt-get install -y tshark
# ...
```
One-liner setup. Especially useful for CI/CD security pipelines.

#### 17. GitHub Actions CI
- Lint (ruff)
- Type check (mypy)  
- Tests (pytest) against sample PCAPs
- Auto-publish to PyPI on tag

#### 18. Composability with other MCP servers
Document and test pairing with:
- **Nmap MCP** — scan first, then capture targeted traffic
- **Your Google Search MCP** — look up suspicious IPs/domains
- **File system MCP** — manage PCAP files

---

## Competitive Positioning Matrix

| Feature | Your MCP | 0xKoda/WireMCP | sarthaksiddha | mcp-wireshark (PyPI) |
|---------|----------|----------------|---------------|---------------------|
| Stars | 5 | 281 | 15 | ~new |
| Language | Python | Node.js | Python | Python |
| Live capture | ✅ | ✅ | ✅ | ✅ |
| PCAP analysis | ✅ | ✅ | ✅ | ✅ |
| Protocol stats | ✅ | ✅ | ✅ | ✅ |
| Threat intel | ❌ | ✅ (URLhaus) | ❌ | ❌ |
| Credential scan | ❌ | ✅ | ❌ | ❌ |
| IP anonymization | ❌ | ❌ | ✅ | ❌ |
| TCP stream follow | ❌ | ❌ | ❌ | ✅ |
| JSON export | ❌ | ❌ | ❌ | ✅ |
| Display filters | ✅ | ❌ | ✅ | ✅ |
| PyPI package | ❌ | ❌ (npm) | ❌ | ✅ |
| Session mgmt | ❌ | ❌ | ❌ | ❌ |
| MCP Resources | ❌ | ❌ | ❌ | ❌ |
| MCP Prompts | ❌ | ❌ | ❌ | ❌ |
| HTTP analysis | ❌ | ❌ | ❌ | ❌ |
| DNS enrichment | ❌ | ❌ | ❌ | ❌ |
| Differential | ❌ | ❌ | ❌ | ❌ |

**The opportunity:** Nobody has built a comprehensive Wireshark MCP yet. Everyone has 3-7 basic tools. If you ship Tiers 1-3, you'd have the most capable implementation by a wide margin.

---

## Suggested Priority Order

If you're going to work on this iteratively:

1. **Repo cleanup + JSON output** (1-2 hours) — removes the "abandoned project" impression
2. **TCP stream following + threat intel** (half day) — competitive parity with WireMCP
3. **PyPI packaging** (1-2 hours) — adoption multiplier
4. **DNS enrichment + sensitive data scan** (half day) — unique differentiation
5. **Session management + HTTP analysis** (1 day) — moves into "clearly the best one" territory
6. **MCP Resources + Prompts** (half day) — proper MCP-native design
7. **Docker + CI** (few hours) — enterprise readiness

The whole thing is probably a solid weekend of work to go from "one of six Wireshark MCPs" to "the Wireshark MCP."
