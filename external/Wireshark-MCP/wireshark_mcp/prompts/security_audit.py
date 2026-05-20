"""MCP Prompts for guided security analysis."""


def register_prompts(mcp):
    """Register security analysis prompts.

    Args:
        mcp: FastMCP instance
    """

    @mcp.prompt("security_audit")
    def security_audit_prompt() -> str:
        """Systematic security analysis workflow for PCAP files.

        This prompt guides you through a comprehensive security audit of network
        traffic captures.

        Steps:
        1. Extract all unique IP addresses from capture
        2. Check each IP against threat intelligence databases
        3. Scan for sensitive data (credentials, API keys, tokens)
        4. Analyze protocol distribution for anomalies
        5. Check for suspicious patterns (port scans, unusual traffic)
        6. Generate a summary security report

        Usage:
            Use this prompt when you need to perform a thorough security
            assessment of network traffic captured in a PCAP file.
        """
        return """
# Security Audit Workflow for PCAP Analysis

Perform a comprehensive security audit on the provided capture file following these steps:

## Step 1: Traffic Overview
- Use `get_capture_file_info()` to get basic capture metadata
- Use `get_protocol_statistics()` to understand protocol distribution
- Identify any unusual protocol patterns or ratios

## Step 2: IP Address Extraction
- Use `analyze_pcap_file()` with display filter to extract all unique source and destination IPs
- Create a list of all external IPs (non-RFC1918 addresses)

## Step 3: Threat Intelligence Check
(If threat intelligence tools are available)
- Check each external IP against URLhaus malware database
- Flag any IPs associated with known malicious activity
- Document threat indicators found

## Step 4: Sensitive Data Scan
- Use `follow_tcp_stream()` to examine HTTP traffic (port 80)
- Look for:
  - Cleartext credentials (Authorization headers, form data)
  - API keys and tokens
  - Session cookies without Secure flag
  - Unencrypted sensitive data

## Step 5: Anomaly Detection
- Look for unusual patterns:
  - High volume of traffic to single host (potential exfiltration)
  - Sequential port scanning behavior
  - Failed connection attempts
  - DNS queries to suspicious domains
  - Large file transfers

## Step 6: Protocol Security Analysis
- Check for deprecated protocols (FTP, Telnet, HTTP without TLS)
- Identify TLS/SSL versions (look for SSLv3, TLS 1.0)
- Check for weak ciphers

## Step 7: Generate Report
Create a security report with:
- Executive summary of findings
- List of threats detected (with severity levels)
- Sensitive data exposure incidents
- Recommendations for remediation
- Timeline of suspicious activity

## Example Commands:

```
# Get overview
get_capture_file_info("/path/to/capture.pcap")
get_protocol_statistics("/path/to/capture.pcap")

# Extract IPs
analyze_pcap_file("/path/to/capture.pcap", "ip", 1000)

# Follow suspicious streams
follow_tcp_stream("/path/to/capture.pcap", 0, "ascii")

# Check for cleartext HTTP
analyze_pcap_file("/path/to/capture.pcap", "http.request.method == 'POST'")
```

## Output Format:
Provide findings in structured format with:
- Finding severity (Critical, High, Medium, Low, Info)
- Finding category (Threat Intelligence, Sensitive Data, Anomaly, Protocol Security)
- Description
- Evidence (packet numbers, stream data)
- Recommended action
"""

    @mcp.prompt("network_troubleshooting")
    def network_troubleshooting_prompt() -> str:
        """Guided network troubleshooting workflow.

        This prompt helps diagnose network connectivity and performance issues.
        """
        return """
# Network Troubleshooting Workflow

Diagnose network issues using captured traffic:

## Step 1: Connection Analysis
- Identify failed TCP handshakes (SYN without SYN-ACK)
- Check for TCP retransmissions
- Look for RST packets indicating connection refusals

## Step 2: DNS Resolution Issues
- Filter DNS queries: `dns.flags.response == 0`
- Check for NXDOMAIN responses
- Look for DNS timeouts

## Step 3: Performance Analysis
- Identify high latency connections
- Check TCP window sizes
- Look for packet loss indicators

## Step 4: Application Layer Issues
- Examine HTTP response codes (4xx, 5xx errors)
- Check for TLS handshake failures
- Look for application-specific errors

Use these tools:
- `analyze_pcap_file()` with appropriate filters
- `get_protocol_statistics()` for traffic overview
- `follow_tcp_stream()` to see full conversations
"""

    @mcp.prompt("incident_response")
    def incident_response_prompt() -> str:
        """Incident response investigation workflow.

        This prompt guides security incident investigation using packet captures.
        """
        return """
# Incident Response Investigation

## Phase 1: Scoping
- Identify time range of suspicious activity
- Determine affected systems (IPs/hostnames)
- Classify incident type (malware, data breach, DOS, etc.)

## Phase 2: Evidence Collection
- Extract relevant packet streams
- Document all suspicious connections
- Preserve chain of custody for evidence

## Phase 3: Indicator Extraction
- Extract indicators of compromise (IOCs):
  - Malicious IP addresses
  - Suspicious domains
  - File hashes (if available)
  - Attack signatures

## Phase 4: Timeline Construction
- Build chronological timeline of events
- Correlate with other log sources
- Identify initial access vector

## Phase 5: Impact Assessment
- Determine data accessed or exfiltrated
- Identify compromised credentials
- Assess lateral movement

## Phase 6: Reporting
- Document findings
- Create IOC list for blocking
- Provide remediation recommendations
"""
