#!/usr/bin/env python3
"""
Wireshark MCP Server - Usage Demonstration

This script demonstrates how the Wireshark MCP server would be used
by an AI assistant to help users with network analysis tasks.
"""

import asyncio
import json
from pathlib import Path

def demo_conversation():
    """
    Demonstrate typical conversations between user and AI using the Wireshark MCP server.
    """
    print("🌐 Wireshark MCP Server - AI Assistant Demo")
    print("=" * 50)
    
    conversations = [
        {
            "scenario": "Network Troubleshooting",
            "user": "I'm having connectivity issues with my web server. Can you help me capture and analyze network traffic?",
            "ai_steps": [
                "I'll help you troubleshoot your network connectivity. Let me start by checking available network interfaces.",
                "MCP Call: get_network_interfaces()",
                "I can see your network interfaces. Now let's capture some live traffic to see what's happening.",
                "MCP Call: capture_live_packets(interface='eth0', count=200, capture_filter='tcp port 80 or tcp port 443', timeout=60)",
                "I've captured 200 packets of HTTP/HTTPS traffic. Let me analyze the patterns I see...",
                "Based on the capture, I can see several TCP retransmissions and connection timeouts to your web server."
            ]
        },
        {
            "scenario": "Security Investigation", 
            "user": "I have a suspicious PCAP file. Can you analyze it for potential security threats?",
            "ai_steps": [
                "I'll analyze your PCAP file for security threats. Let me start with basic file information.",
                "MCP Call: get_capture_file_info(filepath='/path/to/suspicious.pcap')",
                "Now let me generate protocol statistics to understand the traffic composition.",
                "MCP Call: get_protocol_statistics(filepath='/path/to/suspicious.pcap')",
                "Let me look for suspicious patterns like unusual ports, failed connections, or data exfiltration attempts.",
                "MCP Call: analyze_pcap_file(filepath='/path/to/suspicious.pcap', display_filter='tcp.flags.reset==1 or dns.flags.response==0', max_packets=500)",
                "I found several concerning patterns: unusual DNS queries, failed TCP connections, and potential data exfiltration on non-standard ports."
            ]
        },
        {
            "scenario": "Performance Analysis",
            "user": "Our network seems slow. Can you help identify bandwidth usage and top talkers?",
            "ai_steps": [
                "I'll help you analyze network performance. Let's capture live traffic to identify bandwidth usage.",
                "MCP Call: capture_live_packets(interface='1', count=1000, timeout=120)",
                "Now let me analyze the capture for conversation statistics and top talkers.",
                "MCP Call: get_protocol_statistics(filepath='temp_capture.pcap')",
                "Based on the analysis, I can see the top bandwidth consumers and protocol distribution.",
                "The analysis shows heavy BitTorrent traffic consuming 60% of your bandwidth, followed by streaming video at 25%."
            ]
        },
        {
            "scenario": "HTTP Transaction Analysis",
            "user": "I need to analyze HTTP transactions in this capture file for debugging.",
            "ai_steps": [
                "I'll analyze the HTTP transactions in your capture file. Let me filter for HTTP traffic specifically.",
                "MCP Call: analyze_pcap_file(filepath='/path/to/web_traffic.pcap', display_filter='http.request or http.response', max_packets=200)",
                "Let me also look at any HTTP errors or failed transactions.",
                "MCP Call: analyze_pcap_file(filepath='/path/to/web_traffic.pcap', display_filter='http.response.code >= 400', max_packets=100)",
                "I found several HTTP 404 and 500 errors, plus some slow response times that indicate server issues."
            ]
        }
    ]
    
    for i, conv in enumerate(conversations, 1):
        print(f"\n📋 Scenario {i}: {conv['scenario']}")
        print("-" * 40)
        print(f"👤 User: {conv['user']}")
        print()
        
        for step_num, step in enumerate(conv['ai_steps'], 1):
            if step.startswith("MCP Call:"):
                print(f"🤖 AI Assistant: {step}")
                print("   [Executing Wireshark MCP tool...]")
            else:
                print(f"🤖 AI Assistant: {step}")
            print()
    
    print("🎯 Key Benefits Demonstrated:")
    print("- AI can directly interact with network capture tools")
    print("- Complex analysis tasks are simplified through natural language")
    print("- Security validation ensures safe operations") 
    print("- Real-time and file-based analysis capabilities")
    print("- Integration with existing Wireshark expertise")

def demo_mcp_tools():
    """Show the available MCP tools and their capabilities."""
    print("\n🛠️  Available MCP Tools")
    print("=" * 30)
    
    tools = {
        "get_network_interfaces": {
            "description": "Lists all available network interfaces",
            "parameters": "None",
            "example": "get_network_interfaces()",
            "use_case": "Discovery and interface selection"
        },
        "capture_live_packets": {
            "description": "Captures live network traffic",
            "parameters": "interface, count, capture_filter, timeout",
            "example": "capture_live_packets('eth0', 100, 'tcp port 80', 30)",
            "use_case": "Real-time traffic analysis and troubleshooting"
        },
        "analyze_pcap_file": {
            "description": "Analyzes existing PCAP files",
            "parameters": "filepath, display_filter, max_packets",
            "example": "analyze_pcap_file('/path/file.pcap', 'http.request', 200)",
            "use_case": "Forensic analysis and detailed packet inspection"
        },
        "get_protocol_statistics": {
            "description": "Generates protocol and conversation statistics",
            "parameters": "filepath",
            "example": "get_protocol_statistics('/path/file.pcap')",
            "use_case": "Traffic profiling and bandwidth analysis"
        },
        "get_capture_file_info": {
            "description": "Gets metadata about capture files",
            "parameters": "filepath", 
            "example": "get_capture_file_info('/path/file.pcap')",
            "use_case": "File validation and quick overview"
        }
    }
    
    for tool_name, info in tools.items():
        print(f"\n📌 {tool_name}")
        print(f"   Description: {info['description']}")
        print(f"   Parameters: {info['parameters']}")
        print(f"   Example: {info['example']}")
        print(f"   Use Case: {info['use_case']}")

def demo_security_features():
    """Demonstrate the security features built into the server."""
    print("\n🔒 Security Features")
    print("=" * 20)
    
    security_features = [
        {
            "feature": "Interface Validation",
            "description": "Only allows valid network interface names",
            "examples": ["✅ eth0", "✅ Wi-Fi", "❌ ../etc/passwd", "❌ interface;rm -rf /"]
        },
        {
            "feature": "File Path Sanitization", 
            "description": "Validates and sanitizes file paths",
            "examples": ["✅ /valid/path/file.pcap", "❌ ../../../etc/shadow", "❌ file.txt"]
        },
        {
            "feature": "Capture Filter Validation",
            "description": "Validates BPF filter expressions for safety",
            "examples": ["✅ tcp port 80", "✅ host 192.168.1.1", "❌ filter;rm -rf /", "❌ $(malicious)"]
        },
        {
            "feature": "Resource Limits",
            "description": "Enforces limits on capture duration and packet counts",
            "examples": ["Max 300 seconds capture", "Max 10,000 packets", "Max 100MB file size"]
        },
        {
            "feature": "Input Sanitization",
            "description": "All user inputs are validated and sanitized",
            "examples": ["Length limits", "Character filtering", "Type validation"]
        }
    ]
    
    for feature in security_features:
        print(f"\n🛡️  {feature['feature']}")
        print(f"   {feature['description']}")
        for example in feature['examples']:
            print(f"   {example}")

def main():
    """Main demonstration function."""
    demo_conversation()
    demo_mcp_tools()
    demo_security_features()
    
    print("\n🚀 Getting Started")
    print("=" * 17)
    print("1. Install dependencies: pip install -r requirements.txt")
    print("2. Ensure Wireshark/TShark is installed")
    print("3. Configure Claude Desktop with the provided config")
    print("4. Start using natural language to analyze network traffic!")
    
    print("\n📚 Example Commands to Try:")
    print("- 'List available network interfaces'")
    print("- 'Capture 100 packets from interface eth0'") 
    print("- 'Analyze this PCAP file for HTTP traffic'")
    print("- 'Show protocol statistics for my capture file'")
    print("- 'Help me troubleshoot network connectivity issues'")

if __name__ == "__main__":
    main()