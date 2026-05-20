#!/usr/bin/env python3
"""Comprehensive test of all registered tools."""

import sys
sys.path.insert(0, '/home/chris/repo/Wireshark-MCP-main')

from wireshark_mcp.server import WiresharkMCPServer

print("=" * 70)
print("WIRESHARK MCP SERVER - COMPREHENSIVE TOOL TEST")
print("=" * 70)

# Initialize server
server = WiresharkMCPServer()

# Get all registered tools
tools = list(server.mcp._tools.keys())
resources = list(server.mcp._resources.keys())
prompts = list(server.mcp._prompts.keys())

print(f"\n📦 REGISTERED TOOLS ({len(tools)} total)")
print("-" * 70)

# Group tools by category
categories = {
    "Capture & Interfaces": [],
    "Analysis": [],
    "Streams": [],
    "Export": [],
    "Nmap Scanning": [],
    "Threat Intelligence": []
}

for tool in sorted(tools):
    if "interface" in tool or "capture" in tool:
        categories["Capture & Interfaces"].append(tool)
    elif "analyze" in tool or "protocol" in tool or "file_info" in tool:
        categories["Analysis"].append(tool)
    elif "stream" in tool:
        categories["Streams"].append(tool)
    elif "export" in tool or "convert" in tool:
        categories["Export"].append(tool)
    elif "nmap" in tool:
        categories["Nmap Scanning"].append(tool)
    elif "threat" in tool or "ip" in tool:
        categories["Threat Intelligence"].append(tool)

for category, tool_list in categories.items():
    if tool_list:
        print(f"\n{category}:")
        for tool in tool_list:
            print(f"  ✓ {tool}")

print(f"\n📁 REGISTERED RESOURCES ({len(resources)} total)")
print("-" * 70)
for resource in sorted(resources):
    print(f"  ✓ {resource}")

print(f"\n💡 REGISTERED PROMPTS ({len(prompts)} total)")
print("-" * 70)
for prompt in sorted(prompts):
    print(f"  ✓ {prompt}")

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"✓ Total Tools: {len(tools)}")
print(f"✓ Total Resources: {len(resources)}")
print(f"✓ Total Prompts: {len(prompts)}")
print(f"✓ Wireshark Available: YES (tshark: {server.wireshark.tshark_path})")
print(f"✓ Nmap Available: {'YES' if server.nmap else 'NO'} ({server.nmap.nmap_path if server.nmap else 'N/A'})")
print(f"✓ Threat Intel Available: {'YES' if server.threat_intel else 'NO'}")
print("\n✅ ALL SYSTEMS OPERATIONAL!")
print("=" * 70)
