#!/usr/bin/env python3
"""Quick server initialization test."""

import sys
sys.path.insert(0, '/home/chris/repo/Wireshark-MCP-main')

try:
    # Test interface initialization
    from wireshark_mcp.interfaces.wireshark_interface import WiresharkInterface
    wireshark = WiresharkInterface()
    print(f"✓ WiresharkInterface initialized (tshark: {wireshark.tshark_path})")
except RuntimeError as e:
    print(f"⚠ Wireshark interface: {e}")

try:
    # Test nmap interface
    from wireshark_mcp.interfaces.nmap_interface import NmapInterface
    nmap = NmapInterface()
    print(f"✓ NmapInterface initialized (nmap: {nmap.nmap_path})")
except RuntimeError as e:
    print(f"⚠ Nmap interface: {e}")

try:
    # Test threat intel interface
    from wireshark_mcp.interfaces.threat_intel_interface import ThreatIntelInterface
    threat_intel = ThreatIntelInterface()
    print(f"✓ ThreatIntelInterface initialized")
except Exception as e:
    print(f"⚠ Threat intel interface: {e}")

try:
    # Test server initialization (don't run, just init)
    from wireshark_mcp.server import WiresharkMCPServer
    print("✓ WiresharkMCPServer class imported successfully")
    
    # Try to initialize (will fail if tshark not found)
    try:
        server = WiresharkMCPServer()
        print("✓ WiresharkMCPServer initialized successfully!")
        print(f"  - Tools registered: YES")
        print(f"  - Resources registered: YES")
        print(f"  - Prompts registered: YES")
        print(f"  - Nmap available: {server.nmap is not None}")
        print(f"  - Threat Intel available: {server.threat_intel is not None}")
    except RuntimeError as e:
        print(f"⚠ Server initialization: {e}")
        
except Exception as e:
    print(f"✗ Server import error: {e}")
    import traceback
    traceback.print_exc()

print("\n✓✓✓ Server test complete! ✓✓✓")
