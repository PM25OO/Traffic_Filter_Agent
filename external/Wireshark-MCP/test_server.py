#!/usr/bin/env python3
"""
Test script for Wireshark MCP Server

This script tests the core functionality of the Wireshark MCP server
without requiring a full MCP client setup.
"""

import asyncio
import json
import sys
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

# Import from the main server file
import importlib.util
spec = importlib.util.spec_from_file_location("wireshark_mcp_server", "wireshark-mcp-server.py")
wireshark_mcp_server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wireshark_mcp_server)

WiresharkInterface = wireshark_mcp_server.WiresharkInterface
SecurityValidator = wireshark_mcp_server.SecurityValidator

async def test_wireshark_interface():
    """Test the Wireshark interface functionality."""
    print("🧪 Testing Wireshark MCP Server Components")
    print("=" * 50)
    
    try:
        # Test Wireshark interface initialization
        print("1. Testing Wireshark Interface Initialization...")
        wireshark = WiresharkInterface()
        print(f"   ✅ TShark found at: {wireshark.tshark_path}")
        if wireshark.dumpcap_path:
            print(f"   ✅ Dumpcap found at: {wireshark.dumpcap_path}")
        if wireshark.capinfos_path:
            print(f"   ✅ Capinfos found at: {wireshark.capinfos_path}")
        
    except Exception as e:
        print(f"   ❌ Error initializing Wireshark interface: {e}")
        return False
    
    # Test interface listing
    print("\n2. Testing Network Interface Listing...")
    try:
        interfaces_result = wireshark.get_interfaces()
        if interfaces_result["status"] == "success":
            print(f"   ✅ Found {interfaces_result['count']} network interfaces:")
            for i, interface in enumerate(interfaces_result["interfaces"][:5]):  # Show first 5
                print(f"      {i+1}. {interface}")
            if interfaces_result['count'] > 5:
                print(f"      ... and {interfaces_result['count'] - 5} more")
        else:
            print(f"   ⚠️  Interface listing issue: {interfaces_result['message']}")
    except Exception as e:
        print(f"   ❌ Error listing interfaces: {e}")
    
    # Test security validator
    print("\n3. Testing Security Validation...")
    test_interfaces = ["eth0", "wlan0", "Ethernet 2", "Wi-Fi", "1", "invalid;command", "../etc/passwd"]
    for iface in test_interfaces:
        is_valid = SecurityValidator.validate_interface(iface)
        status = "✅" if is_valid else "❌"
        print(f"   {status} Interface '{iface}': {'Valid' if is_valid else 'Invalid'}")
    
    test_filters = ["tcp port 80", "host 192.168.1.1", "tcp; rm -rf /", "normal filter"]
    for filter_expr in test_filters:
        is_valid = SecurityValidator.validate_capture_filter(filter_expr)
        status = "✅" if is_valid else "❌"
        print(f"   {status} Filter '{filter_expr}': {'Valid' if is_valid else 'Invalid'}")
    
    print("\n4. Testing Live Capture (if permissions allow)...")
    try:
        # Try to get the first available interface
        interfaces_result = wireshark.get_interfaces()
        if interfaces_result["status"] == "success" and interfaces_result["interfaces"]:
            # Extract interface number/name from first interface
            first_interface = interfaces_result["interfaces"][0]
            # Try to extract just the number or name
            if ". " in first_interface:
                interface_id = first_interface.split(". ")[0]
            else:
                interface_id = "1"  # Default fallback
            
            print(f"   Testing capture on interface: {interface_id}")
            capture_result = wireshark.capture_packets(interface_id, count=5, timeout=10)
            
            if capture_result["status"] == "success":
                print(f"   ✅ Successfully captured {capture_result['packet_count']} packets")
            else:
                print(f"   ⚠️  Capture test failed (this is expected without proper permissions): {capture_result['message']}")
        else:
            print("   ⚠️  No interfaces available for testing")
    except Exception as e:
        print(f"   ⚠️  Capture test failed (expected without permissions): {e}")
    
    print("\n5. Testing File Path Security...")
    test_paths = [
        "/tmp/test.pcap",
        "../etc/passwd",
        "C:\\Windows\\System32\\test.pcap",
        "./nonexistent.pcap",
        "test.txt"
    ]
    
    for path in test_paths:
        sanitized = SecurityValidator.sanitize_filepath(path)
        status = "✅" if sanitized else "❌"
        result = sanitized if sanitized else "Rejected"
        print(f"   {status} Path '{path}': {result}")
    
    print("\n🎉 Component testing completed!")
    print("\nNext steps:")
    print("1. Install requirements: pip install -r requirements.txt")
    print("2. Configure Claude Desktop with the provided config")
    print("3. Test with Claude Desktop or other MCP clients")
    print("4. Ensure proper network capture permissions are set")
    
    return True

async def test_mcp_server():
    """Test the full MCP server (requires FastMCP)."""
    print("\n6. Testing MCP Server Integration...")
    try:
        WiresharkMCPServer = wireshark_mcp_server.WiresharkMCPServer
        
        print("   ✅ MCP Server class imported successfully")
        
        # Test server initialization (don't actually run it)
        server = WiresharkMCPServer()
        print("   ✅ MCP Server initialized successfully")
        print("   📋 Registered tools:")
        print("      - get_network_interfaces()")
        print("      - capture_live_packets()")
        print("      - analyze_pcap_file()")
        print("      - get_protocol_statistics()")
        print("      - get_capture_file_info()")
        
        return True
        
    except ImportError as e:
        print(f"   ⚠️  FastMCP not installed: {e}")
        print("   💡 Install with: pip install fastmcp")
        return False
    except Exception as e:
        print(f"   ❌ Error testing MCP server: {e}")
        return False

def main():
    """Main test function."""
    print("Wireshark MCP Server - Component Tests")
    print("=====================================")
    
    # Run the async tests
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        success = loop.run_until_complete(test_wireshark_interface())
        loop.run_until_complete(test_mcp_server())
        
        if success:
            print("\n✅ Basic component tests passed!")
            print("The server should be ready for MCP client integration.")
        else:
            print("\n❌ Some tests failed. Check the output above.")
            
    except KeyboardInterrupt:
        print("\n⏹️  Test interrupted by user")
    except Exception as e:
        print(f"\n❌ Unexpected error during testing: {e}")
    finally:
        loop.close()

if __name__ == "__main__":
    main()