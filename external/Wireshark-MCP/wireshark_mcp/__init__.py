"""
Wireshark MCP Server - Comprehensive network analysis platform.

Combines Wireshark packet analysis with nmap scanning, threat intelligence,
and modern MCP features for next-level network analysis.
"""

__version__ = "0.1.0"
__author__ = "Wireshark MCP Contributors"

# Lazy imports to avoid requiring dependencies at import time
def __getattr__(name):
    if name == "WiresharkMCPServer":
        from .server import WiresharkMCPServer
        return WiresharkMCPServer
    elif name == "main":
        from .server import main
        return main
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")

__all__ = ["WiresharkMCPServer", "main", "__version__"]
