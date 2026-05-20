#!/usr/bin/env python3
"""
Wireshark MCP Server - Backward Compatibility Wrapper

This file maintains backward compatibility with the original single-file server.
The actual implementation is now in the wireshark_mcp package.

For new installations, use: pip install wireshark-mcp-server
"""

import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import from the modular package
try:
    from wireshark_mcp.server import main
except ImportError as e:
    logger.error(f"Failed to import wireshark_mcp package: {e}")
    logger.error("Please install the package: pip install -e .")
    exit(1)

if __name__ == "__main__":
    logger.info("Starting Wireshark MCP Server (backward compatibility wrapper)")
    main()