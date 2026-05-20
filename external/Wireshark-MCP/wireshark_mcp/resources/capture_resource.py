"""MCP Resource for capture files."""

import json
import os
from pathlib import Path


def register_resources(mcp):
    """Register capture file resources.

    Args:
        mcp: FastMCP instance
    """

    @mcp.resource("wireshark://captures/")
    def list_captures() -> str:
        """List available PCAP files in common directories.

        Returns:
            JSON string with list of PCAP files
        """
        # Look in common capture directories
        search_dirs = [
            Path.cwd(),
            Path.home() / "captures",
            Path("/tmp"),
            Path("/var/tmp")
        ]

        captures = []
        for directory in search_dirs:
            if directory.exists() and directory.is_dir():
                try:
                    for file in directory.glob("*.pcap"):
                        captures.append({
                            "path": str(file),
                            "name": file.name,
                            "size": file.stat().st_size,
                            "modified": file.stat().st_mtime
                        })
                    for file in directory.glob("*.pcapng"):
                        captures.append({
                            "path": str(file),
                            "name": file.name,
                            "size": file.stat().st_size,
                            "modified": file.stat().st_mtime
                        })
                except PermissionError:
                    continue

        result = {
            "captures": captures,
            "count": len(captures),
            "directories_searched": [str(d) for d in search_dirs if d.exists()]
        }

        return json.dumps(result, indent=2)
