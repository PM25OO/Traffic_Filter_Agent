# Wireshark MCP Server - Quick Setup Guide

## Prerequisites Check

### ✅ System Requirements
- [ ] Python 3.9+ installed (`python --version`)
- [ ] Wireshark installed with TShark CLI access (`tshark --version`)
- [ ] Network capture permissions configured
- [ ] Claude Desktop or MCP-compatible client

### ✅ Permission Setup

#### Windows
```powershell
# Wireshark installer usually handles this automatically
# Run as Administrator if needed for live captures
```

#### Linux
```bash
# Option 1: Add user to wireshark group (recommended)
sudo usermod -aG wireshark $USER
sudo logout  # Then log back in

# Option 2: Set capabilities on dumpcap
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap

# Verify permissions
dumpcap -D
```

#### macOS
```bash
# Wireshark installer typically handles permissions
# May need sudo for some captures
```

## Installation Steps

### 1. Download/Clone Project
```bash
# Place all project files in a directory
mkdir wireshark-mcp
cd wireshark-mcp
# Copy all project files here
```

### 2. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 3. Test Installation
```bash
python test_server.py
```

### 4. Configure Claude Desktop

**Find your config file:**
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

**Add server configuration:**
```json
{
  "mcpServers": {
    "wireshark": {
      "command": "python",
      "args": ["/FULL/PATH/TO/wireshark-mcp-server.py"],
      "env": {
        "PYTHONPATH": "/FULL/PATH/TO/PROJECT/DIRECTORY"
      }
    }
  }
}
```

**Important:** Use absolute paths, not relative paths!

### 5. Restart Claude Desktop
Close and reopen Claude Desktop to load the new server.

## Verification

### Test Basic Functionality
In Claude Desktop, try these commands:

1. **"List available network interfaces"**
   - Should show your network adapters

2. **"Capture 10 packets from interface 1"**
   - Should capture live traffic (requires permissions)

3. **"Help me with network analysis"**
   - Should show available tools and capabilities

### Troubleshooting

#### "TShark not found"
```bash
# Verify installation
tshark --version

# Check PATH (Windows)
where tshark

# Check PATH (Linux/macOS)  
which tshark
```

#### "Permission denied"
```bash
# Linux: Check group membership
groups $USER

# Test dumpcap directly
dumpcap -D
```

#### "FastMCP not installed"
```bash
pip install fastmcp
```

#### "Module import errors"
```bash
# Check Python path in config
# Ensure absolute paths are used
# Verify all files are in same directory
```

## Usage Examples

Once configured, you can use natural language:

- **"Show me available network interfaces"**
- **"Capture HTTP traffic for 30 seconds"**
- **"Analyze this PCAP file: /path/to/file.pcap"**
- **"Help troubleshoot network connectivity issues"**
- **"Generate protocol statistics from my capture"**

## Security Notes

- The server validates all inputs for security
- File paths are sanitized and checked
- Capture limits are enforced automatically
- Only PCAP/PCAPNG files are accepted for analysis

## Support

If you encounter issues:

1. Run `python test_server.py` to check components
2. Check Claude Desktop logs for error messages
3. Verify Wireshark installation and permissions
4. Ensure absolute paths in configuration
5. Test TShark CLI access manually

## Advanced Configuration

### Custom Installation Paths
If Wireshark is installed in a custom location, modify the paths in `wireshark-mcp-server.py`:

```python
# Update these paths in WiresharkInterface._find_tshark()
custom_paths = [
    "/custom/path/to/tshark",
    "C:\\Custom\\Wireshark\\tshark.exe"
]
```

### Performance Tuning
For high-volume analysis, adjust these limits in `SecurityValidator`:

```python
MAX_CAPTURE_DURATION = 600  # 10 minutes
MAX_PACKET_COUNT = 20000    # 20k packets
MAX_FILE_SIZE = 200 * 1024 * 1024  # 200MB
```

## Integration with Other Tools

The MCP server can be integrated with:
- VS Code with MCP extension
- Cursor IDE
- Custom MCP clients
- Automation scripts

Ready to analyze networks with AI! 🚀