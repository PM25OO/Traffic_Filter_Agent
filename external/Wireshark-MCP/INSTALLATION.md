# Installation Guide

## Quick Start

### 1. Install System Dependencies

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install python3-pip tshark nmap
```

#### macOS
```bash
brew install python wireshark nmap
```

#### Windows
1. Install [Python 3.8+](https://www.python.org/downloads/)
2. Install [Wireshark](https://www.wireshark.org/download.html)
3. Install [Nmap](https://nmap.org/download.html)

### 2. Install Python Package

```bash
# From PyPI (when published)
pip install wireshark-mcp-server

# From source (development)
git clone <repository-url>
cd Wireshark-MCP-main
pip install -e .
```

### 3. Configure Network Permissions

#### Linux (Recommended)
```bash
# Method 1: Set capabilities (no root needed for captures)
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap

# Method 2: Add user to wireshark group
sudo usermod -aG wireshark $USER
newgrp wireshark  # Or logout and login
```

#### macOS
```bash
# Run with sudo or ensure user is admin
# Wireshark installer typically configures permissions
```

#### Windows
- Run terminal as Administrator for packet capture
- Or configure NPcap permissions during installation

### 4. Optional: Configure Threat Intelligence

```bash
# Get free API key from https://www.abuseipdb.com/
export ABUSEIPDB_API_KEY="your_api_key_here"

# Add to ~/.bashrc or ~/.zshrc for persistence
echo 'export ABUSEIPDB_API_KEY="your_key"' >> ~/.bashrc
```

### 5. Test Installation

```bash
# Test Wireshark
tshark --version

# Test Nmap
nmap --version

# Test Python package
python3 -c "import wireshark_mcp; print(wireshark_mcp.__version__)"

# Run server test
wireshark-mcp-server --help
```

## Claude Desktop Integration

### 1. Locate Config File

- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

### 2. Add Server Configuration

```json
{
  "mcpServers": {
    "wireshark": {
      "command": "wireshark-mcp-server",
      "env": {
        "ABUSEIPDB_API_KEY": "your_api_key_here"
      }
    }
  }
}
```

### 3. Restart Claude Desktop

Close and reopen Claude Desktop to load the server.

## Verification Checklist

- [ ] Python 3.8+ installed
- [ ] TShark available: `tshark --version`
- [ ] Nmap available: `nmap --version`
- [ ] Network permissions configured
- [ ] Python package installed: `pip show wireshark-mcp-server`
- [ ] Server runs: `wireshark-mcp-server` (should start without errors)
- [ ] Claude Desktop configured
- [ ] Optional: API keys configured

## Troubleshooting

### Import Error: fastmcp
```bash
pip install fastmcp>=0.9.0
```

### TShark Not Found
```bash
# Verify installation
which tshark

# Add to PATH if needed
export PATH=$PATH:/usr/bin
```

### Permission Denied
```bash
# Check capabilities
getcap /usr/bin/dumpcap

# Should show: cap_net_admin,cap_net_raw=eip
```

### Nmap Not Available
Server will work without nmap, but scanning features won't be available.
Install nmap to enable all features.

## Development Installation

```bash
# Clone repository
git clone <repository-url>
cd Wireshark-MCP-main

# Install in development mode with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# Check code quality
ruff check wireshark_mcp/
black --check wireshark_mcp/
mypy wireshark_mcp/
```

## Uninstallation

```bash
# Remove package
pip uninstall wireshark-mcp-server

# Remove config (optional)
rm ~/.config/Claude/claude_desktop_config.json
```
