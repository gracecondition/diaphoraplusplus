#!/usr/bin/env python3
"""
Diaphora MCP Server for Claude Desktop

This script starts an MCP server that exposes the current Diaphora diff
loaded from IDA.

Usage:
    python mcp_server.py

Claude Desktop Config (~/.config/Claude/claude_desktop_config.json):
{
  "mcpServers": {
    "diaphora": {
      "command": "python3",
      "args": [
        "/path/to/diaphora++/mcp_server.py"
      ]
    }
  }
}

Then in IDA:
1. Run Diaphora diff
2. Right-click on a function match
3. Select "Analyze patchdiff with LLM"
4. Ask Claude to analyze the diff
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from diaphora_mcp import start_stdio_server


def main():
    print(f"[Diaphora MCP] Starting server...", file=sys.stderr)
    print(f"[Diaphora MCP] Waiting for diffs from IDA...", file=sys.stderr)

    # Start stdio MCP server (no database needed - diffs come from IDA)
    start_stdio_server()


if __name__ == "__main__":
    main()
