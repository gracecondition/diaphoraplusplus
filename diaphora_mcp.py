"""
Diaphora MCP (Model Context Protocol) Integration

Provides MCP tools for AI models to analyze binary diffs.
"""

import orjson as json
import sys
import os
from typing import List, Dict, Any, Optional

# File path for inter-process communication between IDA and MCP server
# Use absolute path to avoid any tempfile.gettempdir() differences
_DIFF_FILE_PATH = "/tmp/diaphora_current_diff.json"

# MCP server implementation
class DiaphoraMCPServer:
    """
    MCP server that exposes the current pseudocode diff for analysis.
    """

    def __init__(self):
        """
        Initialize MCP server.
        """
        self.tools = {
            "get_current_diff": self.get_current_diff,
            "analyze_current_diff": self.analyze_current_diff,
        }

    def get_current_diff(self) -> Optional[str]:
        """
        Get the current pseudocode diff that was loaded from IDA.

        Returns:
            The current diff text or None if no diff is loaded
        """
        if not os.path.exists(_DIFF_FILE_PATH):
            return "No diff currently loaded. In IDA, right-click on a match and select 'Analyze patchdiff with LLM'."

        try:
            with open(_DIFF_FILE_PATH, 'rb') as f:
                data = json.loads(f.read())
            return data.get("diff_text", "")
        except Exception as e:
            return f"Error reading diff: {str(e)}"

    def analyze_current_diff(self, analysis_type: str = "security") -> str:
        """
        Get the current diff with analysis context.

        Args:
            analysis_type: Type of analysis ("security", "behavior", "performance")

        Returns:
            Formatted diff with analysis prompt
        """
        if not os.path.exists(_DIFF_FILE_PATH):
            return "No diff currently loaded. In IDA, right-click on a match and select 'Analyze patchdiff with LLM'."

        try:
            with open(_DIFF_FILE_PATH, 'rb') as f:
                data = json.loads(f.read())
        except Exception as e:
            return f"Error reading diff: {str(e)}"

        diff_text = data.get("diff_text", "")
        metadata = data.get("metadata", {})

        prompts = {
            "security": """Analyze this pseudocode diff for security implications:
- Are there new vulnerabilities introduced?
- Were any vulnerabilities fixed?
- Are there suspicious changes to memory operations, bounds checks, or authentication?
- What is the security impact?

""",
            "behavior": """Analyze this pseudocode diff for behavioral changes:
- What is the main functional change?
- Are there logic changes that affect program behavior?
- What are the implications for users?

""",
            "performance": """Analyze this pseudocode diff for performance implications:
- Are there algorithmic changes?
- Were loops or data structures modified?
- What is the performance impact?

"""
        }

        prompt = prompts.get(analysis_type, prompts["security"])

        # Add metadata if available
        metadata_str = ""
        if metadata:
            metadata_str = f"""
Function Information:
- Main: {metadata.get('main_name', 'unknown')} @ {metadata.get('main_address', 'unknown')}
- Diff: {metadata.get('diff_name', 'unknown')} @ {metadata.get('diff_address', 'unknown')}

"""

        return prompt + metadata_str + "Pseudocode Diff:\n" + diff_text

    def handle_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """
        Handle an MCP tool call.

        Args:
            tool_name: Name of the tool to invoke
            arguments: Tool arguments

        Returns:
            Tool result
        """
        if tool_name not in self.tools:
            return {"error": f"Unknown tool: {tool_name}"}

        try:
            result = self.tools[tool_name](**arguments)
            return result
        except Exception as e:
            return {"error": str(e)}

    def get_tool_schema(self) -> List[Dict[str, Any]]:
        """
        Get MCP tool schema for all available tools.

        Returns:
            List of tool schemas
        """
        return [
            {
                "name": "get_current_diff",
                "description": "Get the current pseudocode diff that was loaded from IDA. The user loads a diff by right-clicking on a function match in IDA and selecting 'Analyze patchdiff with LLM'.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "analyze_current_diff",
                "description": "Get the current pseudocode diff with analysis context. Returns the diff formatted with an analysis prompt.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "analysis_type": {
                            "type": "string",
                            "enum": ["security", "behavior", "performance"],
                            "description": "Type of analysis to perform (default: security)"
                        }
                    }
                }
            }
        ]


def set_current_diff(diff_text: str, metadata: Dict[str, Any] = None):
    """
    Set the current diff to be analyzed by Claude.
    Writes the diff to a temp file that the MCP server can read.

    Args:
        diff_text: The pseudocode diff text
        metadata: Optional metadata (function names, addresses, etc.)

    Returns:
        True if successful, False otherwise
    """
    data = {
        "diff_text": diff_text,
        "metadata": metadata or {}
    }

    try:
        with open(_DIFF_FILE_PATH, 'wb') as f:
            f.write(json.dumps(data))
        print(f"[Diaphora MCP] Diff saved to {_DIFF_FILE_PATH}", file=sys.stderr)
        if metadata:
            print(f"[Diaphora MCP] {metadata.get('main_name', 'unknown')} vs {metadata.get('diff_name', 'unknown')}", file=sys.stderr)
        return True
    except Exception as e:
        print(f"[Diaphora MCP] Error saving diff: {e}", file=sys.stderr)
        return False


def create_mcp_server():
    """
    Create and return an MCP server instance.

    Returns:
        DiaphoraMCPServer instance
    """
    return DiaphoraMCPServer()


#-------------------------------------------------------------------------------
# Stdio MCP Server
#-------------------------------------------------------------------------------

def start_stdio_server():
    """
    Start an MCP server listening on stdio.
    This is used for Claude Desktop integration.
    """
    server = DiaphoraMCPServer()

    print("[Diaphora MCP] Stdio server started", file=sys.stderr)

    # Read MCP messages from stdin
    for line in sys.stdin:
        try:
            message = json.loads(line)
            method = message.get("method")

            if method == "initialize":
                response = {
                    "jsonrpc": "2.0",
                    "id": message.get("id"),
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {
                            "tools": {}
                        },
                        "serverInfo": {
                            "name": "diaphora-mcp",
                            "version": "1.0.0"
                        }
                    }
                }
            elif method == "notifications/initialized":
                # No response needed for notifications
                continue
            elif method == "ping":
                response = {
                    "jsonrpc": "2.0",
                    "id": message.get("id"),
                    "result": {}
                }
            elif method == "tools/list":
                response = {
                    "jsonrpc": "2.0",
                    "id": message.get("id"),
                    "result": {
                        "tools": server.get_tool_schema()
                    }
                }
            elif method == "tools/call":
                params = message.get("params", {})
                tool_name = params.get("name")
                arguments = params.get("arguments", {})
                result = server.handle_tool_call(tool_name, arguments)

                # Convert result to JSON string for MCP response
                result_text = result if isinstance(result, str) else json.dumps(result).decode('utf-8')

                response = {
                    "jsonrpc": "2.0",
                    "id": message.get("id"),
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": result_text
                            }
                        ]
                    }
                }
            else:
                response = {
                    "jsonrpc": "2.0",
                    "id": message.get("id"),
                    "error": {
                        "code": -32601,
                        "message": f"Method not found: {method}"
                    }
                }

            # Send response
            print(json.dumps(response).decode('utf-8'))
            sys.stdout.flush()

        except Exception as e:
            error_response = {
                "jsonrpc": "2.0",
                "id": message.get("id") if 'message' in locals() else None,
                "error": {
                    "code": -32603,
                    "message": f"Internal error: {str(e)}"
                }
            }
            print(json.dumps(error_response).decode('utf-8'))
            sys.stdout.flush()


#-------------------------------------------------------------------------------
# MCP Server Launcher (for IDA integration)
#-------------------------------------------------------------------------------

def show_mcp_setup_instructions():
    """
    Print MCP setup instructions for Claude Desktop integration.
    This only needs to be done once.
    """
    # Get paths
    mcp_server_path = os.path.join(os.path.dirname(__file__), "mcp_server.py")
    python_exe = sys.executable

    # Determine config path based on OS
    if sys.platform == "darwin":  # macOS
        config_path = "~/Library/Application Support/Claude/claude_desktop_config.json"
    elif sys.platform == "win32":  # Windows
        config_path = "%APPDATA%/Claude/claude_desktop_config.json"
    else:  # Linux
        config_path = "~/.config/Claude/claude_desktop_config.json"

    config_instructions = f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Diaphora MCP Setup Instructions
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

To connect Claude Desktop to Diaphora (ONE-TIME SETUP):

1. Open (or create): {config_path}

2. Add this configuration:

{{
  "mcpServers": {{
    "diaphora": {{
      "command": "{python_exe}",
      "args": ["{mcp_server_path}"]
    }}
  }}
}}

3. Restart Claude Desktop

4. Done! Now whenever you click "Analyze patchdiff with LLM" in IDA,
   the diff will be available to Claude.

Available tools in Claude Desktop:
   • get_current_diff - Get the pseudocode diff
   • analyze_current_diff - Get diff with analysis prompt

Example queries in Claude:
   • "Show me the current diff"
   • "Analyze the current diff for security issues"
   • "What changed in this function?"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

    print(config_instructions, file=sys.stderr)
