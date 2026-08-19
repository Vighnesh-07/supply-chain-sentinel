import os
import sys
import json

def generate_claude_desktop_config():
    """Generates the Claude Desktop configuration for Supply Chain Sentinel MCP."""
    
    # Path to the mcp server script
    mcp_script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "monitor", "mcp_server.py")
    
    # Path to the python executable
    python_exec = sys.executable
    
    config = {
        "mcpServers": {
            "supply-chain-sentinel": {
                "command": python_exec,
                "args": [mcp_script_path],
                "env": {
                    "PYTHONPATH": os.path.dirname(os.path.abspath(__file__))
                }
            }
        }
    }
    
    config_json = json.dumps(config, indent=2)
    
    print("\n[+] Claude Desktop MCP Configuration:")
    print("-" * 50)
    print(config_json)
    print("-" * 50)
    
    print("\n[i] To use this configuration with Claude Desktop:")
    
    if sys.platform == "win32":
        config_path = os.path.expandvars(r"%APPDATA%\Claude\claude_desktop_config.json")
    elif sys.platform == "darwin":
        config_path = os.path.expanduser("~/Library/Application Support/Claude/claude_desktop_config.json")
    else:
        # Linux / Unknown
        config_path = "~/.config/Claude/claude_desktop_config.json"
        
    print(f"1. Open or create the file at:\n   {config_path}")
    print("2. Copy the JSON above into that file.")
    print("3. Restart Claude Desktop.")
    print("\nSupply Chain Sentinel tools will now be available to Claude!")
    
if __name__ == "__main__":
    generate_claude_desktop_config()
