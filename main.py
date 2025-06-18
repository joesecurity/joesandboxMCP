#!/usr/bin/env python3

import os
import jbxmcp
from jbxmcp.server import run

def main():
    """Initialize and run the Joe Sandbox MCP server."""
    
    if not os.getenv("JBXAPIKEY"):
        print("Error: JBXAPIKEY environment variable is not set.")
        print("Please set it in your MCP client config file or environment")
        return 1
    
    jbxmcp.initialize_client()
    
    print("Starting Joe Sandbox MCP server...")
    run()
    
    return 0

if __name__ == "__main__":
    exit(main())
