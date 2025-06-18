#!/usr/bin/env python3

import os
import jbxmcp
from jbxmcp.server import run

def main():
    """Initialize and run the Joe Sandbox MCP server."""
    if os.getenv("ACCEPTTAC") != "TRUE" or not os.getenv("ACCEPTTAC"):
        print("Error: You need to accept the Joe Sandbox Terms And Conditions.")
        print("By setting ACCEPTTAC=TRUE, you confirm that you have read and accepted the Terms and Conditions: https://jbxcloud.joesecurity.org/resources/termsandconditions.pdf")

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
