from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    name="Joe Sandbox Cloud",
    instructions=(
        """
        You are working with Joe Sandbox Cloud analysis tools. These tools statically and dynamically analyze files and URLs to detect malware and phishing. 
        Use the tools in the following order:
        1. A URL or file is analyzed (submit_analysis_job). This results in one or multiple webid (e.g. for EMLs) which representing analysis. Alternatively past analysis can be queried  (get_list_of_recent_analyses) or searched (search_analysis). Since new analysis take multiple minutes to analyze there is the option for submit_analysis_job to wait for the completion of the analysis. 
        2. the analysis information is queried (get_analysis_info) by passing the webid. This returns a high level summary of the analysis. Always make sure to query the analysis infos for all webids available!.
        3. IOCs can be queried (get_ioc_for_dropped_files, get_ioc_for_domains, get_ioc_for_ips, get_ioc_for_urls, get_signature_info, get_process_info, get_ai_summaries) by passing the webid. By default only malicious IOCs are returned. 
        4. Analysis artifacts can be downloaded (get_unpacked_files and get_pcap_file). Those can be further processed e.g. via Ghidra or Tshark MCP.
        General instructions:
        * AI summarize if available already give you high level summary of IOCs and behaviors. If not available try to gather an overall view of all analysis and IOCs and summarize the findings.
        """
    )
)

import jbxmcp.tools as tools

def run():
    """Run the MCP server using stdio transport."""
    mcp.run(transport='stdio')

if __name__ == "__main__":
    run()
