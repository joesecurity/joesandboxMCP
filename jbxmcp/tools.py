
__all__ = [
    'submit_analysis_job',
    'search_analysis',
    'get_analysis_info',
    'get_ai_summaries',
    'get_dropped_info',
    'get_domain_info',
    'get_ip_info',
    'get_url_info',
    'get_signature_info',
    'get_unpacked_files',
    'get_pcap_file',
    'get_list_of_recent_analyses',
    'get_process_info',
    'get_memory_dumps'
]

from typing import Any, Dict, List, Optional
import xml.etree.ElementTree as ET
import asyncio

from jbxmcp.server import mcp
from jbxmcp.core import (
    get_or_fetch_report,
    make_search_request,
    make_submission,
    query_analysis_info,
    extract_process_tree,
    download_unpacked_files,
    download_pcap_file,
    list_recent_analyses,
    get_indicators,
    download_memory_dumps,
    download_dropped_files
)

@mcp.tool()
async def submit_analysis_job(
    wait_for_analysis_end: bool,
    timeout: Optional[int] = 1200,
    sample_path: Optional[str] = None,
    sample_url: Optional[str] = None,
    website_url: Optional[str] = None,
    command_line: Optional[str] = None,
    tags: Optional[List[str]] = None,
    analysis_time: int = 120,
    internet_access: bool = True,
    hybrid_code_analysis: bool = True,
    report_cache: bool = False,
    powershell_logging: bool = False,
    ssl_inspection: bool = True,
    vba_instrumentation: bool = True,
    js_instrumentation: bool = True,
    java_jar_tracing: bool = True,
    start_as_normal_user: bool = False,
    email_notification: bool = False,
    secondary_results: bool = False,
    archive_password: Optional[str] = None,
    command_line_argument: Optional[str] = None,
) -> str:
    """
    Submit a file, URL, website, or command line for sandbox analysis using Joe Sandbox.

    This tool analyzes one of the following:
    - A local file (`sample_path`)
    - A remote file URL (`sample_url`)
    - A website to visit (`website_url`)
    - A raw command line to execute (`command_line`)

    Only one input type must be provided. The rest of the arguments configure how the analysis is performed.
    For URL and website analysis, make sure `internet_access=True` to allow downloads or navigation.

    Args:
        wait_for_analysis_end: If True, the tool will block and wait until the sandbox analysis is complete before returning. If False, the tool returns immediately after submission.
        timeout (default: 1200): Max number of seconds to wait for analysis completion, this is only relevant if wait_for_analysis_end is True.
        File to Upload (required — provide exactly one):
            sample_path: Path to a local file to upload and analyze.
            sample_url: Direct download URL for a file to analyze.
            website_url: Website to visit and analyze in a browser.
            command_line: Command line string to execute in the sandbox.

        Sandbox configuration parameters (optional):
            tags (default: null): Optional tags for the submission.
            analysis_time (default: 120): Time in seconds to run the analysis.
            internet_access (default: True): Enable internet during analysis.
            report_cache (default: False): Use cached results if available.
            powershell_logging (default: False): Enable PowerShell script logging.
            ssl_inspection (default: True): Enable HTTPS inspection.
            vba_instrumentation (default: True): Instrument VBA macros.
            hybrid_code_analysis (default: True): Enable Hybrid Code Analysis (HCA).
            js_instrumentation (default: True): Instrument JavaScript.
            java_jar_tracing (default: True): Enable Java tracing.
            start_as_normal_user (default: False): Run the sample without admin privileges.
            email_notification (default: False): Send notification when complete.
            secondary_results (default: False): Generate post-analysis artifacts.
            archive_password (default: None): This password will be used to decrypt submitted archives (zip, 7z, rar etc.).
            command_line_argument (default: null): Startup arguments for the sample.

    Returns:
        A dictionary containing:
        - analyses: A list of extracted analysis entries, each with:
            - webid: Unique identifier for the individual analysis which can be used to retrieve results.
            - sha256: SHA-256 hash of the analyzed file or object.
            - filename: Name of the submitted file or artifact.
            - status: status of the analysis, either finished or running/submitted/accepted
    """
    # Merge params
    params = {
        "tags": tags,
        "analysis-time": analysis_time,
        "internet-access": internet_access,
        "hybrid-code-analysis": hybrid_code_analysis,
        "report-cache": report_cache,
        "powershell-logging": powershell_logging,
        "ssl-inspection": ssl_inspection,
        "vba-instrumentation": vba_instrumentation,
        "js-instrumentation": js_instrumentation,
        "java-jar-tracing": java_jar_tracing,
        "start-as-normal-user": start_as_normal_user,
        "email-notification": email_notification,
        "secondary-results": secondary_results,
        "archive-password": archive_password,
        "command-line-argument": command_line_argument,
    }

    # Strip None values
    params = {k: v for k, v in params.items() if v is not None}

    # Call general handler
    try:
        result = await asyncio.wait_for(make_submission(
            wait_for_analysis_end,
            sample_path=sample_path,
            sample_url=sample_url,
            website_url=website_url,
            command_line=command_line,
            params=params,
        ),
        timeout=1200
        )
    except asyncio.TimeoutError:
        return {
            "final_status": "timeout",
            "message": f"Timed out after {timeout} seconds."
        }


    return result

@mcp.tool()
async def search_analysis(query: Dict[str, str]) -> str:
    """
    Search the JoeSandbox Cloud for malware analyses using structured search parameters.

    Args:
        query: A dictionary containing one or more of the following parameters:

            - md5, sha1, sha256: Exact match
            - filename, url, tag, comments, ioc-url, ioc-dropped-file: Substring match
            - detection: One of 'clean', 'suspicious', 'malicious', 'unknown'
            - threatname: Exact match
            - before-date, after-date: ISO 8601 format (YYYY-MM-DD). These are exclusive (the date itself is not included).
            - ioc-domain, ioc-public-ip: Exact match

        Notes:
            - You must provide at least one of the supported parameters.
            - If multiple parameters are provided, all conditions must match (AND logic).
            - Searches are case-insensitive.
            - On the Cloud version, date comparisons use the CET/CEST time zone.
            - The 'q' parameter is not supported and should not be used.

        Examples:
            {"md5": "661f3e4454258ca6ab1a4c31742916c0"}
            {"threatname": "agenttesla", "before-date": "2024-12-01"}
            {"filename": "agent.exe", "detection": "malicious"}
    """
    res = await make_search_request(query)
    if not res:
        return "No results or an error occurred during the search."
    return str(res)

@mcp.tool()
async def get_analysis_info(webid: str) -> Dict[str, Any]:
    """
    Retrieve metadata and status for a previously submitted analysis by its submission ID.

    Use this tool to check whether an analysis is finished, whether the sample was classified as malicious,
    and to retrieve contextual metadata such as score, system, and tags.

    Args:
        webid (required): The submission ID (also called webid) returned when the sample was uploaded.

    Returns:
        If successful, returns a dictionary with fields such as:

        - status (e.g. "finished", "in progress"): Global analysis state.
        - detection (e.g. "malicious", "clean"): Overall result summary.
        - score (integer, e.g. 0-100): The final aggregated threat score.
        - filename: The original filename or download URL of the submitted sample.
        - tags: A list of classification or behavioral tags.
        - scriptname: The Joe Sandbox script used to run the analysis.
        - has_malwareconfig: True if malware configuration extraction succeeded.
        - md5, sha1, sha256: Hashes of the submitted sample.
        - time: The ISO8601 timestamp when the analysis was submitted.
        - duration: Total time (in seconds) the analysis took.
        - classification: Internal or customer-specific label (if set).
        - comments: Analyst comments or notes.
        - encrypted: Whether the submitted file was password-protected.
        - threatname: Identified malware families or on behavioral or signature matches.

        - runs: A list of dictionaries describing individual analysis runs on different systems.
            Each run contains:
            - system: The sandbox environment used (e.g., "w7x64l", "w10x64", "lnxubuntu20").
            - score: Detection score for that system.
            - detection: Result for that specific system (e.g., "malicious", "clean").
            - yara, sigma, suricata: Boolean flags indicating whether detection engines matched.
            - error: Any error that occurred during that specific run.

        Notes:
            - The `runs` array is useful when the same sample is executed on multiple OS environments.
            - The top-level `score` and `detection` reflect the most severe result across all runs.

        If the submission ID is invalid or expired, returns an error object with a reason.
    """
    try:
        result = await query_analysis_info(webid)
        return result
    except Exception as e:
        return {
            "error": f"Could not retrieve analysis info for submission ID '{webid}'. "
                     f"Reason: {str(e)}"
        }

@mcp.tool()
async def get_ai_summaries(webid: str, run: int=0) -> Dict[str, Any]:
    """
    Retrieve the AI summaries for a specific analysis run, either from cache or by downloading it.

    Joe Sandbox analyses may run on multiple system configurations (e.g., different Windows/Linux variants).
    Each run is indexed in the `runs` array of the analysis metadata. This function retrieves the report
    corresponding to a specific run.

    Args:
        webid: The submission ID of the analysis (unique identifier).
        run (optional, default = 0): The index of the analysis run to retrieve the report for.
                                     Use 0 for the first run, 1 for the second, etc.
                                     If not specified, defaults to 0 (the first run).

    Returns:
        A dictionary containing AI reasoning summaries with fields:
        - webid: The analysis ID
        - run: The run index
        - reasonings: List of AI reasoning entries
        - count: Number of reasoning entries found

    Notes:
        - Reports are cached in memory by key: "{webid}-{run}".
        - Use `run` to distinguish between different environments used during analysis.
    """

    try:
        root = await get_or_fetch_report(webid, run)
        if root is None:
            return {"error": f"Could not retrieve report for submission ID '{webid}', run {run}"}
        
        # Find all reasoning elements
        reasoning_elements = root.findall('./llm/reasonings/reasoning')
        
        if not reasoning_elements:
            return {
                "warning": "No AI reasoning summaries found in the report",
                "webid": webid,
                "run": run
            }
        
        # Extract the reasonings with their attributes
        reasonings = []
        for i, reasoning in enumerate(reasoning_elements):
            # Find the text element within this reasoning
            text_element = reasoning.find('./text')
            if text_element is not None and text_element.text:
                reasoning_data = {
                    "id": i + 1,
                    "text": text_element.text
                }
                
                # Add any attributes from the reasoning element
                for key, value in reasoning.attrib.items():
                    reasoning_data[key] = value
                
                reasonings.append(reasoning_data)
        
        return {
            "webid": webid,
            "run": run,
            "reasonings": reasonings,
            "count": len(reasonings)
        }
        
    except Exception as e:
        return {
            "error": f"Failed to process AI summaries for submission ID '{webid}'. "
                     f"Reason: {str(e)}"
        }

@mcp.tool()
async def get_dropped_info(webid: str, run: int = 0, only_malicious_elements: bool=True, only_malicious_indicators: bool=True) -> Dict[str, Any]:
    """
    Retrieve metadata for files dropped in a completed analysis, along with their associated detection indicators.

    This tool returns information about dropped files for a specific sandbox run of an analysis.
    Each result includes relevant metadata and detection indicators where available.

    Args:
        webid (required): The submission ID of the analysis.
        run (optional, default = 0): The index of the analysis run to inspect.
                                     Use 0 for the first run, 1 for the second, etc.
        only_malicious_elements (default: True): If True, returns only dropped files explicitly classified as malicious by the sandbox engine.
        only_malicious_indicators (default: True): If True, limits the returned indicators to those considered clearly malicious by the detection logic.
            This excludes low-impact behavioral signals and focuses on indicators with a high likelihood of malicious intent or confirmed threat classification.
            If False, all observed indicators are included regardless of their severity.

    Returns:
        A dictionary with:
          - webid: The analysis ID.
          - malicious_dropped_files: A list of dropped files marked as malicious, each with:
              - filename
              - sha256
              - size
              - type
              - process (originating process)
              - dump_name (sandbox-internal reference)
              - category (e.g., "dropped", "modified")
              - indicators: List of triggered detection rules, if any. Each entry includes:
                  - desc: Description of the matched detection rule.
                  - data: Matched content or signature.
                  - source: The detection subsystem responsible (e.g. Suricata, Sigma, global traffic etc.).
                      - impact: Either "high" or "low", indicating the severity or confidence of the detection.  
                          High-impact indicators are strongly associated with malicious behavior or confirmed threats.  
                          Low-impact indicators reflect general behavior or environmental traits that may not be malicious on their own.
          - count: Total number of malicious dropped files found
    Notes:
        - Empty Array returned if no dropped file was gathered during the analysis
    """

    try:
        root = await get_or_fetch_report(webid, run)
        if root is None:
            return {"error": f"Could not retrieve or parse report for submission ID '{webid}'"}

        dropped_files = root.findall('./droppedinfo/hash')
        results = []

        for dropped in dropped_files:
            attrs = dropped.attrib
            if attrs.get("malicious", "").lower() == "true" or not only_malicious_elements:
                indicators = get_indicators(dropped, only_malicious_indicators)
                file_info = {
                    "filename": attrs.get("file"),
                    "sha256": attrs.get("value"),
                    "type": attrs.get("type"),
                    "size": attrs.get("size"),
                    "process": attrs.get("process"),
                    "dump_name": attrs.get("dump"),
                    "category": attrs.get("category"),
                    "indicators": indicators
                }
                for hash_entry in dropped.findall('./value'):
                    key = hash_entry.attrib.get('algo')
                    if key:
                        file_info[key] = hash_entry.text.lower()

                # Drop any empty/null entries
                file_info = {k: v for k, v in file_info.items() if v}
                results.append(file_info)

        return {
            "webid": webid,
            "malicious_dropped_files": results,
            "count": len(results)
        }

    except Exception as e:
        return {
            "error": f"Failed to extract malicious dropped file data for submission ID '{webid}' run {run}. "
                     f"Reason: {str(e)}"
        }


@mcp.tool()
async def get_process_info(webid: str, run: int=0) -> Dict[str, Any]:
    """
    Extract and return the full process tree for a specific analysis run from a Joe Sandbox report.

    This tool traverses the execution tree recorded during dynamic analysis and returns a structured
    process hierarchy, showing which processes spawned others, with their respective attributes.

    Each process node includes:
      - name: Process executable name
      - pid: Process ID
      - cmdline: Full command-line invocation
      - path: File path of the executable
      - has_exited: Boolean flag indicating if the process terminated
      - children: List of child processes (if any), recursively structured
      - targetid: purely internal field, ignore this when replying to the user

    The result can be large and deeply nested, depending on the behavior of the sample. To improve
    readability, consider representing the tree using indentation or a UNIX-style `tree` layout. If the cmd args are not too long, consider displaying them as well, e.g.:

        parent.exe (1000) - "C:\Program Files\Parent\parent.exe"
        ├── child1.exe (1001) - "C:\Program Files\Parent\child1.exe --option"
        │   └── grandchild1.exe (1002) - "grandchild1.exe /silent"
        └── child2.exe (1003) - "child2.exe --config config.yaml --verbose"
            ├── grandchild2.exe (1004) - "grandchild2.exe"
            └── grandchild3.exe (1005) - "grandchild3.exe --debug --log-level=info"

    Args:
        webid (required): Submission ID of the analysis.
        run (default: 0): Index of the sandbox run to inspect (from the `runs` array in analysis info).

    Returns:
        Dictionary representing the root-level processes and their child process trees.
        If parsing or report retrieval fails, returns an error dictionary with a reason.
    """

    try:
        root = await get_or_fetch_report(webid, run)
        if root is None:
            return {"error": f"Could not retrieve or parse report for submission ID '{webid}' run {run}"}
        try:
            proc_tree = extract_process_tree(root)
        except Exception as e:
            return {"error": f"Could not reconstruct process tree for submission ID {webid} run {run}"}

        return proc_tree

    except Exception as e:
        return {
            "error": f"Failed to extract process tree for submission ID '{webid}' run {run}. "
                     f"Reason: {str(e)}"
        }

@mcp.tool()
async def get_domain_info(webid: str, run: int = 0, only_malicious_elements: bool=True, only_malicious_indicators: bool=True) -> Dict[str, Any]:
    """
    Retrieve domains in a completed analysis, along with their associated detection indicators.

    This tool extracts domains gathered by the sandbox engine and returns relevant context such as resolved IP address, activity status, and detection metadata.
    Optional filtering parameters allow control over the inclusion of domains and indicators based on their assessed severity.

    Args:
        webid (required): The submission ID of the analysis.
        run (default: 0): Index of the sandbox run to inspect (from the `runs` array in analysis info).
        only_malicious_elements (default: True): If True, returns only domains explicitly classified as malicious by the sandbox engine.
        only_malicious_indicators (default: True): If True, limits the returned indicators to those considered clearly malicious by the detection logic.
            This excludes low-impact behavioral signals and focuses on indicators with a high likelihood of malicious intent or confirmed threat classification.
            If False, all observed indicators are included regardless of their severity.

    Returns:
        A dictionary containing a list of malicious domains. Each entry includes:
          - name: The domain name.
          - ip: The resolved IP address, if available.
          - active: Whether the domain was reachable during analysis.
          - malicious: 'true' for domains classified as malicious
          - indicators: List of triggered detection rules, if any. Each entry includes:
              - desc: Description of the matched detection rule.
              - data: Matched content or signature.
              - source: The detection subsystem responsible (e.g. Suricata, Sigma, global traffic etc.).
                - impact: Either "high" or "low", indicating the severity or confidence of the detection.  
                    High-impact indicators are strongly associated with malicious behavior or confirmed threats.  
                    Low-impact indicators reflect general behavior or environmental traits that may not be malicious on their own.
    Notes:
        - Empty Array returned if no domain was gathered during the analysis
    """
    try:
        root = await get_or_fetch_report(webid, run)
        if root is None:
            return {"error": f"Could not retrieve or parse report for submission ID '{webid}' run {run}"}
        domaininfo = root.findall("./domaininfo/domain")
        domains = []
        for domain_entry in domaininfo:
            attrs = domain_entry.attrib
            if attrs.get("malicious") == "true" or not only_malicious_elements:
                indicators = get_indicators(domain_entry, only_malicious_indicators)
                domain = {
                    "name": attrs.get("name"),
                    "ip": attrs.get("ip"),
                    "active": attrs.get("active"),
                    "malicious": attrs.get("malicious"),
                    "indicators": indicators
                }
                domains.append(domain)
        return domains
    except Exception as e:
        return {
            "error": f"Failed to get domain info for submission ID '{webid}' run {run}. "
                     f"Reason: {str(e)}"
        }


@mcp.tool()
async def get_ip_info(webid: str, run: int = 0, only_malicious_elements: bool=True, only_malicious_indicators: bool=True) -> Dict[str, Any]:
    """
    Retrieve IP addresses in a completed analysis, along with their associated detection indicators.

    This tool extracts IP addresses gathered by the sandbox engine and returns relevant context such as geolocation, status, and detection metadata.
    Optional filtering parameters allow control over the inclusion of IP addresses and indicators based on their assessed severity.

    Args:
        webid (required): The submission ID of the analysis.
        run (default: 0): Index of the sandbox run to inspect (from the `runs` array in analysis info).
        only_malicious_elements (default: True): If True, returns only IP addresses explicitly classified as malicious by the sandbox engine.
        only_malicious_indicators (default: True): If True, limits the returned indicators to those considered clearly malicious by the detection logic.
            This excludes low-impact behavioral signals and focuses on indicators with a high likelihood of malicious intent or confirmed threat classification.
            If False, all observed indicators are included regardless of their severity.

    Returns:
        A dictionary containing a list of malicious IP addresses. Each entry includes:
          - ip: The IP address in question.
          - country: Country code associated with the IP.
          - pingable: Whether the IP responded during analysis.
          - domain: Resolved domain name (if available).
          - malicious: 'true' for IP addresses classified as malicious
          - indicators: List of triggered detection rules, if any. Each entry includes:
              - desc: Description of the matched detection rule.
              - data: Matched content or signature.
              - source: The detection subsystem responsible (e.g. Suricata, Sigma, global traffic etc.).
                - impact: Either "high" or "low", indicating the severity or confidence of the detection.  
                    High-impact indicators are strongly associated with malicious behavior or confirmed threats.  
                    Low-impact indicators reflect general behavior or environmental traits that may not be malicious on their own.
    Notes:
        - Empty Array returned if no ip was gathered during the analysis
    """
    try:
        root = await get_or_fetch_report(webid, run)
        if root is None:
            return {"error": f"Could not retrieve or parse report for submission ID '{webid}' run {run}"}
        ipinfo = root.findall("./ipinfo/ip")
        ips = []
        for ip_entry in ipinfo:
            attrs = ip_entry.attrib
            if attrs.get("malicious") == "true" or not only_malicious_elements:
                indicators = get_indicators(ip_entry, only_malicious_indicators)
                ip = {
                    "ip": attrs.get("ip"),
                    "country": attrs.get("country"),
                    "pingable": attrs.get("pingable"),
                    "domain": attrs.get("domain"),
                    "malicious": attrs.get("malicious"),
                    "indicators": indicators
                }
                ips.append(ip)
        return ips
    except Exception as e:
        return {
            "error": f"Failed to get IP info for submission ID '{webid}' run {run}. "
                     f"Reason: {str(e)}"
        }

@mcp.tool()
async def get_url_info(webid: str, run: int = 0, only_malicious_elements: bool=True, only_malicious_indicators: bool=True) -> Dict[str, Any]:
    """
    Retrieve urls in a completed analysis, along with their associated detection indicators.

    This tool extracts urls gathered by the sandbox engine and returns relevant context such as ip address, source, and detection metadata.
    Optional filtering parameters allow control over the inclusion of urls and indicators based on their assessed severity.

    Args:
        webid (required): The submission ID of the analysis.
        run (default: 0): Index of the sandbox run to inspect (from the `runs` array in analysis info).
        only_malicious_elements (default: True): If True, returns only urls explicitly classified as malicious by the sandbox engine.
        only_malicious_indicators (default: True): If True, limits the returned indicators to those considered clearly malicious by the detection logic.
            This excludes low-impact behavioral signals and focuses on indicators with a high likelihood of malicious intent or confirmed threat classification.
            If False, all observed indicators are included regardless of their severity.

    Returns:
        A dictionary containing a list of malicious URLs. Each entry includes:
          - url: The observed URL (may be truncated if extremely long).
          - ip: The resolved IP address associated with the URL (if available).
          - fromMemory: Whether the URL was extracted from memory.
          - source: Subsystem or extraction context (e.g., browser, process).
          - malicious: 'true' for urls classified as malicious
          - indicators: List of triggered detection rules, if any. Each entry includes:
              - desc: Description of the matched detection rule.
              - data: Matched content or signature.
              - source: The detection subsystem responsible (e.g. Suricata, Sigma, global traffic etc.).
    - impact: Either "high" or "low", indicating the severity or confidence of the detection.  
        High-impact indicators are strongly associated with malicious behavior or confirmed threats.  
        Low-impact indicators reflect general behavior or environmental traits that may not be malicious on their own.

    Notes:
        - Very long URLs are truncated for readability but include their original length as a hint.
        - Empty Array returned if no url was gathered during the analysis
    """
    try:
        root = await get_or_fetch_report(webid, run)
        if root is None:
            return {"error": f"Could not retrieve or parse report for submission ID '{webid}' run {run}"}
        urlinfo = root.findall("./urlinfo/url")
        urls = []
        for url_entry in urlinfo:
            attrs = url_entry.attrib
            if attrs.get("malicious") == "true" or not only_malicious_elements:
                indicators = get_indicators(url_entry, only_malicious_indicators)
                url = attrs.get("name")
                orig_len = len(url)
                if len(url) > 150:
                    url = url[:150] + f" <truncated url, orig length={orig_len}>"
                url = {
                    "url": url,
                    "ip": attrs.get("ip"),
                    "fromMemory": attrs.get("fromMemory"),
                    "source": attrs.get("source"),
                    "malicious": attrs.get("malicious"),
                    "indicators": indicators
                }
                urls.append(url)
        return urls
    except Exception as e:
        return {
            "error": f"Failed to get URL IOCs for submission ID '{webid}' run {run}. "
                     f"Reason: {str(e)}"
        }

@mcp.tool()
async def get_signature_info(webid: str, run: int = 0, only_malicious_indicators: bool = True) -> Dict[str, Any]:
    """
    Retrieve high-impact signature detections from a sandbox analysis report.

    This tool extracts detection signatures triggered during the specified analysis run. These signatures reflect behavioral or static patterns typically associated with malware, such as code injection, credential theft, or suspicious memory activity as well as general behavioural indicators.
    Optional filtering parameters allow control over the inclusion of all signatures or only those with high impact.

    Args:
        webid (required): The submission ID of the analysis.
        run (optional, default = 0): Index of the sandbox run to inspect (from the `runs` array in analysis info). Use 0 for the first run.
        only_malicious_indicators (default: True): If True, limits the returned signatures to those considered high impact by the detection logic.

    Returns:
        A dictionary containing a list of triggered detection signatures. Each entry includes:
        - desc: Description of the detected malicious behavior or technique.
        - indicators: List of up to three supporting observations. Each indicator includes:
            - desc: Action or operation that triggered the detection (e.g., "Section loaded").
            - context: Process name or source related to the event.
            - evidence: Supporting detail, such as file paths, memory dumps, or rule names.
            - impact: Either "high" or "low", indicating the severity or confidence of the detection.  
                High-impact indicators are strongly associated with malicious behavior or confirmed threats.  
                Low-impact indicators reflect general behavior or environmental traits that may not be malicious on their own.
    """
    try:
        root = await get_or_fetch_report(webid, run)
        if root is None:
            return {"error": f"Could not retrieve or parse report for submission ID '{webid}' run {run}"}
        siginfo = root.findall("./signatureinfo/sig")
        sigs = []
        for entry in siginfo:
            attrs = entry.attrib
            is_malicious_indicator = float(attrs.get("impact", 0.0)) >= 2.0
            if is_malicious_indicator or not only_malicious_indicators:
                sources = []
                for source_entry in entry.findall("./sources/source"):
                    source_attrib = source_entry.attrib
                    source = {
                        "desc": source_attrib.get("op"),
                        "context": source_attrib.get("process"),
                        "evidence" : source_entry.text,
                        "impact": "high" if is_malicious_indicator else "low"
                    }
                    sources.append(source)
                    if len(sources) >= 3:
                        break
                sig = {
                    "desc": attrs.get("desc"),
                    "indicators": sources
                }
                sigs.append(sig) 
        return sigs
    except Exception as e:
        return {
            "error": f"Failed to get signature info for submission ID '{webid}' run {run}. "
                     f"Reason: {str(e)}"
        }

@mcp.tool()
async def get_unpacked_files(webid: str, run: int = 0, save_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Retrieve and classify in-memory unpacked binaries from a sandbox analysis.

    This tool extracts executable artifacts that were unpacked in memory during the dynamic execution of the submitted sample. These binaries typically reflect runtime-decrypted payloads or memory-resident code generated by the sample or its child processes.

    Each extracted file is associated with:
    - The process ID (pid) responsible for its memory region.
    - A classification that indicates **when** during execution the memory snapshot was taken.

    If a custom `save_path` is provided, the files are saved under `{save_path}/{webid}-{run}`. If the path is invalid or inaccessible, a fallback directory under `unpacked_files/{webid}-{run}` is used instead.

    Snapshot types:
        - "Snapshot at beginning of execution": Memory captured at process start.
        - "Snapshot taken on unpacking (modifying executable sections or adding new ones)": Captured at runtime after self-modifying code or section manipulation.
        - "Snapshot at the end of execution": Captured near process termination.
        - "Snapshot taken when memory gets freed": Captured when memory regions were released.

    Args:
        webid (required): The submission ID of the analysis.
        run (optional, default = 0): Index of the sandbox run to process (typically 0 for the first run).
        save_path (optional): Optional base directory to store the unpacked files. If not valid, a default directory is used.

    Returns:
        A dictionary containing:
        - output_directory: Absolute path where the files were saved.
        - files: A list of unpacked file entries, each with:
            - unpacked_file: Absolute path to the file on disk.
            - pid: ID of the process associated with the memory region.
            - type: A human-readable label describing when the snapshot was taken.
        - note: A message indicating whether the fallback directory was used.
    """
    try:
        return await download_unpacked_files(webid, run, save_path)
    except Exception as e:
        return {
            "error": f"Failed to download unpacked files for submission ID '{webid}' run {run}. "
                     f"Reason: {str(e)}"
        }

@mcp.tool()
async def get_pcap_file(webid: str, run: int = 0, save_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Retrieve the network traffic capture (PCAP) file from a sandbox analysis.

    This tool downloads the full packet capture generated during execution of the submitted sample. The PCAP file contains all recorded network traffic for the specified sandbox run, including DNS requests, HTTP traffic, and raw TCP/UDP communications.

    The PCAP is saved locally with the name `{webid}-{run}.pcap`. If a custom `save_path` is provided, the file is written to that directory. If the path is invalid or inaccessible, the file is saved to a fallback directory named `pcap/`.

    Args:
        webid (required): The submission ID of the analysis.
        run (optional, default = 0): Index of the sandbox run to retrieve.
        save_path (optional): Custom directory to save the PCAP file. If invalid, a fallback location is used.

    Returns:
        A dictionary containing:
        - output_file: Absolute path to the downloaded PCAP file.
        - note: Message indicating whether the fallback directory was used.
    """
    try:
        return await download_pcap_file(webid, run, save_path)
    except Exception as e:
        return {
            "error": f"Failed to download pcap file for submission ID '{webid}' run {run}."
                     f"Reason: {str(e)}"
        }

@mcp.tool()
async def get_list_of_recent_analyses(limit: int = 20) -> List[Dict[str, Any]]:
    """
    List recent analyses submitted by the user.

    This tool returns a summary of the most recent sandbox analyses performed in the current account. Each entry includes the submission ID and a minimal set of metadata useful for follow-up actions such as downloading artifacts or examining behavior.

    By default, the tool returns the latest 20 analyses. You can override the `limit` parameter to retrieve more or fewer entries.

    For each analysis, the following fields are returned:
        - webid: Unique submission identifier.
        - time: Timestamp of when the analysis was submitted.
        - filename: Original submitted filename or URL.
        - sha256: SHA-256 hash of the submitted object.
        - score: Final detection score assigned by the sandbox.
        - detection: Verdict (e.g., clean, suspicious, malicious).
        - classification: Malware family or type (if available).
        - threatname: Named threat label (e.g., campaign or actor), if detected.
        - systems: List of sandbox systems the sample was run on.
        - num_runs: Total number of sandbox executions (runs) for this submission.

    Args:
        limit (optional, default = 20): The number of most recent analyses to return.

    Returns:
        A list of dictionaries summarizing each recent analysis.
    """
    return await asyncio.to_thread(list_recent_analyses, limit)


@mcp.tool()
async def get_memory_dumps(webid: str, run: int = 0, save_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Download and extract memory dumps from a Joe Sandbox analysis.

    This tool retrieves the 'memdumps' archive from the specified analysis run and extracts
    all contents into a local directory for further inspection. These files represent raw 
    memory snapshots taken during execution.

    Files are extracted as-is without renaming or classification.

    Output path logic:
    - If `save_path` is valid, dumps go to `{save_path}/memdumps/{webid}`
    - If not, fallback is `memdumps/{webid}` under the current directory

    Args:
        webid (str): Joe Sandbox analysis ID
        run (int, optional): Run index (default: 0)
        save_path (str, optional): Optional base path to save dumps

    Returns:
        dict: {
            "output_directory": absolute path to extraction folder,
            "info": "Info string detailing how many memory dumps were downloaded"
            "note": status message (e.g. fallback notice)
        }
    """
    try:
        return await download_memory_dumps(webid, run, save_path)
    except Exception as e:
        return {
            "error": f"Failed to download memory dumps for submission ID '{webid}' run {run}. "
                     f"Reason: {str(e)}"
        }

@mcp.tool()
async def get_dropped_files(webid: str, run: int = 0, save_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Download all dropped files from a Joe Sandbox analysis.

    This tool retrieves the 'dropped' archive from the specified analysis run and extracts
    all contents into a local directory for further inspection.

    Files are extracted as-is without renaming or classification.

    Output path logic:
    - If `save_path` is valid, dumps go to `{save_path}/droppedfiles/{webid}`
    - If not, fallback is `droppedfiles/{webid}` under the current directory

    Args:
        webid (str): Joe Sandbox analysis ID
        run (int, optional): Run index (default: 0)
        save_path (str, optional): Optional base path to save dumps

    Returns:
        dict: {
            "output_directory": absolute path to extraction folder,
            "files": list of files with full path
            "note": status message (e.g. fallback notice)
        }
    """
    try:
        return await download_dropped_files(webid, run, save_path)
    except Exception as e:
        return {
            "error": f"Failed to download dropped files for submission ID '{webid}' run {run}. "
                     f"Reason: {str(e)}"
        }