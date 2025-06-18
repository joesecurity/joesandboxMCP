__all__ = [
    'initialize_client',
    'get_client',
    'AsyncReportCache',
    'report_cache',
    'get_or_fetch_report',
    'make_search_request',
    'make_submission',
    'query_analysis_info',
    'extract_process_tree',
    'download_unpacked_files',
    'download_pcap_file',
    'list_recent_analyses',
    'get_indicators'
]

import os
import asyncio
import httpx
import io
import re
import zipfile
import jbxapi
import xml.etree.ElementTree as ET
from collections import OrderedDict, deque
from typing import Any, Dict, Optional, List

# API endpoint
JBXCLOUD_APIURL = "https://jbxcloud.joesecurity.org/api/"

# Global client instance
jbx_client = None


def initialize_client():
    """
    Initialize the Joe Sandbox API client.
    
    This function initializes the global jbx_client instance using the API key
    from the environment variables.
    
    Returns:
        The initialized JoeSandbox client instance.
    """
    global jbx_client
    
    # Get API key from environment
    JBXAPIKEY = os.getenv("JBXAPIKEY")
    
    if not JBXAPIKEY:
        raise ValueError("JBXAPIKEY environment variable is not set.")
    
    # Initialize the client
    jbx_client = jbxapi.JoeSandbox(
        apikey=JBXAPIKEY,
        apiurl=JBXCLOUD_APIURL,
        accept_tac=True
    )
    
    return jbx_client

def get_client():
    global jbx_client
    
    if jbx_client is None:
        initialize_client()
    
    return jbx_client

class AsyncReportCache:
    """
    Asynchronous cache for Joe Sandbox reports.
    
    This class provides a thread-safe cache for storing and retrieving
    Joe Sandbox reports using asyncio locks.
    """
    def __init__(self, max_size: int=10):
        self._cache: OrderedDict[str, bytes] = OrderedDict()
        self._lock = asyncio.Lock()
        self._max_size = max_size
    
    async def get(self, cache_key: str) -> Optional[bytes]:
        async with self._lock:
            return self._cache.get(cache_key)
    
    async def set(self, cache_key: str, xml: bytes):
        async with self._lock:
            if cache_key in self._cache:
                self._cache.move_to_end(cache_key)
            else:
                self._cache[cache_key] = xml
                if len(self._cache) > self._max_size:
                    self._cache.popitem(last=False)

# Create a global cache instance
report_cache = AsyncReportCache(max_size=10)

async def get_or_fetch_report(webid: str, run: int=0) -> Optional[ET.Element]:
    """
    Get a report from the cache or fetch it from the API.
    
    Args:
        webid: The webid of the report to retrieve.
        run: The analysis run index of the report to retrieve, default: 0
        
    Returns:
        The report as an XML Element, or None if it couldn't be retrieved.
    """
    cache_key = f"{webid}-{run}"
    cached = await report_cache.get(cache_key)
    if cached:
        xml_stream = io.BytesIO(cached)
        xml_tree = ET.parse(xml_stream)
        return xml_tree.getroot()
    
    # If not in cache, fetch from API
    def blocking_download():
        client = get_client()
        _, data = client.analysis_download(webid=webid, type='xml', run=run)
        return data
    
    try:
        data = await asyncio.to_thread(blocking_download)
        await report_cache.set(cache_key, data)
        xml_stream = io.BytesIO(data)
        xml_tree = ET.parse(xml_stream)
        xml_root = xml_tree.getroot()
        return xml_root
    except Exception as e:
        print(f"Error fetching report for webid {webid}, run {run}: {e}")
        return None

async def make_search_request(query_dict: Dict[str, str]) -> Optional[Dict[str, Any]]:
    """
    Query jbxapi for a search in the existing analyses.
    
    Args:
        query_dict: A dictionary of search parameters.
        
    Returns:
        The search results as a dictionary, or None if the search failed.
    """
    query_dict['apikey'] = os.getenv("JBXAPIKEY")
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(JBXCLOUD_APIURL + "v2/analysis/search", data=query_dict)
            return response.json()
        except Exception as e:
            print(f"Error during analysis search: {e}")
            return None

async def make_submission(
    wait_for_analysis_end: bool,
    sample_path: Optional[str] = None,
    sample_url: Optional[str] = None,
    website_url: Optional[str] = None,
    command_line: Optional[str] = None,
    params: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Submit a sample, URL, website, or command line for analysis.
    
    Only one of the input methods should be provided. Raises ValueError if none or multiple are given.
    
    Args:
        wait_for_analysis_end: wait until the analysis is finished before returning the result
        sample_path: Path to a local file.
        sample_url: URL of a remote sample file.
        website_url: Website URL to analyze.
        command_line: Command line string to analyze.
        params: Dictionary of sandbox parameters.
        
    Returns:
        A dict containing the submission result.
        
    Raises:
        ValueError: If none or multiple input methods are provided.
    """
    params = params or {}
    client = get_client()
    
    # Check that exactly one input method is provided
    methods_provided = sum(bool(x) for x in [sample_path, sample_url, website_url, command_line])
    if methods_provided != 1:
        raise ValueError("Exactly one of sample_path, sample_url, website_url, or command_line must be provided.")

    # Submit based on the input method
    if sample_path:
        def blocking_upload():
            with open(sample_path, 'rb') as f:
                return client.submit_sample(f, params=params)
        submission_obj =  await asyncio.to_thread(blocking_upload)

    elif sample_url:
        submission_obj = client.submit_sample_url(sample_url, params=params)

    elif website_url:
        submission_obj = client.submit_url(website_url, params=params)

    elif command_line:
        submission_obj = client.submit_command_line(command_line, params=params)
    
    return await poll_submission(submission_obj, wait_for_analysis_end)
    
async def poll_submission(
    submission_obj: Dict[str, Any],
    wait_for_analysis_end: bool,
    poll_interval: int = 3
) -> Dict[str, Any]:
    """
    Polls the submission state from Joe Sandbox API

    Args:
        submission_obj containing the submission id
        wait_for_analysis_end: True if the function should only return if the analysis has concluded
    """
    def blocking_func(submission_id: str):
        return jbx_client.submission_info(submission_id=submission_id)

    jbx_client = get_client()
    await asyncio.sleep(5)  # allow submission to initialize
    submission_id = submission_obj.get("submission_id") or submission_obj.get("submission-id")

    while True:
        info = await asyncio.to_thread(blocking_func, submission_id)
        # If not waiting, or analysis has completed
        if not wait_for_analysis_end or info.get("status") == "finished":
            analyses = info.get("analyses", [])
            result = {
                "analyses": [
                    {
                        "webid": a.get("webid"),
                        "sha256": a.get("sha256"),
                        "filename": a.get("filename"),
                        "status": info.get("status"),
                    }
                    for a in analyses
                ]
            }
            return result

        await asyncio.sleep(poll_interval)


async def query_analysis_info(webid: str) -> Dict[str, Any]:
    """
    Query information about an analysis.
    
    Args:
        webid: The webid of the analysis to query.
        
    Returns:
        A dictionary containing information about the analysis.
    """
    client = get_client()
    
    def blocking_query():
        return client.analysis_info(webid=webid)
    
    return await asyncio.to_thread(blocking_query)

def extract_process_tree(process_elements) -> Dict[str, Any]:
    """
    Reconstructs a process tree as a nested json array from the xml report
    """
    def process_node(proc_elem):
        # Extract key attributes
        attrs = proc_elem.attrib
        node = {
            "name": attrs.get("name"),
            "pid": attrs.get("pid"),
            "cmdline": attrs.get("cmdline"),
            "path": attrs.get("path"),
            "targetid": attrs.get("targetid"),
            "has_exited": attrs.get("hasexited") == "true"
        }

        # Recursively extract children
        children = proc_elem.findall("./process")
        if children:
            node["children"] = [process_node(child) for child in children]

        return node
    process_elements = process_elements.findall("./behavior/system/startupoverview/process")
    return [process_node(p) for p in process_elements]

def flatten_process_tree(proc_tree: List[Dict[str, Any]]) -> Dict[str, str]:
    """
    Flatten the process tree and return a mapping from targetid to process ID (pid).
    """
    targetid_to_pid = {}
    queue = deque(proc_tree)
    while queue:
        node = queue.popleft()
        if "targetid" in node and "pid" in node:
            targetid_to_pid[str(node["targetid"])] = str(node["pid"])
        if "children" in node:
            queue.extend(node["children"])
    return targetid_to_pid

def extract_unpack_filename_metadata(filename: str) -> Optional[Dict[str, Any]]:
    """
    Extract the targetid and frame id from the filename pattern:
    e.g., '1.2.filename.exe.abc.unpack' → targetid='1', frame_id=2
    """
    frame_map = {
        -1: "UNKNOWN",
        0: "Snapshot at beginning of execution",
        1: "Snapshot taken on unpacking (modifying executable sections or adding new ones)",
        2: "Snapshot at the end of execution",
        3: "Snapshot taken when memory gets freed"
    }
    match = re.match(r'^(\d+)\.(\d+)\..+\.unpack$', filename)
    if not match:
        return None
    targetid, frame_id = match.groups()
    frame_id = int(frame_id)
    return {
        "targetid": targetid,
        "frame_label": frame_map.get(frame_id, "UNKNOWN")
    }

async def download_unpacked_files(webid: str, run: Optional[int] = 0, save_path: Optional[str] = None) -> Dict[str, Any]:
    jbx_client = get_client()
    _, data = jbx_client.analysis_download(webid=webid, run=run, type='unpackpe')

    default_output_dir = os.path.join("unpacked_files", f"{webid}-{run}")
    output_dir = default_output_dir
    used_default_path = False

    root = await get_or_fetch_report(webid, run)
    proc_tree = extract_process_tree(root)
    targetid_to_pid = flatten_process_tree(proc_tree)

    if save_path:
        try:
            output_dir = os.path.join(save_path, f"{webid}-{run}")
            os.makedirs(output_dir, exist_ok=True)
        except (OSError, FileNotFoundError):
            output_dir = default_output_dir
            os.makedirs(output_dir, exist_ok=True)
            used_default_path = True
    else:
        os.makedirs(output_dir, exist_ok=True)

    # Extract files and associate them with process IDs and frame stages
    unpacked_files_info = []

    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        zf.extractall(path=output_dir, pwd=b"infected")
        for name in zf.namelist():
            if name.endswith('/') or '.raw.' in name:
                continue
            base = os.path.basename(name)
            metadata = extract_unpack_filename_metadata(base)
            if metadata is None:
                continue
            targetid = metadata["targetid"]
            frame_label = metadata["frame_label"]
            pid = targetid_to_pid.get(targetid, "unknown")
            full_path = os.path.abspath(os.path.join(output_dir, name))
            unpacked_files_info.append({
                "unpacked_file": full_path,
                "pid": pid,
                "type": frame_label
            })

    note = (
        "User-provided save_path was invalid. Default directory was used."
        if used_default_path else
        "Extraction completed successfully."
    )

    return {
        "output_directory": os.path.abspath(output_dir),
        "files": unpacked_files_info,
        "note": note
    }

async def download_pcap_file(webid: str, run: Optional[int] = 0, save_path: Optional[str] = None) -> Dict[str, Any]:
    jbx_client = get_client()
    try:
        _, data = jbx_client.analysis_download(webid=webid, run=run, type='pcapunified')
    except Exception as e:
        _, data = jbx_client.analysis_download(webid=webid, type='pcap')

    filename = f"{webid}-{run}.pcap"
    default_output_dir = os.path.join("pcap")
    output_dir = default_output_dir
    used_default_path = False

    if save_path:
        try:
            os.makedirs(save_path, exist_ok=True)
            output_dir = save_path
        except (OSError, FileNotFoundError):
            os.makedirs(default_output_dir, exist_ok=True)
            used_default_path = True
    else:
        os.makedirs(default_output_dir, exist_ok=True)

    full_path = os.path.abspath(os.path.join(output_dir, filename))

    with open(full_path, "wb") as f:
        f.write(data)

    note = (
        "User-provided save_path was invalid. Default directory was used."
        if used_default_path else
        "PCAP download completed successfully."
    )

    return {
        "output_file": full_path,
        "note": note
    }

def list_recent_analyses(limit: int = 20) -> List[Dict[str, Any]]:
    jbx_client = get_client()
    results = []

    for each in jbx_client.analysis_list_paged():
        info = jbx_client.analysis_info(webid=each["webid"])

        systems = list({run.get("system") for run in info.get("runs", []) if run.get("system")})
        num_runs = len(info.get("runs", []))

        results.append({
            "webid": info.get("webid"),
            "time": info.get("time"),
            "filename": info.get("filename"),
            "sha256": info.get("sha256"),
            "score": info.get("score"),
            "detection": info.get("detection"),
            "classification": info.get("classification"),
            "threatname": info.get("threatname"),
            "systems": systems,
            "num_runs": num_runs,
        })

        if len(results) >= limit:
            break

    return results

def get_indicators(xml_element: ET.Element, only_malicious_indicators: bool) -> List[Dict[str, str]]:
    indicators = []
    for indic in xml_element.findall("./sighits/sig"):
        indic_attrib = indic.attrib
        is_malicious_indicator = float(indic_attrib.get("impact", 0.0)) >= 2.0
        if  is_malicious_indicator or not only_malicious_indicators:
            indicator = {
                "desc": indic_attrib.get("desc"),
                "data": indic_attrib.get("data"),
                "source": indic_attrib.get("source"),
                "impact": "high" if is_malicious_indicator else "low"
            }
            indicators.append(indicator)
    return indicators
