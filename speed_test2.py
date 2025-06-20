import requests
import base64
import json
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import sys
from datetime import datetime
import logging

# --- 配置日志 ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- 全局常量 ---
NODES_URL = "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/all_nodes.txt"
SUB_FILE = "data/sub.txt"
FAILED_FILE = "data/failed_proxies.json"
MAX_WORKERS = 100  # 增加并发线程数，取决于网络和服务器承受能力
CONNECTION_TIMEOUT = 7  # 端口连接超时时间（秒），略微增加以应对网络波动

# --- 辅助函数：解码 URL 编码 ---
def urldecode(s):
    """URL-decodes a string."""
    return requests.utils.unquote(s)

# --- 节点解析函数 ---
def parse_vmess(link):
    try:
        encoded_json = link[8:]
        # Base64 decode, handle padding and URL-safe variations
        decoded_json_bytes = base64.urlsafe_b64decode(encoded_json + '==')
        decoded_json = decoded_json_bytes.decode('utf-8')
        config = json.loads(decoded_json)
        address = config.get('add')
        port = config.get('port')
        ps = config.get('ps', 'Unnamed VMess')
        return address, port, ps
    except (TypeError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as e:
        logging.error(f"VMess Base64/JSON decode error for link {link[:50]}...: {e}")
        return None, None, f"VMess_Parsing_Error: {e}"
    except Exception as e:
        logging.error(f"Unexpected VMess parsing error for link {link[:50]}...: {e}")
        return None, None, f"VMess_Parsing_Error: {e}"

def parse_vless(link):
    try:
        # Regex to capture UUID, host, port, params, and name
        match = re.match(r"vless://([0-9a-fA-F-]+)@([^:]+):(\d+)(\?[^#]*)?(#.*)?", link)
        if match:
            # uuid = match.group(1) # Not needed for port test
            address = match.group(2)
            port = int(match.group(3))
            
            name_part = match.group(5)
            name = urldecode(name_part[1:]) if name_part and len(name_part) > 1 else "Unnamed VLESS"
            return address, port, name
        logging.warning(f"Invalid VLESS format for link: {link[:50]}...")
        return None, None, "Invalid VLESS format"
    except (ValueError, TypeError) as e:
        logging.error(f"VLESS port conversion error for link {link[:50]}...: {e}")
        return None, None, f"VLESS_Parsing_Error: {e}"
    except Exception as e:
        logging.error(f"Unexpected VLESS parsing error for link {link[:50]}...: {e}")
        return None, None, f"VLESS_Parsing_Error: {e}"

def parse_trojan(link):
    try:
        # Regex to capture password, host, port, params, and name
        match = re.match(r"trojan://([^@]+@)?([^:]+):(\d+)(\?[^#]*)?(#.*)?", link)
        if match:
            # password_part = match.group(1) # Not needed for port test
            address = match.group(2)
            port = int(match.group(3))

            name_part = match.group(5)
            name = urldecode(name_part[1:]) if name_part and len(name_part) > 1 else "Unnamed Trojan"
            return address, port, name
        logging.warning(f"Invalid Trojan format for link: {link[:50]}...")
        return None, None, "Invalid Trojan format"
    except (ValueError, TypeError) as e:
        logging.error(f"Trojan port conversion error for link {link[:50]}...: {e}")
        return None, None, f"Trojan_Parsing_Error: {e}"
    except Exception as e:
        logging.error(f"Unexpected Trojan parsing error for link {link[:50]}...: {e}")
        return None, None, f"Trojan_Parsing_Error: {e}"

def parse_ss_ssr(link):
    try:
        # SS/SSR links can be complex. They might be base64 encoded or direct.
        # This is a simplified parser focusing on server:port.
        match = re.match(r"(ss|ssr)://([^#]+)(#.*)?", link)
        if not match:
            logging.warning(f"Invalid SS/SSR format for link: {link[:50]}...")
            return None, None, "Invalid SS/SSR format"

        protocol_type = match.group(1)
        encoded_or_raw_part = match.group(2)
        name_part = match.group(3)
        name = urldecode(name_part[1:]) if name_part and len(name_part) > 1 else f"Unnamed {protocol_type.upper()}"

        decoded_part = ""
        try:
            # Try URL-safe base64 decode first
            decoded_part_bytes = base64.urlsafe_b64decode(encoded_or_raw_part + '==')
            decoded_part = decoded_part_bytes.decode('utf-8')
        except (TypeError, ValueError, UnicodeDecodeError):
            decoded_part = encoded_or_raw_part # Not base64 or failed decode, treat as raw

        # Look for @host:port pattern in either decoded or raw part
        server_match = re.search(r"@([^:]+):(\d+)", decoded_part)
        if not server_match:
            server_match = re.search(r"@([^:]+):(\d+)", encoded_or_raw_part) # Fallback to raw if not found in decoded

        if server_match:
            address = server_match.group(1)
            port = int(server_match.group(2))
            return address, port, name
        
        logging.warning(f"Could not find server:port in {protocol_type.upper()} link: {link[:50]}...")
        return None, None, f"SS/SSR_Parsing_Error: Server/Port not found"
    except (ValueError, TypeError) as e:
        logging.error(f"SS/SSR port conversion error for link {link[:50]}...: {e}")
        return None, None, f"SS/SSR_Parsing_Error: {e}"
    except Exception as e:
        logging.error(f"Unexpected SS/SSR parsing error for link {link[:50]}...: {e}")
        return None, None, f"SS/SSR_Parsing_Error: {e}"

def parse_hysteria2(link):
    try:
        # hysteria2://uuid@host:port/?params#name
        match = re.match(r"hysteria2://([^@]+@)?([^:]+):(\d+)(\?[^#]*)?(#.*)?", link)
        if match:
            # uuid_part = match.group(1) # Not needed for port test
            address = match.group(2)
            port = int(match.group(3))
            
            name_part = match.group(5)
            name = urldecode(name_part[1:]) if name_part and len(name_part) > 1 else "Unnamed Hysteria2"
            return address, port, name
        logging.warning(f"Invalid Hysteria2 format for link: {link[:50]}...")
        return None, None, "Invalid Hysteria2 format"
    except (ValueError, TypeError) as e:
        logging.error(f"Hysteria2 port conversion error for link {link[:50]}...: {e}")
        return None, None, f"Hysteria2_Parsing_Error: {e}"
    except Exception as e:
        logging.error(f"Unexpected Hysteria2 parsing error for link {link[:50]}...: {e}")
        return None, None, f"Hysteria2_Parsing_Error: {e}"

def parse_node_link(link):
    """Parses a full node link, extracts relevant info and original details."""
    original_link_full = link.strip().replace('\r', '') # Keep original for output
    
    # Extract existing latency and name for re-application
    existing_latency_match = re.search(r"(_\d+ms)", original_link_full)
    existing_latency_str = existing_latency_match.group(1) if existing_latency_match else ""
    
    existing_name_match = re.search(r"(#.*)", original_link_full)
    existing_name_str = existing_name_match.group(1) if existing_name_match else ""
    
    # Clean link for protocol parsing
    link_base_for_parsing = re.sub(r"_\d+ms", "", original_link_full).split('#')[0].strip()

    if link_base_for_parsing.startswith("vmess://"):
        addr, port, name = parse_vmess(link_base_for_parsing)
        return "vmess", addr, port, name, original_link_full, existing_latency_str, existing_name_str
    elif link_base_for_parsing.startswith("vless://"):
        addr, port, name = parse_vless(link_base_for_parsing)
        return "vless", addr, port, name, original_link_full, existing_latency_str, existing_name_str
    elif link_base_for_parsing.startswith("trojan://"):
        addr, port, name = parse_trojan(link_base_for_parsing)
        return "trojan", addr, port, name, original_link_full, existing_latency_str, existing_name_str
    elif link_base_for_parsing.startswith("ss://") or link_base_for_parsing.startswith("ssr://"):
        addr, port, name = parse_ss_ssr(link_base_for_parsing)
        return "ss/ssr", addr, port, name, original_link_full, existing_latency_str, existing_name_str
    elif link_base_for_parsing.startswith("hysteria2://"):
        addr, port, name = parse_hysteria2(link_base_for_parsing)
        return "hysteria2", addr, port, name, original_link_full, existing_latency_str, existing_name_str
    else:
        logging.warning(f"Unsupported protocol encountered: {link_base_for_parsing[:50]}...")
        return "unknown", None, None, "Unsupported Protocol", original_link_full, existing_latency_str, existing_name_str

# --- 端口连通性测试函数 ---
def test_port_connectivity(node_parsed_info):
    protocol, address, port, name, original_link_full, existing_latency_str, existing_name_str = node_parsed_info
    
    result = {
        "status": "failed",
        "reason": "Unknown Error",
        "link": original_link_full, # Store the full original link for failed nodes
        "latency": -1,
        "node_name": name # Parsed or default name
    }

    if not address or not isinstance(port, int) or port <= 0 or port > 65535:
        result['reason'] = f"Invalid Address/Port: {address}:{port}"
        logging.error(f"Invalid address or port for {name} ({original_link_full[:50]}...): {result['reason']}")
        return result

    try:
        start_time = time.time()
        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONNECTION_TIMEOUT)

        # Resolve hostname to IP address, handle resolution errors
        try:
            ip_address = socket.gethostbyname(address)
        except socket.gaierror as e:
            result['reason'] = f"DNS Resolution Failed: {e}"
            logging.warning(f"DNS resolution failed for {name} ({address}): {e}")
            return result
        except Exception as e:
            result['reason'] = f"DNS Resolution Unknown Error: {e}"
            logging.error(f"Unexpected DNS error for {name} ({address}): {e}")
            return result

        # Connect to the target address and port
        sock.connect((ip_address, port))
        end_time = time.time()
        latency_ms = int((end_time - start_time) * 1000)

        sock.close()
        result.update({
            "status": "success",
            "reason": "Connected",
            "latency": latency_ms
        })
        logging.info(f"Success: {name} ({address}:{port}) - {latency_ms}ms")
        return result
    except socket.timeout:
        result['reason'] = "Connection Timeout"
        logging.warning(f"Timeout: {name} ({address}:{port})")
        return result
    except ConnectionRefusedError:
        result['reason'] = "Connection Refused"
        logging.warning(f"Refused: {name} ({address}:{port})")
        return result
    except socket.error as e:
        result['reason'] = f"Socket Error: {e}"
        logging.warning(f"Socket error for {name} ({address}:{port}): {e}")
        return result
    except Exception as e:
        result['reason'] = f"Unhandled Testing Error: {e}"
        logging.critical(f"Critical error during testing for {name} ({address}:{port}): {e}")
        return result

# --- 文件操作函数 ---
def load_existing_nodes(file_path):
    """Loads cleaned node links from a file for deduplication."""
    existing_links = set()
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#') or line.startswith('-'): # Skip comments and YAML list indicators
                        continue
                    # Remove _latency_ms and #name for comparison
                    cleaned_line = re.sub(r"_\d+ms", "", line).split('#')[0].strip()
                    if cleaned_line:
                        existing_links.add(cleaned_line)
        except Exception as e:
            logging.error(f"Error loading existing nodes from {file_path}: {e}")
    return existing_links

def load_failed_proxies(file_path):
    """Loads failed proxy links from JSON file for incremental testing."""
    failed_links = set()
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                failed_data = json.load(f)
                if isinstance(failed_data, list):
                    for entry in failed_data:
                        if 'link' in entry and isinstance(entry['link'], str):
                            # Store only the base link for comparison
                            failed_links.add(re.sub(r"_\d+ms", "", entry['link']).split('#')[0].strip())
                else:
                    logging.warning(f"Invalid JSON format in {file_path}: Expected a list.")
        except json.JSONDecodeError as e:
            logging.error(f"Failed to decode JSON from {file_path}: {e}. File might be corrupted.")
            # Optionally, back up the corrupted file and create an empty one
        except FileNotFoundError:
            pass # File does not exist, no failed nodes to load
        except Exception as e:
            logging.error(f"Unexpected error loading failed proxies from {file_path}: {e}")
    return failed_links

def get_nodes_from_url(url):
    """Fetches raw node lines from a URL."""
    try:
        response = requests.get(url, timeout=15) # Increased timeout for fetching
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        return response.text.splitlines()
    except requests.exceptions.Timeout:
        logging.error(f"Timeout fetching nodes from URL {url}.")
        return []
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching nodes from URL {url}: {e}")
        return []
    except Exception as e:
        logging.critical(f"Critical error fetching nodes from URL {url}: {e}")
        return []

def write_successful_nodes(results, file_path):
    """Appends sorted successful nodes to the file."""
    if not results:
        return

    # Prepare lines with proper formatting
    lines_to_write = []
    for result in results:
        # Reconstruct the link: base part + new latency + original name
        cleaned_link_base = re.sub(r"_\d+ms", "", result['link']).split('#')[0].strip()
        final_link = f"{cleaned_link_base}_{result['latency']}ms"
        
        # Append original name part if it existed, otherwise try to use parsed name
        if result['link'].strip().endswith(result['existing_name_str']): # If original link ended with its name part
            final_link = f"{final_link}{result['existing_name_str']}"
        elif result['node_name'] and result['node_name'] not in ["Unnamed VMess", "Unnamed VLESS", "Unnamed Trojan", "Unnamed SS/SSR", "Unnamed Hysteria2"]:
            # Only add parsed name if it's not a generic placeholder and no original name was present
            if not re.search(r"#[^#]*$", final_link): # Ensure no existing #name already
                 final_link = f"{final_link}#{result['node_name']}"

        lines_to_write.append(final_link)

    try:
        # Append to the file
        with open(file_path, 'a', encoding='utf-8') as f:
            f.write(f"\n# Updated by GitHub Actions at {datetime.utcnow().strftime('%a %b %d %H:%M:%S UTC %Y')}\n")
            f.write("-------------------------------------\n")
            f.write("\n".join(lines_to_write))
            f.write("\n") # Ensure a newline at the end
        logging.info(f"Appended {len(results)} successful nodes to {file_path}")
    except IOError as e:
        logging.error(f"Error writing successful nodes to {file_path}: {e}")
    except Exception as e:
        logging.critical(f"Unexpected error writing successful nodes to {file_path}: {e}")

def write_failed_proxies(results, file_path):
    """Merges and overwrites failed proxies to the JSON file."""
    # Load existing failed proxies
    existing_failed_data = []
    if os.path.exists(file_path) and os.stat(file_path).st_size > 0:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                existing_failed_data = json.load(f)
            if not isinstance(existing_failed_data, list): # Handle corrupted non-list JSON
                logging.warning(f"{file_path} is not a JSON list. Resetting failed proxies file.")
                existing_failed_data = []
        except json.JSONDecodeError as e:
            logging.error(f"Failed to decode JSON from {file_path}: {e}. File might be corrupted. Overwriting.")
            existing_failed_data = []
        except Exception as e:
            logging.error(f"Unexpected error loading existing failed proxies from {file_path}: {e}. Overwriting.")
            existing_failed_data = []
    
    # Convert new failed results to the desired format
    new_failed_entries = []
    for r in results:
        # Avoid storing existing latency or name in failed.json for cleaner tracking
        cleaned_link_for_fail_json = re.sub(r"_\d+ms", "", r['link']).split('#')[0].strip()
        
        # If there was an original #name, include it in the failed link
        original_name_match = re.search(r"(#.*)", r['link'])
        if original_name_match:
            cleaned_link_for_fail_json = f"{cleaned_link_for_fail_json}{original_name_match.group(1)}"

        new_failed_entries.append({
            "link": cleaned_link_for_fail_json,
            "reason": r['reason'],
            "timestamp": datetime.utcnow().isoformat()
        })
    
    # Merge existing and new, then deduplicate
    # Use a dictionary to easily deduplicate by base link
    merged_failed_data_dict = {}
    for entry in existing_failed_data + new_failed_entries:
        if 'link' in entry and isinstance(entry['link'], str):
            # Use the base link as key for deduplication
            base_link_for_key = re.sub(r"_\d+ms", "", entry['link']).split('#')[0].strip()
            merged_failed_data_dict[base_link_for_key] = entry # Overwrite with newer entry if duplicate

    final_failed_list = list(merged_failed_data_dict.values())

    try:
        # Overwrite the file with the merged, deduplicated list
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(final_failed_list, f, ensure_ascii=False, indent=2)
        logging.info(f"Updated {file_path} with {len(results)} new failed entries (total {len(final_failed_list)}).")
    except IOError as e:
        logging.error(f"Error writing failed proxies to {file_path}: {e}")
    except Exception as e:
        logging.critical(f"Unexpected error writing failed proxies to {file_path}: {e}")

# --- 主逻辑 ---
def main():
    logging.info("Starting proxy node speed test.")

    # Ensure data directory exists
    os.makedirs(os.path.dirname(SUB_FILE), exist_ok=True)
    os.makedirs(os.path.dirname(FAILED_FILE), exist_ok=True)

    # Load existing successful and failed nodes for incremental testing
    existing_successful_links = load_existing_nodes(SUB_FILE)
    existing_failed_links = load_failed_proxies(FAILED_FILE)

    logging.info(f"Loaded {len(existing_successful_links)} existing successful nodes from {SUB_FILE}.")
    logging.info(f"Loaded {len(existing_failed_links)} existing failed nodes from {FAILED_FILE}.")

    # Fetch new nodes from the URL
    raw_nodes_lines = get_nodes_from_url(NODES_URL)
    if not raw_nodes_lines:
        logging.warning("No nodes fetched from URL. Exiting.")
        return

    nodes_to_test_parsed = []
    # Use a set to track nodes added to nodes_to_test_parsed in the current run
    current_run_processed_base_links = set() 

    for line_num, line in enumerate(raw_nodes_lines, 1):
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith('#'):
            continue

        # Get base link for comparison (without latency/name)
        base_link_for_comparison = re.sub(r"_\d+ms", "", line_stripped).split('#')[0].strip()
        
        # Check against already processed/tested nodes
        if base_link_for_comparison in existing_successful_links:
            logging.info(f"Skipping already successful node (Line {line_num}): {line_stripped[:50]}...")
            continue
        if base_link_for_comparison in existing_failed_links:
            logging.info(f"Skipping previously failed node (Line {line_num}): {line_stripped[:50]}...")
            continue
        if base_link_for_comparison in current_run_processed_base_links:
            logging.info(f"Skipping duplicate node in current input (Line {line_num}): {line_stripped[:50]}...")
            continue
        
        # Add to set for current run deduplication
        current_run_processed_base_links.add(base_link_for_comparison)
        
        # Parse the node link
        node_parsed_info = parse_node_link(line_stripped)
        protocol, addr, port, name, original_link_full, existing_latency_str, existing_name_str = node_parsed_info

        if protocol == "unknown" or addr is None or port is None:
            logging.error(f"Skipping node due to parsing error (Line {line_num}): {original_link_full[:50]}... Reason: {name}")
            # Add to failed results immediately if parsing fails
            failed_results_on_parse = {
                "status": "failed",
                "reason": f"Parsing Error: {name}",
                "link": original_link_full,
                "latency": -1,
                "node_name": name
            }
            write_failed_proxies([failed_results_on_parse], FAILED_FILE) # Write immediately to avoid losing info
            continue
        
        nodes_to_test_parsed.append(node_parsed_info)

    if not nodes_to_test_parsed:
        logging.info("No new unique nodes to test after filtering. Exiting.")
        return

    logging.info(f"Found {len(nodes_to_test_parsed)} new unique nodes to test.")

    successful_test_results = []
    failed_test_results = [] # Store results from the current test run

    # --- 并行测试 ---
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Submit all parsing results to the executor
        future_to_node_info = {executor.submit(test_port_connectivity, node_info): node_info for node_info in nodes_to_test_parsed}

        for future in as_completed(future_to_node_info):
            original_node_info = future_to_node_info[future] # Retrieve original info for logging
            
            try:
                result = future.result()
                if result['status'] == 'success':
                    # Add original metadata back for successful write
                    result['existing_latency_str'] = original_node_info[5]
                    result['existing_name_str'] = original_node_info[6]
                    successful_test_results.append(result)
                else:
                    failed_test_results.append(result)
                logging.info(f"Test Result: {result['link'].split('#')[0][:50]}... - {result['status']} ({result['latency']}ms / {result['reason']})")
            except Exception as exc:
                # Catch any unexpected errors from the thread execution
                logging.error(f"Node {original_node_info[3]} ({original_node_info[4][:50]}...) generated an exception: {exc}")
                failed_test_results.append({
                    "status": "failed",
                    "reason": f"Execution Exception: {exc}",
                    "link": original_node_info[4], # Use original full link
                    "latency": -1,
                    "node_name": original_node_info[3] # Original parsed name
                })

    # Sort successful nodes by latency
    successful_test_results.sort(key=lambda x: x['latency'])

    # Write results to files
    write_successful_nodes(successful_test_results, SUB_FILE)
    write_failed_proxies(failed_test_results, FAILED_FILE)
    
    logging.info("Testing complete.")

if __name__ == "__main__":
    main()
