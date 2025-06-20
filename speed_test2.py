import requests
import base64
import json
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
import argparse
import sys
from datetime import datetime

# 文件路径
NODES_URL = "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/nodes.txt"
SUB_FILE = "data/sub.txt"
FAILED_FILE = "data/failed_proxies.json"
MAX_WORKERS = 50  # 并发测试的线程数
CONNECTION_TIMEOUT = 5  # 端口连接超时时间（秒）

def parse_vmess(link):
    try:
        encoded_json = link[8:]
        decoded_json = base64.b64decode(encoded_json).decode('utf-8')
        config = json.loads(decoded_json)
        address = config.get('add')
        port = config.get('port')
        ps = config.get('ps', 'Unnamed VMess') # 提取节点名称
        return address, port, ps
    except Exception as e:
        return None, None, f"Error parsing VMess: {e}"

def parse_vless(link):
    try:
        # vless://uuid@host:port?params#name
        match = re.match(r"vless://[^@]+@([^:]+):(\d+)(\?[^#]*)?(#.*)?", link)
        if match:
            address = match.group(1)
            port = int(match.group(2))
            name_match = re.search(r"#(.*)", link)
            name = name_match.group(1) if name_match else "Unnamed VLESS"
            return address, port, name
        return None, None, "Invalid VLESS format"
    except Exception as e:
        return None, None, f"Error parsing VLESS: {e}"

def parse_trojan(link):
    try:
        # trojan://password@host:port?params#name
        match = re.match(r"trojan://[^@]+@([^:]+):(\d+)(\?[^#]*)?(#.*)?", link)
        if match:
            address = match.group(1)
            port = int(match.group(2))
            name_match = re.search(r"#(.*)", link)
            name = name_match.group(1) if name_match else "Unnamed Trojan"
            return address, port, name
        return None, None, "Invalid Trojan format"
    except Exception as e:
        return None, None, f"Error parsing Trojan: {e}"

def parse_ss_ssr(link):
    try:
        # ss://method:password@server:port#name 或 ss://base64encoded#name
        # ssr://base64encoded#name
        match = re.match(r"(ss|ssr)://([^#]+)(#.*)?", link)
        if not match:
            return None, None, "Invalid SS/SSR format"

        encoded_part = match.group(2)
        decoded_part = ""
        try:
            decoded_part = base64.urlsafe_b64decode(encoded_part + "==").decode('utf-8')
        except:
            decoded_part = encoded_part # Not base64 encoded

        # Try to parse from decoded part
        server_match = re.search(r"@([^:]+):(\d+)", decoded_part)
        if server_match:
            address = server_match.group(1)
            port = int(server_match.group(2))
            name_match = re.search(r"#(.*)", link)
            name = name_match.group(1) if name_match else f"Unnamed {match.group(1).upper()}"
            return address, port, name
        else: # Try parsing from original encoded part if not found in decoded (e.g. ss without base64)
            server_match = re.search(r"@([^:]+):(\d+)", encoded_part)
            if server_match:
                address = server_match.group(1)
                port = int(server_match.group(2))
                name_match = re.search(r"#(.*)", link)
                name = name_match.group(1) if name_match else f"Unnamed {match.group(1).upper()}"
                return address, port, name
        
        return None, None, f"Could not find server:port in {match.group(1).upper()} link"
    except Exception as e:
        return None, None, f"Error parsing SS/SSR: {e}"

def parse_hysteria2(link):
    try:
        # hysteria2://uuid@host:port/?params#name
        match = re.match(r"hysteria2://[^@]+@([^:]+):(\d+)(\?[^#]*)?(#.*)?", link)
        if match:
            address = match.group(1)
            port = int(match.group(2))
            name_match = re.search(r"#(.*)", link)
            name = name_match.group(1) if name_match else "Unnamed Hysteria2"
            return address, port, name
        return None, None, "Invalid Hysteria2 format"
    except Exception as e:
        return None, None, f"Error parsing Hysteria2: {e}"

def parse_node_link(link):
    link = link.strip().replace('\r', '') # Clean line endings

    # Remove existing _latency_ms and #name if present for clean parsing
    original_name_match = re.search(r"#(.*)", link)
    original_name = original_name_match.group(1) if original_name_match else ""
    
    link_base = re.sub(r"_\d+ms", "", link).split('#')[0] # Remove _latency_ms and everything after #

    if link_base.startswith("vmess://"):
        addr, port, name = parse_vmess(link_base)
        return "vmess", addr, port, name, link
    elif link_base.startswith("vless://"):
        addr, port, name = parse_vless(link_base)
        return "vless", addr, port, name, link
    elif link_base.startswith("trojan://"):
        addr, port, name = parse_trojan(link_base)
        return "trojan", addr, port, name, link
    elif link_base.startswith("ss://") or link_base.startswith("ssr://"):
        addr, port, name = parse_ss_ssr(link_base)
        return "ss/ssr", addr, port, name, link
    elif link_base.startswith("hysteria2://"):
        addr, port, name = parse_hysteria2(link_base)
        return "hysteria2", addr, port, name, link
    else:
        return "unknown", None, None, "Unsupported Protocol", link

def test_port_connectivity(node_info):
    protocol, address, port, name, original_link = node_info
    if not address or not port:
        return {
            "status": "failed",
            "reason": name, # name in this context is the parsing error
            "link": original_link,
            "latency": -1,
            "node_name": name
        }

    try:
        start_time = time.time()
        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONNECTION_TIMEOUT)

        # Resolve hostname to IP address
        ip_address = socket.gethostbyname(address)

        # Connect to the target address and port
        sock.connect((ip_address, port))
        end_time = time.time()
        latency_ms = int((end_time - start_time) * 1000)

        sock.close()
        return {
            "status": "success",
            "reason": "Connected",
            "link": original_link,
            "latency": latency_ms,
            "node_name": name
        }
    except socket.timeout:
        return {
            "status": "failed",
            "reason": "Connection Timeout",
            "link": original_link,
            "latency": -1,
            "node_name": name
        }
    except socket.error as e:
        return {
            "status": "failed",
            "reason": f"Socket Error: {e}",
            "link": original_link,
            "latency": -1,
            "node_name": name
        }
    except Exception as e:
        return {
            "status": "failed",
            "reason": f"Unknown Error: {e}",
            "link": original_link,
            "latency": -1,
            "node_name": name
        }

def load_existing_nodes(file_path):
    existing_links = set()
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                # Remove latency part and comments for comparison
                cleaned_line = re.sub(r"_\d+ms", "", line).split('#')[0].strip()
                if cleaned_line and not cleaned_line.startswith('#'):
                    existing_links.add(cleaned_line)
    return existing_links

def load_failed_proxies(file_path):
    failed_links = set()
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                failed_data = json.load(f)
                for entry in failed_data:
                    if 'link' in entry:
                        failed_links.add(entry['link'].split('#')[0].strip()) # Store only the base link
        except json.JSONDecodeError:
            print(f"Warning: {file_path} is not valid JSON. Ignoring its content.")
            pass
        except FileNotFoundError:
            pass
    return failed_links

def get_nodes_from_url(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
        return response.text.splitlines()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching nodes from URL {url}: {e}", file=sys.stderr)
        return []

def main():
    os.makedirs(os.path.dirname(SUB_FILE), exist_ok=True)
    os.makedirs(os.path.dirname(FAILED_FILE), exist_ok=True)

    # Load existing successful and failed nodes for incremental testing
    existing_successful_links = load_existing_nodes(SUB_FILE)
    existing_failed_links = load_failed_proxies(FAILED_FILE)

    print(f"Loaded {len(existing_successful_links)} existing successful nodes.")
    print(f"Loaded {len(existing_failed_links)} existing failed nodes.")

    # Fetch new nodes from the URL
    raw_nodes_lines = get_nodes_from_url(NODES_URL)
    if not raw_nodes_lines:
        print("No nodes fetched from URL. Exiting.")
        return

    nodes_to_test = []
    processed_links = set() # To prevent adding duplicate links from nodes.txt

    for line in raw_nodes_lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        base_link_for_comparison = re.sub(r"_\d+ms", "", line).split('#')[0].strip()
        
        if base_link_for_comparison in existing_successful_links:
            print(f"Skipping already successful node: {line[:50]}...")
            continue
        if base_link_for_comparison in existing_failed_links:
            print(f"Skipping previously failed node: {line[:50]}...")
            continue
        if base_link_for_comparison in processed_links:
            print(f"Skipping duplicate node in current run: {line[:50]}...")
            continue
        
        processed_links.add(base_link_for_comparison)
        
        node_type, addr, port, name, original_link = parse_node_link(line)
        if node_type == "unknown":
            print(f"Warning: Skipping unsupported node format: {original_link}")
            with open(FAILED_FILE, 'a', encoding='utf-8') as f:
                # If the file is empty or not a valid JSON array, write an opening bracket
                if os.stat(FAILED_FILE).st_size == 0 or not open(FAILED_FILE, 'r').read().strip().startswith('['):
                    f.write('[\n')
                else: # Otherwise, add a comma before the new entry
                    f.seek(0, os.SEEK_END)
                    if f.tell() > 2: # Check if it's not just "[\n"
                        f.seek(f.tell() - 2, os.SEEK_SET) # Move back to before last "]\n"
                        f.truncate() # Remove "]\n"
                        f.write(',\n')
                    else: # Handle empty JSON array case: "[\n]"
                         f.seek(f.tell() - 2, os.SEEK_SET) # Move back to before last "]\n"
                         f.truncate() # Remove "]\n"
                         f.write('\n') # Add a new line
                json.dump({"link": original_link, "reason": "Unsupported Protocol"}, f, ensure_ascii=False, indent=2)
                f.write('\n]\n') # Close the JSON array
            continue
        
        nodes_to_test.append((node_type, addr, port, name, original_link))

    if not nodes_to_test:
        print("No new nodes to test. Exiting.")
        return

    print(f"Found {len(nodes_to_test)} new nodes to test.")

    successful_results = []
    failed_results = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_node = {executor.submit(test_port_connectivity, node): node for node in nodes_to_test}

        for future in as_completed(future_to_node):
            result = future.result()
            if result['status'] == 'success':
                successful_results.append(result)
            else:
                failed_results.append(result)
            print(f"Tested {result['link'].split('#')[0]} - {result['status']} ({result['latency']}ms / {result['reason']})")

    # Sort successful nodes by latency
    successful_results.sort(key=lambda x: x['latency'])

    # Append successful nodes to sub.txt
    if successful_results:
        with open(SUB_FILE, 'a', encoding='utf-8') as f:
            f.write(f"\n# Updated by GitHub Actions at {datetime.utcnow().strftime('%a %b %d %H:%M:%S UTC %Y')}\n")
            f.write("-------------------------------------\n")
            for result in successful_results:
                # Keep original link format, add latency and update name if needed
                # Remove existing latency part for clean update
                cleaned_link = re.sub(r"_\d+ms", "", result['link'])
                final_link = f"{cleaned_link.split('#')[0].strip()}_{result['latency']}ms"
                
                # Re-add original #name part if exists
                original_name_match = re.search(r"#(.*)", result['link'])
                if original_name_match:
                    final_link = f"{final_link}#{original_name_match.group(1)}"
                else: # Try to use the parsed node_name if no original hash name
                     if result['node_name'] and result['node_name'] != "Unnamed VMess" and result['node_name'] != "Unnamed VLESS": # Avoid adding generic names
                        final_link = f"{final_link}#{result['node_name']}"

                f.write(f"{final_link}\n")
        print(f"Appended {len(successful_results)} successful nodes to {SUB_FILE}")

    # Append failed nodes to failed_proxies.json
    if failed_results:
        # Load existing failed proxies to merge
        existing_failed_data = []
        if os.path.exists(FAILED_FILE) and os.stat(FAILED_FILE).st_size > 0:
            try:
                with open(FAILED_FILE, 'r', encoding='utf-8') as f:
                    existing_failed_data = json.load(f)
            except json.JSONDecodeError:
                print(f"Warning: {FAILED_FILE} is corrupted or empty. Starting fresh for failed proxies.")
                existing_failed_data = []
        
        # Convert new failed results to the desired format and add to existing
        new_failed_entries = [{"link": r['link'], "reason": r['reason'], "timestamp": datetime.utcnow().isoformat()} for r in failed_results]
        
        # Deduplicate and merge
        merged_failed_data = {}
        for entry in existing_failed_data + new_failed_entries:
            if 'link' in entry:
                # Use the base link as key for deduplication
                base_link = re.sub(r"_\d+ms", "", entry['link']).split('#')[0].strip()
                merged_failed_data[base_link] = entry # Overwrite with newer entry if duplicate

        final_failed_list = list(merged_failed_data.values())

        with open(FAILED_FILE, 'w', encoding='utf-8') as f:
            json.dump(final_failed_list, f, ensure_ascii=False, indent=2)
        print(f"Appended {len(failed_results)} failed nodes to {FAILED_FILE}")
        
    print("Testing complete.")

if __name__ == "__main__":
    main()
